//! Server-rendered site: public pages, admin, static assets and the image proxy.

pub mod admin;
pub mod h;
pub mod pages;

use askama::Template;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use rust_embed::RustEmbed;
use serde::Deserialize;

use crate::auth::Admin;
use crate::error::AppError;
use crate::state::AppState;

#[derive(RustEmbed)]
#[folder = "static/"]
struct Assets;

/// Changes whenever the binary does, so `?v=` busts caches on deploy.
pub const ASSET_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Everything the base layout needs.
pub struct Layout {
    pub title: String,
    pub description: String,
    pub nav: &'static str,
    pub query: String,
    pub is_admin: bool,
    pub csrf: String,
    pub queue: i64,
    pub canonical: Option<String>,
    pub og_image: Option<String>,
    pub asset_version: &'static str,
}

impl Layout {
    pub async fn new(state: &AppState, admin: &Option<Admin>, title: impl Into<String>, description: impl Into<String>, nav: &'static str) -> Self {
        let queue = match admin {
            Some(_) => crate::store::submissions::count_live(&state.db).await.unwrap_or(0),
            None => 0,
        };
        Layout {
            title: title.into(),
            description: description.into(),
            nav,
            query: String::new(),
            is_admin: admin.is_some(),
            csrf: admin.as_ref().map(|a| a.csrf.clone()).unwrap_or_default(),
            queue,
            canonical: None,
            og_image: None,
            asset_version: ASSET_VERSION,
        }
    }

    pub fn canonical(mut self, state: &AppState, path: &str) -> Self {
        self.canonical = Some(format!("{}{}", state.config.base_url, path));
        self
    }
}

pub fn render(t: impl Template) -> Response {
    match t.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("template error: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "template error").into_response()
        }
    }
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPage {
    l: Layout,
    heading: String,
    message: String,
}

/// Turn an error into a friendly HTML page.
pub async fn page_error(state: &AppState, err: AppError) -> Response {
    let status = err.status();
    let (heading, message) = match status {
        StatusCode::NOT_FOUND => ("Not found".to_string(), "We couldn't find that. It may have been merged with someone else, or the link is wrong.".to_string()),
        StatusCode::BAD_GATEWAY => ("Couldn't reach that feed".to_string(), format!("{}. Try again in a bit.", err.public_message())),
        StatusCode::BAD_REQUEST => ("That didn't work".to_string(), err.public_message()),
        _ => ("Something went wrong".to_string(), "That's on us. Try again in a moment.".to_string()),
    };
    if status.is_server_error() {
        tracing::error!("{err}");
    }
    let l = Layout::new(state, &None, heading.clone(), message.clone(), "").await;
    let mut resp = render(ErrorPage { l, heading, message });
    *resp.status_mut() = status;
    resp
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .merge(pages::routes())
        .nest("/admin", admin::routes())
        .route("/static/{*path}", get(static_file))
        .route("/favicon.ico", get(favicon))
        .route("/robots.txt", get(robots))
        .route("/img", get(image_proxy))
        .fallback(not_found)
}

async fn not_found(State(state): State<AppState>) -> Response {
    page_error(&state, AppError::NotFound).await
}

async fn static_file(Path(path): Path<String>) -> Response {
    match Assets::get(&path) {
        Some(file) => {
            let mime = mime_guess::from_path(&path).first_or_octet_stream();
            (
                [
                    (header::CONTENT_TYPE, mime.to_string()),
                    // Versioned with ?v=, so cache hard.
                    (header::CACHE_CONTROL, "public, max-age=604800".to_string()),
                ],
                Body::from(file.data.into_owned()),
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn favicon() -> Response {
    static_file(Path("img/favicon-64.png".into())).await
}

async fn robots(State(state): State<AppState>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain")],
        format!("User-agent: *\nDisallow: /admin\nDisallow: /img\nDisallow: /api/\nSitemap: {}/sitemap.xml\n", state.config.base_url),
    )
        .into_response()
}

#[derive(Deserialize)]
struct ImgQuery {
    u: String,
    /// "cover" falls back to the cover placeholder; anything else to the avatar one.
    k: Option<String>,
}

/// Image proxy for person photos and covers. Public URLs only, images only, size capped.
async fn image_proxy(State(state): State<AppState>, Query(q): Query<ImgQuery>) -> Response {
    match state.http.fetch_image(&q.u).await {
        Ok((bytes, ct)) => (
            [
                (header::CONTENT_TYPE, ct),
                (header::CACHE_CONTROL, "public, max-age=604800, immutable".to_string()),
                (header::CONTENT_SECURITY_POLICY, "default-src 'none'".to_string()),
            ],
            Body::from(bytes),
        )
            .into_response(),
        // A broken image is worse than a placeholder (the JS also swaps avatars for initials).
        Err(_) => {
            let (path, ct) = if q.k.as_deref() == Some("cover") { ("img/cover.svg", "image/svg+xml") } else { ("img/default-avatar.png", "image/png") };
            match Assets::get(path) {
                Some(file) => ([(header::CONTENT_TYPE, ct), (header::CACHE_CONTROL, "public, max-age=3600")], Body::from(file.data.into_owned())).into_response(),
                None => StatusCode::NOT_FOUND.into_response(),
            }
        }
    }
}

/// Parsed `application/x-www-form-urlencoded` body that keeps repeated keys (`ids=1&ids=2`).
pub struct FormData(pub Vec<(String, String)>);

impl FormData {
    pub fn parse(body: &[u8]) -> Self {
        FormData(url::form_urlencoded::parse(body).into_owned().collect())
    }
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }
    pub fn all(&self, key: &str) -> Vec<&str> {
        self.0.iter().filter(|(k, _)| k == key).map(|(_, v)| v.as_str()).collect()
    }
}
