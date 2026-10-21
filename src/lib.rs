pub mod api;
pub mod auth;
pub mod config;
pub mod crawler;
pub mod db;
pub mod error;
pub mod feed;
pub mod import_v1;
pub mod index;
pub mod net;
pub mod normalize;
pub mod notify;
pub mod state;
pub mod store;
pub mod submit;
pub mod web;

use std::time::Duration;

use axum::http::{header, HeaderValue, Method};
use axum::Router;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::config::Config;
use crate::error::AppResult;
use crate::state::AppState;

/// Open (and if needed create, migrate and import into) the database, and build the app state.
pub async fn init(config: Config) -> AppResult<AppState> {
    let fresh = !config.db_path.exists();
    let db = db::connect(&config.db_path).await?;
    if fresh {
        if let Some(v1) = config.v1_db_path.as_ref().filter(|p| p.exists()) {
            tracing::info!("importing v1 database {}", v1.display());
            match import_v1::import(v1, &db).await {
                Ok(report) => tracing::info!("v1 import done: {report:?}"),
                Err(e) => {
                    // Leave nothing half-imported behind: the next boot retries from scratch.
                    db.close().await;
                    let _ = std::fs::remove_file(&config.db_path);
                    return Err(e);
                }
            }
        }
    }
    auth::ensure_admin(&db, &config.admin_username, &config.admin_password).await?;
    Ok(AppState::new(db, config))
}

pub fn router(state: AppState) -> Router {
    // The API is public and read-mostly; any origin may call it (PinePods web clients included).
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE, "x-podpeople-client".parse().unwrap()]);
    let api = Router::new()
        .nest("/v2", api::v2::routes())
        .merge(api::legacy::routes())
        .layer(cors);
    Router::new()
        .nest("/api", api)
        .merge(web::routes())
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY")))
        .layer(CompressionLayer::new())
        .layer(TimeoutLayer::with_status_code(axum::http::StatusCode::GATEWAY_TIMEOUT, Duration::from_secs(60)))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
