//! Admin area. Every POST checks the session's CSRF token; every change is written to the audit log.

use askama::Template;
use axum::body::Bytes;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{header, HeaderMap};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;

use super::{page_error, render, FormData, Layout};
use crate::auth::{self, Admin, MaybeAdmin};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::store::admin::{self as store, AuditEntry, CreditRow, FailingFeed};
use crate::store::people::{self, DuplicateGroup, PersonSearchHit};
use crate::store::podcasts::{self, PopularPodcast};
use crate::store::submissions::{self, Payload, Submission};
use crate::store::{stats, Person, PersonRef};

const PAGE: i64 = 30;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(queue))
        .route("/dashboard", get(|| async { Redirect::permanent("/admin") }))
        .route("/login", get(login_page).post(login))
        .route("/logout", post(logout))
        .route("/submissions/approve-page", post(approve_page))
        .route("/submissions/{id}/approve", post(approve))
        .route("/submissions/{id}/revert", post(revert))
        .route("/submissions/{id}/revert-related", post(revert_related))
        .route("/people", get(people_page))
        .route("/people/merge", post(merge_people))
        .route("/people/{id}", get(person_page).post(update_person))
        .route("/people/{id}/hide", post(hide_person))
        .route("/people/{id}/unhide", post(unhide_person))
        .route("/people/{id}/delete", post(delete_person))
        .route("/credits/{id}/delete", post(delete_credit))
        .route("/podcasts", get(podcasts_page))
        .route("/podcasts/{id}/recrawl", post(recrawl))
        .route("/podcasts/{id}/delete", post(delete_podcast))
        .route("/admins", get(admins_page).post(add_admin))
        .route("/admins/{id}/delete", post(delete_admin))
        .route("/password", post(change_password))
        .route("/data", get(data_page))
        .route("/data/import", post(import))
        .route("/audit", get(audit_page))
}

/// Admin pages redirect to the login form instead of returning a bare 401.
async fn guarded(state: &AppState, admin: Option<Admin>, f: impl std::future::Future<Output = AppResult<Response>>) -> Response {
    if admin.is_none() {
        return Redirect::to("/admin/login").into_response();
    }
    match f.await {
        Ok(r) => r,
        Err(e) => page_error(state, e).await,
    }
}

/// Authenticate a POST: session + CSRF token from the form body.
async fn post_auth(state: &AppState, headers: &HeaderMap, body: &Bytes) -> AppResult<(Admin, FormData)> {
    let admin = auth::admin_from_headers(&state.db, headers).await?.ok_or(AppError::Unauthorized)?;
    let form = FormData::parse(body);
    admin.check_csrf(form.get("csrf").or_else(|| headers.get("x-csrf-token").and_then(|v| v.to_str().ok())))?;
    Ok((admin, form))
}

/// Run a POST action and redirect back with a flash message.
async fn action<F, Fut>(state: &AppState, headers: &HeaderMap, body: Bytes, back: &str, f: F) -> Response
where
    F: FnOnce(Admin, FormData) -> Fut,
    Fut: std::future::Future<Output = AppResult<String>>,
{
    let res = async {
        let (admin, form) = post_auth(state, headers, &body).await?;
        let back = form.get("back").filter(|b| b.starts_with("/admin")).map(str::to_string);
        let flash = f(admin, form).await?;
        Ok::<_, AppError>((back, flash))
    }
    .await;
    match res {
        Ok((override_back, flash)) => {
            let target = override_back.unwrap_or_else(|| back.to_string());
            let sep = if target.contains('?') { '&' } else { '?' };
            Redirect::to(&format!("{target}{sep}flash={}", urlencoding::encode(&flash))).into_response()
        }
        Err(AppError::Unauthorized) => Redirect::to("/admin/login").into_response(),
        Err(e) => page_error(state, e).await,
    }
}

#[derive(Deserialize, Default)]
struct ListQuery {
    status: Option<String>,
    page: Option<i64>,
    q: Option<String>,
    flash: Option<String>,
}

// ---------- Login ----------

#[derive(Template)]
#[template(path = "admin/login.html")]
struct LoginPage {
    l: Layout,
    error: Option<String>,
}

async fn login_page(State(state): State<AppState>, MaybeAdmin(admin): MaybeAdmin) -> Response {
    if admin.is_some() {
        return Redirect::to("/admin").into_response();
    }
    let l = Layout::new(&state, &None, "Admin sign in", "", "admin").await;
    render(LoginPage { l, error: None })
}

async fn login(State(state): State<AppState>, crate::api::ClientIp(ip): crate::api::ClientIp, body: Bytes) -> Response {
    let form = FormData::parse(&body);
    let (username, password) = (form.get("username").unwrap_or(""), form.get("password").unwrap_or(""));
    let ip_key = format!("login:{}", state.hash_ip(&ip));
    if !state.login_attempt_allowed(&ip_key) {
        let l = Layout::new(&state, &None, "Admin sign in", "", "admin").await;
        return render(LoginPage { l, error: Some("Too many attempts. Wait a few minutes and try again.".into()) });
    }
    match auth::login(&state.db, username, password).await {
        Ok(Some(id)) => match auth::create_session(&state.db, id).await {
            Ok(token) => {
                state.login_succeeded(&ip_key);
                ([(header::SET_COOKIE, auth::session_cookie(&token, state.config.secure_cookies()))], Redirect::to("/admin")).into_response()
            }
            Err(e) => page_error(&state, e).await,
        },
        Ok(None) => {
            let l = Layout::new(&state, &None, "Admin sign in", "", "admin").await;
            render(LoginPage { l, error: Some("Wrong username or password.".into()) })
        }
        Err(e) => page_error(&state, e).await,
    }
}

async fn logout(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if let Ok((_, _)) = post_auth(&state, &headers, &body).await {
        if let Some(token) = auth::cookie_token(&headers) {
            let _ = auth::destroy_session(&state.db, &token).await;
        }
    }
    ([(header::SET_COOKIE, auth::clear_cookie(state.config.secure_cookies()))], Redirect::to("/")).into_response()
}

// ---------- Review queue ----------

pub struct QueueItem {
    pub sub: Submission,
    pub people: Vec<PersonRef>,
    /// (field, before, after) for person edits.
    pub diff: Vec<(String, String, String)>,
    pub related: usize,
}

#[derive(Template)]
#[template(path = "admin/queue.html")]
struct QueuePage {
    l: Layout,
    tab: &'static str,
    flash: Option<String>,
    status: String,
    items: Vec<QueueItem>,
    page: i64,
    has_more: bool,
}

async fn queue(State(state): State<AppState>, MaybeAdmin(admin): MaybeAdmin, Query(q): Query<ListQuery>) -> Response {
    let a = admin.clone();
    guarded(&state, admin, async {
        let status = match q.status.as_deref() {
            Some("approved") => "approved",
            Some("reverted") => "reverted",
            _ => "live",
        };
        let page = q.page.unwrap_or(1).max(1);
        let subs = submissions::list(&state.db, status, PAGE + 1, (page - 1) * PAGE).await?;
        let has_more = subs.len() as i64 > PAGE;
        let mut conn = state.db.acquire().await?;
        let mut items = Vec::new();
        for sub in subs.into_iter().take(PAGE as usize) {
            let payload: Payload = serde_json::from_str(&sub.payload).unwrap_or_default();
            let mut people_ids: Vec<i64> = sqlx::query_scalar("SELECT DISTINCT person_id FROM credits WHERE submission_id = ?")
                .bind(sub.id)
                .fetch_all(&mut *conn)
                .await?;
            people_ids.extend(sub.person_id);
            let mut refs = Vec::new();
            for pid in people_ids {
                if let Some(p) = people::get_any(&mut conn, pid).await? {
                    refs.push(p.as_ref());
                }
            }
            let mut diff = Vec::new();
            if let (Some(b), Some(after)) = (payload.before.as_ref(), payload.after.as_ref().and_then(|a| a.as_object())) {
                for (k, v) in after {
                    diff.push((k.clone(), b.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string(), v.as_str().unwrap_or("").to_string()));
                }
            }
            let related = if sub.status == "live" { submissions::related_live(&mut conn, sub.id).await?.len() } else { 0 };
            items.push(QueueItem { sub, people: refs, diff, related });
        }
        let l = Layout::new(&state, &a, "Review queue", "", "admin").await;
        Ok(render(QueuePage { l, tab: "queue", flash: q.flash.clone(), status: status.to_string(), items, page, has_more }))
    })
    .await
}

async fn approve(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<i64>, body: Bytes) -> Response {
    let st = state.clone();
    action(&state, &headers, body, "/admin", |admin, _| async move {
        let mut tx = st.db.begin().await?;
        submissions::approve(&mut tx, id, admin.id).await?;
        store::audit(&mut tx, admin.id, "approve", "submission", Some(id), "").await?;
        tx.commit().await?;
        Ok("Approved.".into())
    })
    .await
}

async fn approve_page(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let st = state.clone();
    action(&state, &headers, body, "/admin", |admin, form| async move {
        let ids: Vec<i64> = form.all("ids").iter().filter_map(|s| s.parse().ok()).collect();
        let mut tx = st.db.begin().await?;
        let mut n = 0;
        for id in &ids {
            if submissions::approve(&mut tx, *id, admin.id).await.is_ok() {
                n += 1;
            }
        }
        store::audit(&mut tx, admin.id, "approve-page", "submission", None, &format!("{n} submissions")).await?;
        tx.commit().await?;
        Ok(format!("Approved {n} submissions."))
    })
    .await
}

async fn revert(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<i64>, body: Bytes) -> Response {
    let st = state.clone();
    action(&state, &headers, body, "/admin", |admin, _| async move {
        let mut tx = st.db.begin().await?;
        submissions::revert(&mut tx, id, admin.id).await?;
        store::audit(&mut tx, admin.id, "revert", "submission", Some(id), "").await?;
        tx.commit().await?;
        Ok("Reverted.".into())
    })
    .await
}

async fn revert_related(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<i64>, body: Bytes) -> Response {
    let st = state.clone();
    action(&state, &headers, body, "/admin", |admin, _| async move {
        let mut tx = st.db.begin().await?;
        let ids = submissions::related_live(&mut tx, id).await?;
        for sid in &ids {
            submissions::revert(&mut tx, *sid, admin.id).await?;
        }
        store::audit(&mut tx, admin.id, "revert-related", "submission", Some(id), &format!("{} submissions", ids.len())).await?;
        tx.commit().await?;
        Ok(format!("Reverted {} submissions.", ids.len()))
    })
    .await
}

// ---------- People ----------

#[derive(Template)]
#[template(path = "admin/people.html")]
struct PeoplePage {
    l: Layout,
    tab: &'static str,
    flash: Option<String>,
    q: String,
    results: Vec<PersonSearchHit>,
    duplicates: Vec<DuplicateGroup>,
}

async fn people_page(State(state): State<AppState>, MaybeAdmin(admin): MaybeAdmin, Query(q): Query<ListQuery>) -> Response {
    let a = admin.clone();
    guarded(&state, admin, async {
        let query = q.q.clone().unwrap_or_default();
        let results = if query.trim().is_empty() { vec![] } else { people::search(&state.db, &query, 50).await? };
        let l = Layout::new(&state, &a, "People", "", "admin").await;
        Ok(render(PeoplePage { l, tab: "people", flash: q.flash.clone(), q: query, results, duplicates: people::duplicate_groups(&state.db).await? }))
    })
    .await
}

#[derive(Template)]
#[template(path = "admin/person.html")]
struct PersonAdminPage {
    l: Layout,
    tab: &'static str,
    flash: Option<String>,
    person: Person,
    hidden: bool,
    credits: Vec<CreditRow>,
}

async fn person_page(State(state): State<AppState>, MaybeAdmin(admin): MaybeAdmin, Path(id): Path<i64>, Query(q): Query<ListQuery>) -> Response {
    let a = admin.clone();
    guarded(&state, admin, async {
        let mut conn = state.db.acquire().await?;
        let person = people::get_any(&mut conn, id).await?.ok_or(AppError::NotFound)?;
        drop(conn);
        let l = Layout::new(&state, &a, person.name.clone(), "", "admin").await;
        Ok(render(PersonAdminPage {
            l,
            tab: "people",
            flash: q.flash.clone(),
            hidden: store::is_hidden(&state.db, id).await?,
            credits: store::person_credits(&state.db, id).await?,
            person,
        }))
    })
    .await
}

async fn update_person(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<i64>, body: Bytes) -> Response {
    let st = state.clone();
    action(&state, &headers, body, &format!("/admin/people/{id}"), |admin, form| async move {
        let name = form.get("name").map(crate::normalize::clean_name).filter(|n| !n.is_empty());
        let url = |k: &str| form.get(k).map(|v| crate::normalize::clean_url(Some(v)).unwrap_or_default());
        let bio = form.get("bio").map(|b| b.trim().chars().take(2000).collect::<String>());
        let mut tx = st.db.begin().await?;
        people::update(&mut tx, id, &people::PersonEdit {
            name: name.as_deref(),
            bio: bio.as_deref(),
            img: url("img").as_deref(),
            website: url("website").as_deref(),
        })
        .await?;
        sqlx::query("UPDATE people SET verified = ? WHERE id = ?").bind(form.get("verified") == Some("1")).bind(id).execute(&mut *tx).await?;
        store::audit(&mut tx, admin.id, "edit", "person", Some(id), name.as_deref().unwrap_or("")).await?;
        tx.commit().await?;
        Ok("Saved.".into())
    })
    .await
}

async fn set_hidden(state: AppState, headers: HeaderMap, id: i64, body: Bytes, hidden: bool) -> Response {
    let st = state.clone();
    action(&state, &headers, body, &format!("/admin/people/{id}"), |admin, _| async move {
        let mut tx = st.db.begin().await?;
        store::set_hidden(&mut tx, id, hidden).await?;
        store::audit(&mut tx, admin.id, if hidden { "hide" } else { "unhide" }, "person", Some(id), "").await?;
        tx.commit().await?;
        Ok(if hidden { "Hidden everywhere." } else { "Visible again." }.into())
    })
    .await
}

async fn hide_person(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<i64>, body: Bytes) -> Response {
    set_hidden(state, headers, id, body, true).await
}

async fn unhide_person(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<i64>, body: Bytes) -> Response {
    set_hidden(state, headers, id, body, false).await
}

async fn delete_person(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<i64>, body: Bytes) -> Response {
    let st = state.clone();
    action(&state, &headers, body, "/admin/people", |admin, _| async move {
        let mut tx = st.db.begin().await?;
        let name: Option<String> = sqlx::query_scalar("SELECT name FROM people WHERE id = ?").bind(id).fetch_optional(&mut *tx).await?;
        sqlx::query("DELETE FROM people WHERE id = ?").bind(id).execute(&mut *tx).await?;
        store::audit(&mut tx, admin.id, "delete", "person", Some(id), name.as_deref().unwrap_or("")).await?;
        tx.commit().await?;
        Ok(format!("Deleted {}.", name.unwrap_or_default()))
    })
    .await
}

async fn merge_people(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let st = state.clone();
    let keep_hint = FormData::parse(&body).get("keep").and_then(|k| k.trim().trim_start_matches('#').parse::<i64>().ok());
    let back = keep_hint.map(|k| format!("/admin/people/{k}")).unwrap_or_else(|| "/admin/people".into());
    action(&state, &headers, body, &back, |admin, form| async move {
        let keep: i64 = form
            .get("keep")
            .and_then(|k| k.trim().trim_start_matches('#').parse().ok())
            .ok_or_else(|| AppError::bad_request("pick the person to keep"))?;
        let ids: Vec<i64> = form.all("ids").iter().filter_map(|s| s.parse().ok()).filter(|i| *i != keep).collect();
        if ids.is_empty() {
            return Err(AppError::bad_request("nothing to merge"));
        }
        let mut tx = st.db.begin().await?;
        people::get_any(&mut tx, keep).await?.ok_or_else(|| AppError::bad_request(format!("no person #{keep}")))?;
        for dup in &ids {
            people::merge(&mut tx, keep, *dup).await?;
            store::audit(&mut tx, admin.id, "merge", "person", Some(keep), &format!("merged #{dup}")).await?;
        }
        tx.commit().await?;
        Ok(format!("Merged {} into #{keep}.", ids.len()))
    })
    .await
}

async fn delete_credit(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<i64>, body: Bytes) -> Response {
    let st = state.clone();
    action(&state, &headers, body, "/admin", |admin, _| async move {
        let mut tx = st.db.begin().await?;
        sqlx::query("DELETE FROM credits WHERE id = ? AND source = 'community'").bind(id).execute(&mut *tx).await?;
        store::audit(&mut tx, admin.id, "delete", "credit", Some(id), "").await?;
        tx.commit().await?;
        Ok("Credit removed.".into())
    })
    .await
}

// ---------- Podcasts ----------

#[derive(Template)]
#[template(path = "admin/podcasts.html")]
struct PodcastsPage {
    l: Layout,
    tab: &'static str,
    flash: Option<String>,
    q: String,
    results: Vec<PopularPodcast>,
    failing: Vec<FailingFeed>,
}

async fn podcasts_page(State(state): State<AppState>, MaybeAdmin(admin): MaybeAdmin, Query(q): Query<ListQuery>) -> Response {
    let a = admin.clone();
    guarded(&state, admin, async {
        let query = q.q.clone().unwrap_or_default();
        let results = if query.trim().is_empty() { vec![] } else { podcasts::search(&state.db, &query, 50).await? };
        let l = Layout::new(&state, &a, "Podcasts", "", "admin").await;
        Ok(render(PodcastsPage { l, tab: "podcasts", flash: q.flash.clone(), q: query, results, failing: store::failing_feeds(&state.db).await? }))
    })
    .await
}

async fn recrawl(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<i64>, body: Bytes) -> Response {
    let st = state.clone();
    action(&state, &headers, body, &format!("/podcasts/{id}"), |admin, _| async move {
        let stats = crate::crawler::crawl(&st, id).await?;
        let mut conn = st.db.acquire().await?;
        store::audit(&mut conn, admin.id, "recrawl", "podcast", Some(id), "").await?;
        Ok(match stats {
            Some(s) => format!("Crawled: {} new episodes, {} new credits, {} removed.", s.episodes_added, s.credits_added, s.credits_removed),
            None => "Feed unchanged (or no feed to crawl).".into(),
        })
    })
    .await
}

async fn delete_podcast(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<i64>, body: Bytes) -> Response {
    let st = state.clone();
    action(&state, &headers, body, "/admin/podcasts", |admin, _| async move {
        let mut tx = st.db.begin().await?;
        let title: Option<String> = sqlx::query_scalar("SELECT title FROM podcasts WHERE id = ?").bind(id).fetch_optional(&mut *tx).await?;
        sqlx::query("UPDATE submissions SET podcast_id = NULL WHERE podcast_id = ?").bind(id).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM podcasts WHERE id = ?").bind(id).execute(&mut *tx).await?;
        store::audit(&mut tx, admin.id, "delete", "podcast", Some(id), title.as_deref().unwrap_or("")).await?;
        tx.commit().await?;
        Ok(format!("Deleted {}.", title.unwrap_or_default()))
    })
    .await
}

// ---------- Admins ----------

#[derive(Template)]
#[template(path = "admin/admins.html")]
struct AdminsPage {
    l: Layout,
    tab: &'static str,
    flash: Option<String>,
    admins: Vec<(i64, String, String)>,
    me: i64,
}

async fn admins_page(State(state): State<AppState>, MaybeAdmin(admin): MaybeAdmin, Query(q): Query<ListQuery>) -> Response {
    let a = admin.clone();
    guarded(&state, admin, async {
        let me = a.as_ref().map(|x| x.id).unwrap_or(0);
        let l = Layout::new(&state, &a, "Admins", "", "admin").await;
        Ok(render(AdminsPage { l, tab: "admins", flash: q.flash.clone(), admins: store::admins(&state.db).await?, me }))
    })
    .await
}

async fn add_admin(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let st = state.clone();
    action(&state, &headers, body, "/admin/admins", |admin, form| async move {
        let username = form.get("username").map(str::trim).filter(|u| !u.is_empty()).ok_or_else(|| AppError::bad_request("username required"))?;
        let password = form.get("password").unwrap_or("");
        if password.chars().count() < 10 {
            return Err(AppError::bad_request("passwords need at least 10 characters"));
        }
        let mut tx = st.db.begin().await?;
        sqlx::query("INSERT INTO admins (username, password_hash) VALUES (?, ?)")
            .bind(username)
            .bind(auth::hash_password(password)?)
            .execute(&mut *tx)
            .await
            .map_err(|_| AppError::bad_request("that username is taken"))?;
        store::audit(&mut tx, admin.id, "add", "admin", None, username).await?;
        tx.commit().await?;
        Ok(format!("Added {username}."))
    })
    .await
}

async fn delete_admin(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<i64>, body: Bytes) -> Response {
    let st = state.clone();
    action(&state, &headers, body, "/admin/admins", |admin, _| async move {
        if id == admin.id {
            return Err(AppError::bad_request("you can't remove yourself"));
        }
        let mut tx = st.db.begin().await?;
        sqlx::query("UPDATE submissions SET reviewed_by = NULL WHERE reviewed_by = ?").bind(id).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM admins WHERE id = ?").bind(id).execute(&mut *tx).await?;
        store::audit(&mut tx, admin.id, "delete", "admin", Some(id), "").await?;
        tx.commit().await?;
        Ok("Admin removed.".into())
    })
    .await
}

async fn change_password(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let st = state.clone();
    action(&state, &headers, body, "/admin/admins", |admin, form| async move {
        let current = form.get("current").unwrap_or("");
        let new = form.get("password").unwrap_or("");
        if auth::login(&st.db, &admin.username, current).await?.is_none() {
            return Err(AppError::bad_request("current password is wrong"));
        }
        if new.chars().count() < 10 {
            return Err(AppError::bad_request("passwords need at least 10 characters"));
        }
        let mut tx = st.db.begin().await?;
        sqlx::query("UPDATE admins SET password_hash = ? WHERE id = ?").bind(auth::hash_password(new)?).bind(admin.id).execute(&mut *tx).await?;
        // Sign out every other session.
        sqlx::query("DELETE FROM sessions WHERE admin_id = ? AND csrf_token != ?").bind(admin.id).bind(&admin.csrf).execute(&mut *tx).await?;
        store::audit(&mut tx, admin.id, "change-password", "admin", Some(admin.id), "").await?;
        tx.commit().await?;
        Ok("Password changed. Other sessions were signed out.".into())
    })
    .await
}

// ---------- Data ----------

#[derive(Template)]
#[template(path = "admin/data.html")]
struct DataPage {
    l: Layout,
    tab: &'static str,
    flash: Option<String>,
    stats: stats::Stats,
    report: Option<String>,
}

async fn data_page(State(state): State<AppState>, MaybeAdmin(admin): MaybeAdmin, Query(q): Query<ListQuery>) -> Response {
    let a = admin.clone();
    guarded(&state, admin, async {
        let l = Layout::new(&state, &a, "Data", "", "admin").await;
        Ok(render(DataPage { l, tab: "data", flash: q.flash.clone(), stats: stats::get(&state.db).await?, report: None }))
    })
    .await
}

/// Merge an uploaded JSON dump (multipart: csrf + file).
async fn import(State(state): State<AppState>, MaybeAdmin(admin): MaybeAdmin, mut multipart: Multipart) -> Response {
    let a = admin.clone();
    guarded(&state, admin, async {
        let admin = a.clone().ok_or(AppError::Unauthorized)?;
        let mut csrf = None;
        let mut file = None;
        while let Some(field) = multipart.next_field().await.map_err(|e| AppError::bad_request(e.to_string()))? {
            match field.name() {
                Some("csrf") => csrf = Some(field.text().await.map_err(|e| AppError::bad_request(e.to_string()))?),
                Some("file") => file = Some(field.bytes().await.map_err(|e| AppError::bad_request(e.to_string()))?),
                _ => {}
            }
        }
        admin.check_csrf(csrf.as_deref())?;
        let file = file.ok_or_else(|| AppError::bad_request("no file uploaded"))?;
        let dump: serde_json::Value = serde_json::from_slice(&file).map_err(|e| AppError::bad_request(format!("not valid JSON: {e}")))?;
        let mut tx = state.db.begin().await?;
        let report = store::import_dump(&mut tx, &dump).await?;
        let pretty = serde_json::to_string_pretty(&report)?;
        store::audit(&mut tx, admin.id, "import", "dump", None, &serde_json::to_string(&report)?).await?;
        tx.commit().await?;
        let l = Layout::new(&state, &a, "Data", "", "admin").await;
        Ok(render(DataPage { l, tab: "data", flash: Some("Import finished.".into()), stats: stats::get(&state.db).await?, report: Some(pretty) }))
    })
    .await
}

#[derive(Template)]
#[template(path = "admin/audit.html")]
struct AuditPage {
    l: Layout,
    tab: &'static str,
    flash: Option<String>,
    entries: Vec<AuditEntry>,
    page: i64,
    has_more: bool,
}

async fn audit_page(State(state): State<AppState>, MaybeAdmin(admin): MaybeAdmin, Query(q): Query<ListQuery>) -> Response {
    let a = admin.clone();
    guarded(&state, admin, async {
        let page = q.page.unwrap_or(1).max(1);
        let mut entries = store::audit_page(&state.db, PAGE + 1, (page - 1) * PAGE).await?;
        let has_more = entries.len() as i64 > PAGE;
        entries.truncate(PAGE as usize);
        let l = Layout::new(&state, &a, "Audit log", "", "admin").await;
        Ok(render(AuditPage { l, tab: "audit", flash: None, entries, page, has_more }))
    })
    .await
}
