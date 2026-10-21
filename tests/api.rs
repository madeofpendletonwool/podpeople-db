//! End-to-end tests against the real router, a temp database, and local mock servers for feeds
//! and the Podcast Index. No network access.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::Query;
use axum::http::{header, Request, StatusCode};
use axum::routing::get;
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use podpeople::config::Config;
use podpeople::state::AppState;

const FEED: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd" xmlns:podcast="https://podcastindex.org/namespace/1.0">
<channel>
  <title>Mock Show</title>
  <itunes:author>Hosty Mc Hostface &amp; Wondery Media</itunes:author>
  <podcast:guid>aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</podcast:guid>
  <podcast:person role="host" href="https://alice.example">Alice Anchor</podcast:person>
  {EXTRA_CHANNEL}
  <item><title>Ep 3</title><guid>ep-3</guid><pubDate>Tue, 20 Oct 2026 10:00:00 +0000</pubDate><enclosure url="https://cdn.example/3.mp3" type="audio/mpeg"/>
    <podcast:person role="guest">Gina Guest</podcast:person></item>
  <item><title>Ep 2</title><guid>ep-2</guid><pubDate>Tue, 13 Oct 2026 10:00:00 +0000</pubDate><enclosure url="https://cdn.example/2.mp3" type="audio/mpeg"/></item>
  <item><title>Ep 1</title><guid>ep-1</guid><pubDate>Tue, 06 Oct 2026 10:00:00 +0000</pubDate><enclosure url="https://cdn.example/1.mp3" type="audio/mpeg"/></item>
</channel></rss>"#;

struct Mock {
    addr: SocketAddr,
    /// Extra channel-level XML, to change the feed between crawls.
    extra: Arc<Mutex<String>>,
}

async fn mock_servers() -> Mock {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let extra = Arc::new(Mutex::new(r#"<podcast:person role="co-host">Bob Banter</podcast:person>"#.to_string()));
    let feed_extra = extra.clone();
    let app = Router::new()
        .route("/feed.xml", get(move || {
            let extra = feed_extra.clone();
            async move { ([(header::CONTENT_TYPE, "application/rss+xml")], FEED.replace("{EXTRA_CHANNEL}", &extra.lock().unwrap())) }
        }))
        .route("/not-a-feed", get(|| async { "<html>nope</html>" }))
        .route("/api/podcast", get(move |Query(q): Query<std::collections::HashMap<String, String>>| async move {
            let id: i64 = q.get("id").and_then(|i| i.parse().ok()).unwrap_or(0);
            if id == 4242 {
                axum::Json(json!({ "status": "true", "feed": { "id": 4242, "title": "Mock Show", "url": format!("http://{}/feed.xml", addr), "author": "Hosty" } }))
            } else {
                axum::Json(json!({ "status": "true", "feed": [] }))
            }
        }))
        .route("/api/search", get(|| async { axum::Json(json!({ "feeds": [] })) }));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Mock { addr, extra }
}

struct TestApp {
    router: Router,
    state: AppState,
    mock: Mock,
    _dir: tempfile::TempDir,
}

async fn app() -> TestApp {
    let mock = mock_servers().await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::for_tests(dir.path().join("db.sqlite"));
    config.search_api_url = format!("http://{}", mock.addr);
    let state = podpeople::init(config).await.unwrap();
    TestApp { router: podpeople::router(state.clone()), state, mock, _dir: dir }
}

impl TestApp {
    fn feed_url(&self) -> String {
        format!("http://{}/feed.xml", self.mock.addr)
    }

    async fn send(&self, req: Request<Body>) -> (StatusCode, Vec<u8>, axum::http::HeaderMap) {
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
        (status, body, headers)
    }

    async fn get(&self, path: &str) -> (StatusCode, Value) {
        let (s, b, _) = self.send(Request::get(path).body(Body::empty()).unwrap()).await;
        (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    async fn get_html(&self, path: &str) -> (StatusCode, String) {
        let (s, b, _) = self.send(Request::get(path).body(Body::empty()).unwrap()).await;
        (s, String::from_utf8_lossy(&b).into_owned())
    }

    async fn post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        let req = Request::post(path)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-real-ip", "203.0.113.7")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (s, b, _) = self.send(req).await;
        (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    async fn lookup(&self) -> Value {
        let (s, v) = self.get(&format!("/api/v2/podcasts/lookup?feed_url={}", urlencoding::encode(&self.feed_url()))).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        v
    }

    async fn admin_cookie(&self) -> (String, String) {
        let id: i64 = sqlx::query_scalar("SELECT id FROM admins LIMIT 1").fetch_one(&self.state.db).await.unwrap();
        let token = podpeople::auth::create_session(&self.state.db, id).await.unwrap();
        let csrf: String = sqlx::query_scalar("SELECT csrf_token FROM sessions ORDER BY rowid DESC LIMIT 1").fetch_one(&self.state.db).await.unwrap();
        (format!("{}={token}", podpeople::auth::COOKIE), csrf)
    }

    async fn admin_post(&self, path: &str, cookie: &str, form: &str) -> StatusCode {
        let req = Request::post(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, cookie)
            .body(Body::from(form.to_string()))
            .unwrap();
        self.send(req).await.0
    }
}

fn names(list: &Value) -> Vec<String> {
    list.as_array().unwrap().iter().map(|p| p["person"]["name"].as_str().unwrap().to_string()).collect()
}

#[tokio::test]
async fn feed_people_are_crawled_and_stored() {
    let t = app().await;
    let v = t.lookup().await;
    assert_eq!(v["podcast"]["title"], "Mock Show");
    assert_eq!(v["podcast"]["has_person_tags"], true);
    assert_eq!(v["episode_count"], 3);
    assert_eq!(names(&v["people"]), vec!["Alice Anchor", "Bob Banter"]);
    assert_eq!(v["people"][0]["sources"], json!(["feed"]));
    assert_eq!(v["people"][0]["verified"], true);
    assert_eq!(names(&v["guests"]), vec!["Gina Guest"]);
    // itunes:author yields a suggestion; the org part ("Wondery Media") doesn't.
    assert_eq!(v["suggestions"], json!(["Hosty Mc Hostface"]));

    // Second lookup is served from the database.
    let again = t.lookup().await;
    assert_eq!(again["podcast"]["id"], v["podcast"]["id"]);
}

#[tokio::test]
async fn podcast_index_lookup_adds_and_crawls() {
    let t = app().await;
    let (s, v) = t.get("/api/v2/podcasts/lookup?podcastindex_id=4242").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["podcast"]["podcastindex_id"], 4242);
    assert_eq!(names(&v["people"]), vec!["Alice Anchor", "Bob Banter"]);
    let (s, _) = t.get("/api/v2/podcasts/lookup?podcastindex_id=999").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = t.get("/api/v2/podcasts/lookup?podcastindex_id=4242&add=false").await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn non_feeds_are_rejected() {
    let t = app().await;
    let url = format!("http://{}/not-a-feed", t.mock.addr);
    let (s, _) = t.get(&format!("/api/v2/podcasts/lookup?feed_url={}", urlencoding::encode(&url))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn recrawl_replaces_feed_credits_but_keeps_community_ones() {
    let t = app().await;
    let v = t.lookup().await;
    let id = v["podcast"]["id"].as_i64().unwrap();
    let (s, _) = t.post("/api/v2/submissions", json!({ "podcast": { "id": id }, "people": [{ "name": "Carla Community" }] })).await;
    assert_eq!(s, StatusCode::OK);

    *t.mock.extra.lock().unwrap() = String::new(); // Bob leaves the feed
    podpeople::crawler::crawl(&t.state, id).await.unwrap();
    let (_, v) = t.get(&format!("/api/v2/podcasts/{id}")).await;
    assert_eq!(names(&v["people"]), vec!["Alice Anchor", "Carla Community"]);
}

#[tokio::test]
async fn submissions_go_live_dedupe_and_revert() {
    let t = app().await;
    let id = t.lookup().await["podcast"]["id"].as_i64().unwrap();

    // Two new people plus an existing one typed with different spacing/case.
    let (s, r) = t
        .post("/api/v2/submissions", json!({ "podcast": { "id": id }, "people": [
            { "name": "Dana  Doe" }, { "name": "Eve Example", "role": "Producer" }, { "name": "alice anchor" }
        ]}))
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let credits = r["credits"].as_array().unwrap();
    assert_eq!(credits[0]["person"]["name"], "Dana Doe");
    assert_eq!(credits[0]["new_person"], true);
    assert_eq!(credits[1]["role"], "producer");
    assert_eq!(credits[2]["new_person"], false, "matched the feed's Alice Anchor");
    let sub_id = r["submission_id"].as_i64().unwrap();

    let (_, v) = t.get(&format!("/api/v2/podcasts/{id}")).await;
    let dana = v["people"].as_array().unwrap().iter().find(|p| p["person"]["name"] == "Dana Doe").unwrap();
    assert_eq!(dana["verified"], false, "community additions are live but unverified");

    // Resubmitting the same thing creates nothing and no queue entry.
    let (_, again) = t.post("/api/v2/submissions", json!({ "podcast": { "id": id }, "people": [{ "name": "Dana Doe" }] })).await;
    assert_eq!(again["submission_id"], Value::Null);
    assert_eq!(again["credits"][0]["created"], false);

    // Revert removes the credits and the people it created, but not Alice.
    let mut tx = t.state.db.begin().await.unwrap();
    podpeople::store::submissions::revert(&mut tx, sub_id, 1).await.unwrap();
    tx.commit().await.unwrap();
    let (_, v) = t.get(&format!("/api/v2/podcasts/{id}")).await;
    assert_eq!(names(&v["people"]), vec!["Alice Anchor", "Bob Banter"]);
    let (_, hits) = t.get("/api/v2/people/search?q=dana").await;
    assert_eq!(hits, json!([]));
}

#[tokio::test]
async fn episode_guests_and_manual_podcasts() {
    let t = app().await;
    let id = t.lookup().await["podcast"]["id"].as_i64().unwrap();
    let (s, r) = t
        .post("/api/v2/submissions", json!({ "podcast": { "feed_url": t.feed_url() }, "episode": { "guid": "ep-2" }, "people": [{ "name": "Gina Guest" }] }))
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    assert_eq!(r["credits"][0]["role"], "guest");
    assert_eq!(r["credits"][0]["new_person"], false);
    let (_, ep) = t.get(&format!("/api/v2/episodes/lookup?id={id}&episode_guid=ep-2")).await;
    assert_eq!(ep["episode"]["people"][0]["person"]["name"], "Gina Guest");

    // An episode we don't have yet is created from what the contributor sends.
    let (s, r) = t
        .post("/api/v2/submissions", json!({ "podcast": { "id": id }, "episode": { "guid": "ep-99", "title": "Bonus" }, "people": [{ "name": "Hal" }] }))
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");

    // #7: a show with no public feed.
    let (s, r) = t.post("/api/v2/submissions", json!({ "podcast": { "title": "Patreon Only Show" }, "people": [{ "name": "Ivy" }] })).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    assert_eq!(r["podcast"]["title"], "Patreon Only Show");
    assert_eq!(r["podcast"]["feed_url"], Value::Null);

    let (s, _) = t.post("/api/v2/submissions", json!({ "podcast": {}, "people": [{ "name": "Nope" }] })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = t.post("/api/v2/submissions", json!({ "podcast": { "id": id }, "people": [] })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn honeypot_pretends_success() {
    let t = app().await;
    let id = t.lookup().await["podcast"]["id"].as_i64().unwrap();
    let (s, r) = t.post("/api/v2/submissions", json!({ "podcast": { "id": id }, "people": [{ "name": "Spam Bot" }], "homepage": "http://spam" })).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(r["submission_id"], Value::Null);
    let (_, hits) = t.get("/api/v2/people/search?q=spam").await;
    assert_eq!(hits, json!([]));
}

#[tokio::test]
async fn person_edits_apply_and_revert() {
    let t = app().await;
    let v = t.lookup().await;
    let alice = v["people"][0]["person"]["id"].as_i64().unwrap();
    let (s, r) = t.post(&format!("/api/v2/people/{alice}/edit"), json!({ "bio": "Anchors things.", "website": "javascript:alert(1)" })).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    assert_eq!(r["person"]["bio"], "Anchors things.");
    assert_eq!(r["person"]["website"], Value::Null, "non-http URLs are dropped");
    let sub = r["submission_id"].as_i64().unwrap();
    let mut tx = t.state.db.begin().await.unwrap();
    podpeople::store::submissions::revert(&mut tx, sub, 1).await.unwrap();
    tx.commit().await.unwrap();
    let (_, p) = t.get(&format!("/api/v2/people/{alice}")).await;
    assert_eq!(p["person"]["bio"], Value::Null);
    assert_eq!(p["person"]["website"], "https://alice.example/");
}

#[tokio::test]
async fn merged_people_keep_resolving() {
    let t = app().await;
    let id = t.lookup().await["podcast"]["id"].as_i64().unwrap();
    let (_, r) = t.post("/api/v2/submissions", json!({ "podcast": { "id": id }, "people": [{ "name": "Alicia Anchor" }] })).await;
    let dup = r["credits"][0]["person"]["id"].as_i64().unwrap();
    let (_, v) = t.get(&format!("/api/v2/podcasts/{id}")).await;
    let alice = v["people"][0]["person"]["id"].as_i64().unwrap();

    let mut tx = t.state.db.begin().await.unwrap();
    podpeople::store::people::merge(&mut tx, alice, dup).await.unwrap();
    tx.commit().await.unwrap();
    let (s, p) = t.get(&format!("/api/v2/people/{dup}")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(p["person"]["id"], alice);
    assert_eq!(p["merged_from"], dup);
    let (s, html) = t.get_html(&format!("/people/{dup}/whatever")).await;
    assert_eq!(s, StatusCode::PERMANENT_REDIRECT, "{html}");
}

#[tokio::test]
async fn legacy_endpoints_keep_v1_shapes() {
    let t = app().await;
    t.get("/api/v2/podcasts/lookup?podcastindex_id=4242").await;
    let (s, hosts) = t.get("/api/hosts/4242").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(hosts[0]["name"], "Alice Anchor");
    assert_eq!(hosts[0]["podcasts"][0]["podcastId"], 4242);
    assert_eq!(hosts[0]["podcasts"][0]["role"], "Host");
    assert!(hosts[0]["podcasts"][0]["feedUrl"].as_str().unwrap().ends_with("/feed.xml"));

    let (_, found) = t.get("/api/host-search?name=alice").await;
    assert_eq!(found[0]["name"], "Alice Anchor");
    assert_eq!(found[0]["podcasts"][0]["podcastTitle"], "Mock Show");
    let (_, short) = t.get("/api/host-search?name=al").await;
    assert_eq!(short, json!([]));

    // Unknown podcast: empty list right away (never blocks on a crawl).
    let (s, none) = t.get("/api/hosts/777").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(none, json!([]));

    let (_, stats) = t.get("/api/discover/stats").await;
    assert!(stats["total_hosts"].as_i64().unwrap() >= 2);
    let (_, top) = t.get("/api/discover/top-hosts").await;
    assert!(top[0]["podcastCount"].is_number());
}

#[tokio::test]
async fn batch_and_changes() {
    let t = app().await;
    let id = t.lookup().await["podcast"]["id"].as_i64().unwrap();
    t.post("/api/v2/submissions", json!({ "podcast": { "id": id }, "episode": { "guid": "ep-1" }, "people": [{ "name": "Jo Guest" }] })).await;
    let (s, b) = t
        .post("/api/v2/podcasts/batch", json!({ "podcasts": [{ "podcastindex_id": 1 }, { "feed_url": t.feed_url() }], "include_episode_credits": true }))
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let results = b["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["index"], 1);
    assert_eq!(results[0]["episode_credits"][0]["person"]["name"], "Jo Guest");
    assert_eq!(results[0]["episode_credits"][0]["episode_guid"], "ep-1");

    let (s, c) = t.get("/api/v2/changes?since=0").await;
    assert_eq!(s, StatusCode::OK);
    assert!(c["people"].as_array().unwrap().len() >= 4);
    assert!(c["until"].is_string());
    let (s, _) = t.get("/api/v2/changes?since=garbage").await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sqlite_download_is_scrubbed() {
    let t = app().await;
    t.lookup().await;
    let (s, bytes, _) = t.send(Request::get("/api/download-database").body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::OK);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dl.sqlite");
    std::fs::write(&path, bytes).unwrap();
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", path.display())).await.unwrap();
    let admins: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM admins").fetch_one(&pool).await.unwrap();
    let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions").fetch_one(&pool).await.unwrap();
    let people: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM people").fetch_one(&pool).await.unwrap();
    assert_eq!((admins, sessions), (0, 0));
    assert!(people >= 2);
}

#[tokio::test]
async fn admin_requires_session_and_csrf() {
    let t = app().await;
    let (s, _, h) = t.send(Request::get("/admin").body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(h[header::LOCATION], "/admin/login");

    let id = t.lookup().await["podcast"]["id"].as_i64().unwrap();
    let (_, r) = t.post("/api/v2/submissions", json!({ "podcast": { "id": id }, "people": [{ "name": "Kim" }] })).await;
    let sub = r["submission_id"].as_i64().unwrap();

    // No session: redirected to login, nothing happens.
    let s = t.admin_post(&format!("/admin/submissions/{sub}/approve"), "", "csrf=x").await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let (cookie, csrf) = t.admin_cookie().await;
    // Session without the CSRF token: forbidden.
    let s = t.admin_post(&format!("/admin/submissions/{sub}/approve"), &cookie, "csrf=wrong").await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let status: String = sqlx::query_scalar("SELECT status FROM submissions WHERE id = ?").bind(sub).fetch_one(&t.state.db).await.unwrap();
    assert_eq!(status, "live");
    // Both: approved, and the credit is verified.
    let s = t.admin_post(&format!("/admin/submissions/{sub}/approve"), &cookie, &format!("csrf={csrf}")).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let verified: bool = sqlx::query_scalar("SELECT verified FROM credits WHERE submission_id = ?").bind(sub).fetch_one(&t.state.db).await.unwrap();
    assert!(verified);
    let audit: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'approve'").fetch_one(&t.state.db).await.unwrap();
    assert_eq!(audit, 1);

    // The v1 hole: editing/deleting people is no longer possible without admin.
    let (s, _, _) = t.send(Request::delete("/delete-host/1").body(Body::empty()).unwrap()).await;
    assert_ne!(s, StatusCode::OK);
}

#[tokio::test]
async fn pages_render() {
    let t = app().await;
    let v = t.lookup().await;
    let id = v["podcast"]["id"].as_i64().unwrap();
    let person = &v["people"][0]["person"];
    let (_, eps) = t.get(&format!("/api/v2/podcasts/{id}/episodes")).await;
    let ep = eps["episodes"][0]["id"].as_i64().unwrap();
    for path in [
        "/".to_string(),
        "/discover".into(),
        "/search?q=alice".into(),
        format!("/podcasts/{id}"),
        format!("/podcasts/{id}/episodes/{ep}"),
        format!("/people/{}/{}", person["id"], person["slug"].as_str().unwrap()),
        "/about".into(),
        "/contribute".into(),
        "/docs/api".into(),
        "/docs/self-host".into(),
        "/admin/login".into(),
        "/sitemap.xml".into(),
        "/static/app.css".into(),
    ] {
        let (s, body) = t.get_html(&path).await;
        assert_eq!(s, StatusCode::OK, "{path}: {body}");
    }
    let (_, html) = t.get_html(&format!("/podcasts/{id}")).await;
    assert!(html.contains("Alice Anchor") && html.contains("data-contribute"));
    let (s, _) = t.get_html("/podcast/0").await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "#1: id 0 gets a helpful error page");
    let (s, _) = t.get_html("/people/999999").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn v1_import_preserves_ids_and_queues_pending() {
    let dir = tempfile::tempdir().unwrap();
    let v1 = dir.path().join("podpeopledb.sqlite");
    {
        let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}?mode=rwc", v1.display())).await.unwrap();
        for stmt in [
            "CREATE TABLE hosts (id INTEGER PRIMARY KEY, name TEXT, description TEXT, link TEXT, img TEXT, created_at DATETIME)",
            "CREATE TABLE podcasts (id INTEGER PRIMARY KEY, title TEXT, feed_url TEXT)",
            "CREATE TABLE host_podcasts (host_id INTEGER, podcast_id INTEGER, role TEXT, status TEXT, created_at DATETIME)",
            "CREATE TABLE admins (id INTEGER PRIMARY KEY, username TEXT, password TEXT, created_at DATETIME)",
            "INSERT INTO hosts VALUES (15, 'Griffin McElroy', 'A brother', 'https://griffin.example', '', '2026-05-28 02:48:16')",
            "INSERT INTO hosts VALUES (16, 'Pending Person', '', '', '', '2026-05-28 02:48:16')",
            "INSERT INTO hosts VALUES (17, 'Rejected Person', '', '', '', '2026-05-28 02:48:16')",
            "INSERT INTO podcasts VALUES (946647, 'MBMBaM', 'https://feeds.example/mbmbam')",
            "INSERT INTO host_podcasts VALUES (15, 946647, 'Host', 'approved', '2026-05-28 02:48:16')",
            "INSERT INTO host_podcasts VALUES (16, 946647, 'Guest', 'pending', '2026-05-28 02:48:16')",
            "INSERT INTO host_podcasts VALUES (17, 946647, 'Host', 'rejected', '2026-05-28 02:48:16')",
        ] {
            sqlx::query(stmt).execute(&pool).await.unwrap();
        }
        let hash = bcrypt::hash("v1-password", 4).unwrap();
        sqlx::query("INSERT INTO admins VALUES (1, 'oldadmin', ?, '2025-01-01 00:00:00')").bind(hash).execute(&pool).await.unwrap();
        pool.close().await;
    }
    let mut config = Config::for_tests(dir.path().join("podpeople-v2.sqlite"));
    config.v1_db_path = Some(v1.clone());
    let state = podpeople::init(config).await.unwrap();
    let router = podpeople::router(state.clone());

    let resp = router.clone().oneshot(Request::get("/api/v2/people/15").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(v["person"]["name"], "Griffin McElroy");
    assert_eq!(v["person"]["verified"], true);
    assert_eq!(v["podcasts"][0]["podcast"]["podcastindex_id"], 946647);

    let queued: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM submissions WHERE status = 'live'").fetch_one(&state.db).await.unwrap();
    assert_eq!(queued, 1, "the pending v1 credit is in the review queue");
    let rejected: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM credits WHERE person_id = 17").fetch_one(&state.db).await.unwrap();
    assert_eq!(rejected, 0);
    // v1 admin keeps their password; the first-boot env admin isn't created on top.
    assert!(podpeople::auth::login(&state.db, "oldadmin", "v1-password").await.unwrap().is_some());
    let admins: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM admins").fetch_one(&state.db).await.unwrap();
    assert_eq!(admins, 1);
    // The v1 file is untouched.
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}?mode=ro", v1.display())).await.unwrap();
    let tables: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE name = 'people'").fetch_one(&pool).await.unwrap();
    assert_eq!(tables, 0);
}

#[tokio::test]
async fn ssrf_guard_blocks_private_feeds_when_enabled() {
    let mock = mock_servers().await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::for_tests(dir.path().join("db.sqlite"));
    config.allow_private_urls = false;
    let state = podpeople::init(config).await.unwrap();
    let router = podpeople::router(state);
    let url = format!("/api/v2/podcasts/lookup?feed_url={}", urlencoding::encode(&format!("http://{}/feed.xml", mock.addr)));
    let resp = router.oneshot(Request::get(url).body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
