//! v1 endpoints, kept so released PinePods versions (0.9.x and earlier) keep working. Same paths
//! and JSON shapes as v1, served from the v2 schema. New integrations should use `/api/v2`.

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use super::clamp_limit;
use crate::crawler::{self, PodcastKey};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::store::{credits, people, podcasts, stats, Person};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/hosts/{id}", get(hosts_for_podcast))
        .route("/host-search", get(host_search))
        .route("/podcast/{id}", get(podcast))
        .route("/discover/recent-hosts", get(recent_hosts))
        .route("/discover/top-hosts", get(top_hosts))
        .route("/discover/popular-podcasts", get(popular_podcasts))
        .route("/discover/stats", get(discover_stats))
        .route("/public-dataset", get(public_dataset))
        .route("/download-database", get(download_database))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct V1Host {
    id: i64,
    name: String,
    description: String,
    link: String,
    img: String,
    created_at: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    podcasts: Vec<V1Association>,
}

#[derive(Serialize)]
struct V1Association {
    #[serde(rename = "podcastId")]
    podcast_id: i64,
    #[serde(rename = "podcastTitle")]
    title: String,
    role: String,
    status: &'static str,
    #[serde(rename = "feedUrl")]
    feed_url: String,
}

fn v1_host(p: &Person, podcasts: Vec<V1Association>) -> V1Host {
    V1Host {
        id: p.id,
        name: p.name.clone(),
        description: p.bio.clone().unwrap_or_default(),
        link: p.website.clone().unwrap_or_default(),
        img: p.img.clone().unwrap_or_default(),
        created_at: p.created_at.clone(),
        podcasts,
    }
}

/// v1 role strings were capitalized ("Host", "Guest").
fn v1_role(role: &str) -> String {
    let mut c = role.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => "Host".into(),
    }
}

/// `GET /api/hosts/{podcastindex_id}`: the show's people. Never crawls inline (old PinePods calls
/// this on page load with a short timeout); an unknown podcast is added in the background so the
/// next request has data.
async fn hosts_for_podcast(State(state): State<AppState>, Path(id): Path<i64>) -> AppResult<Json<Vec<V1Host>>> {
    let key = PodcastKey { podcastindex_id: Some(id), ..Default::default() };
    let Some(podcast) = crawler::find(&state, &key).await? else {
        if id > 0 {
            let st = state.clone();
            tokio::spawn(async move {
                if let Err(e) = crawler::find_or_add(&st, &key).await {
                    tracing::debug!("background add of podcast index {id} failed: {e}");
                }
            });
        }
        return Ok(Json(Vec::new()));
    };
    let (show, _) = credits::people_for_podcast(&state.db, podcast.id, 0).await?;
    let mut out = Vec::new();
    for pp in show {
        let Some(person) = people::get(&state.db, pp.person.id).await? else { continue };
        out.push(v1_host(&person, vec![V1Association {
            podcast_id: podcast.podcastindex_id.unwrap_or(0),
            title: podcast.title.clone(),
            role: v1_role(&pp.roles[0]),
            status: "approved",
            feed_url: podcast.feed_url.clone().unwrap_or_default(),
        }]));
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
struct NameQuery {
    name: String,
}

/// `GET /api/host-search?name=`: people matching a name, each with the podcasts they're on.
async fn host_search(State(state): State<AppState>, Query(q): Query<NameQuery>) -> AppResult<Json<Vec<V1Host>>> {
    if q.name.trim().chars().count() < 3 {
        return Ok(Json(Vec::new()));
    }
    let mut out = Vec::new();
    for hit in people::search(&state.db, &q.name, 10).await? {
        let Some(person) = people::get(&state.db, hit.person.id).await? else { continue };
        let podcasts = people::podcasts_for(&state.db, person.id)
            .await?
            .into_iter()
            .map(|pp| V1Association {
                podcast_id: pp.podcast.podcastindex_id.unwrap_or(0),
                title: pp.podcast.title,
                role: v1_role(pp.roles.split(',').next().unwrap_or("host")),
                status: "approved",
                feed_url: pp.podcast.feed_url.unwrap_or_default(),
            })
            .collect();
        out.push(v1_host(&person, podcasts));
    }
    Ok(Json(out))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct V1Podcast {
    id: i64,
    title: String,
    description: String,
    author: String,
    owner_name: String,
    image: String,
    link: String,
    url: String,
    hosts: Vec<V1Person>,
}

#[derive(Serialize)]
struct V1Person {
    name: String,
    role: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    img: String,
}

/// `GET /api/podcast/{podcastindex_id}`.
async fn podcast(State(state): State<AppState>, Path(id): Path<i64>) -> AppResult<Json<V1Podcast>> {
    let key = PodcastKey { podcastindex_id: Some(id), ..Default::default() };
    let p = crawler::find_or_add(&state, &key).await?.ok_or(AppError::NotFound)?;
    let (show, _) = credits::people_for_podcast(&state.db, p.id, 0).await?;
    Ok(Json(V1Podcast {
        id: p.podcastindex_id.unwrap_or(0),
        title: p.title,
        description: p.description.unwrap_or_default(),
        author: p.author.unwrap_or_default(),
        owner_name: p.owner_name.unwrap_or_default(),
        image: p.image.unwrap_or_default(),
        link: p.link.unwrap_or_default(),
        url: p.feed_url.unwrap_or_default(),
        hosts: show
            .into_iter()
            .map(|pp| V1Person { role: v1_role(&pp.roles[0]), name: pp.person.name, img: pp.person.img.unwrap_or_default() })
            .collect(),
    }))
}

#[derive(Deserialize)]
struct LimitQuery {
    limit: Option<i64>,
}

async fn recent_hosts(State(state): State<AppState>, Query(q): Query<LimitQuery>) -> AppResult<Json<Vec<V1Host>>> {
    let mut out = Vec::new();
    for r in people::recent(&state.db, clamp_limit(q.limit, 12, 50)).await? {
        if let Some(p) = people::get(&state.db, r.person.id).await? {
            out.push(v1_host(&p, Vec::new()));
        }
    }
    Ok(Json(out))
}

#[derive(Serialize)]
struct V1Ranked {
    id: i64,
    name: String,
    img: String,
    #[serde(rename = "podcastCount")]
    podcast_count: i64,
}

async fn top_hosts(State(state): State<AppState>, Query(q): Query<LimitQuery>) -> AppResult<Json<Vec<V1Ranked>>> {
    Ok(Json(
        people::top(&state.db, clamp_limit(q.limit, 24, 100))
            .await?
            .into_iter()
            .map(|r| V1Ranked { id: r.person.id, name: r.person.name, img: r.person.img.unwrap_or_default(), podcast_count: r.podcast_count })
            .collect(),
    ))
}

#[derive(Serialize)]
struct V1PodcastSummary {
    podcast_id: i64,
    title: String,
    host_count: i64,
    description: String,
}

async fn popular_podcasts(State(state): State<AppState>, Query(q): Query<LimitQuery>) -> AppResult<Json<Vec<V1PodcastSummary>>> {
    Ok(Json(
        podcasts::popular(&state.db, clamp_limit(q.limit, 12, 50))
            .await?
            .into_iter()
            // v1 consumers link to the podcast by Podcast Index id; skip ones without one.
            .filter_map(|p| {
                Some(V1PodcastSummary {
                    podcast_id: p.podcastindex_id?,
                    title: p.title,
                    host_count: p.people_count,
                    description: p.description.unwrap_or_default(),
                })
            })
            .collect(),
    ))
}

#[derive(Serialize)]
struct V1Stats {
    total_hosts: i64,
    total_podcasts: i64,
    pending_hosts: i64,
    approved_hosts: i64,
    episodes_with_guests: i64,
    pending_episode_guests: i64,
}

async fn discover_stats(State(state): State<AppState>) -> AppResult<Json<V1Stats>> {
    let s = stats::get(&state.db).await?;
    Ok(Json(V1Stats {
        total_hosts: s.people,
        total_podcasts: s.podcasts_with_people,
        pending_hosts: s.unreviewed_submissions,
        approved_hosts: s.people,
        episodes_with_guests: s.episode_credits,
        pending_episode_guests: 0,
    }))
}

/// Full public dataset as a JSON download (v2 shape).
async fn public_dataset(State(state): State<AppState>) -> AppResult<Response> {
    let dump = stats::changes(&state.db, "0000").await?;
    let filename = format!("podpeople-dataset-{}.json", chrono::Utc::now().format("%Y-%m-%d"));
    Ok((
        [
            (header::CONTENT_TYPE, "application/json".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename={filename}")),
        ],
        Json(dump),
    )
        .into_response())
}

/// A downloadable SQLite copy of the public data. v1 served the live database file itself,
/// admin password hashes and session tokens included; this builds a scrubbed snapshot instead.
async fn download_database(State(state): State<AppState>) -> AppResult<Response> {
    let dir = tempfile::tempdir().map_err(|e| AppError::Internal(e.to_string()))?;
    let path = dir.path().join("podpeople.sqlite");
    sqlx::query(sqlx::AssertSqlSafe(format!("VACUUM INTO '{}'", path.display().to_string().replace('\'', "''"))))
        .execute(&state.db)
        .await?;
    {
        use std::str::FromStr;
        let opts = sqlx::sqlite::SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))?;
        let snap = sqlx::SqlitePool::connect_with(opts).await?;
        for stmt in [
            "DELETE FROM sessions",
            "DELETE FROM audit_log",
            "UPDATE submissions SET reviewed_by = NULL",
            "DELETE FROM admins",
            "UPDATE submissions SET ip_hash = NULL, instance_id = NULL",
            "UPDATE podcasts SET etag = NULL, last_modified = NULL, crawl_error = NULL",
            "DELETE FROM credits WHERE hidden = 1",
            "DELETE FROM people WHERE hidden = 1",
            "VACUUM",
        ] {
            sqlx::query(stmt).execute(&snap).await?;
        }
        snap.close().await;
    }
    let bytes = tokio::fs::read(&path).await.map_err(|e| AppError::Internal(e.to_string()))?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/vnd.sqlite3".to_string()),
            (header::CONTENT_DISPOSITION, "attachment; filename=podpeople.sqlite".to_string()),
        ],
        Body::from(bytes),
    )
        .into_response())
}
