//! Admin-only queries: audit log, moderation actions, dump import.

use serde::Serialize;
use sqlx::SqliteConnection;

use crate::db::Db;
use crate::error::AppResult;

pub async fn audit(conn: &mut SqliteConnection, admin_id: i64, action: &str, target_type: &str, target_id: Option<i64>, detail: &str) -> AppResult<()> {
    sqlx::query("INSERT INTO audit_log (admin_id, action, target_type, target_id, detail) VALUES (?, ?, ?, ?, ?)")
        .bind(admin_id)
        .bind(action)
        .bind(target_type)
        .bind(target_id)
        .bind(detail)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct AuditEntry {
    pub created_at: String,
    pub admin: Option<String>,
    pub action: String,
    pub target_type: String,
    pub target_id: Option<i64>,
    pub detail: Option<String>,
}

pub async fn audit_page(db: &Db, limit: i64, offset: i64) -> AppResult<Vec<AuditEntry>> {
    Ok(sqlx::query_as(
        "SELECT l.created_at, a.username AS admin, l.action, l.target_type, l.target_id, l.detail
         FROM audit_log l LEFT JOIN admins a ON a.id = l.admin_id ORDER BY l.id DESC LIMIT ? OFFSET ?",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await?)
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct CreditRow {
    pub id: i64,
    pub podcast_id: i64,
    pub podcast_title: String,
    pub episode_title: Option<String>,
    pub role: String,
    pub source: String,
    pub verified: bool,
    pub hidden: bool,
}

pub async fn person_credits(db: &Db, person_id: i64) -> AppResult<Vec<CreditRow>> {
    Ok(sqlx::query_as(
        "SELECT c.id, c.podcast_id, pc.title AS podcast_title, e.title AS episode_title, c.role, c.source, c.verified, c.hidden
         FROM credits c JOIN podcasts pc ON pc.id = c.podcast_id LEFT JOIN episodes e ON e.id = c.episode_id
         WHERE c.person_id = ? ORDER BY c.episode_id IS NOT NULL, pc.title, e.pub_date DESC LIMIT 500",
    )
    .bind(person_id)
    .fetch_all(db)
    .await?)
}

pub async fn is_hidden(db: &Db, person_id: i64) -> AppResult<bool> {
    Ok(sqlx::query_scalar("SELECT hidden FROM people WHERE id = ?").bind(person_id).fetch_optional(db).await?.unwrap_or(false))
}

pub async fn set_hidden(conn: &mut SqliteConnection, person_id: i64, hidden: bool) -> AppResult<()> {
    sqlx::query("UPDATE people SET hidden = ? WHERE id = ?").bind(hidden).bind(person_id).execute(&mut *conn).await?;
    Ok(())
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct FailingFeed {
    pub id: i64,
    pub title: String,
    pub feed_url: Option<String>,
    pub crawl_failures: i64,
    pub crawl_error: Option<String>,
}

pub async fn failing_feeds(db: &Db) -> AppResult<Vec<FailingFeed>> {
    Ok(sqlx::query_as(
        "SELECT id, title, feed_url, crawl_failures, crawl_error FROM podcasts WHERE crawl_failures > 0 ORDER BY crawl_failures DESC, id LIMIT 100",
    )
    .fetch_all(db)
    .await?)
}

pub async fn admins(db: &Db) -> AppResult<Vec<(i64, String, String)>> {
    Ok(sqlx::query_as("SELECT id, username, created_at FROM admins ORDER BY id").fetch_all(db).await?)
}

#[derive(Debug, Default, Serialize)]
pub struct DumpImportReport {
    pub people_added: usize,
    pub people_matched: usize,
    pub podcasts_added: usize,
    pub podcasts_matched: usize,
    pub episodes_added: usize,
    pub credits_added: usize,
    pub skipped: usize,
}

/// Merge a `/api/v2/dump` (or `/api/public-dataset`) JSON document into this database. People are
/// matched by normalized name, podcasts by Podcast Index id, then feed URL. Existing rows are
/// never overwritten; imported community credits arrive unverified unless they were verified.
pub async fn import_dump(conn: &mut SqliteConnection, dump: &serde_json::Value) -> AppResult<DumpImportReport> {
    use std::collections::HashMap;

    use crate::normalize::{clean_name, normalize_feed_url, normalize_name};
    use crate::store::{credits, people, podcasts};

    let mut report = DumpImportReport::default();
    let arr = |k: &str| dump.get(k).and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let s = |v: &serde_json::Value, k: &str| v.get(k).and_then(|x| x.as_str()).map(str::trim).filter(|x| !x.is_empty()).map(str::to_string);
    let n = |v: &serde_json::Value, k: &str| v.get(k).and_then(|x| x.as_i64());

    let mut person_map: HashMap<i64, i64> = HashMap::new();
    for p in arr("people") {
        let (Some(id), Some(name)) = (n(&p, "id"), s(&p, "name")) else {
            report.skipped += 1;
            continue;
        };
        let name = clean_name(&name);
        let existing: Option<i64> = sqlx::query_scalar("SELECT id FROM people WHERE name_normalized = ? ORDER BY verified DESC, id LIMIT 1")
            .bind(normalize_name(&name))
            .fetch_optional(&mut *conn)
            .await?;
        let local = match existing {
            Some(l) => {
                report.people_matched += 1;
                l
            }
            None => {
                report.people_added += 1;
                let verified = p.get("verified").and_then(|v| v.as_bool()).unwrap_or(false);
                people::insert(conn, &name, s(&p, "bio").as_deref(), s(&p, "img").as_deref(), s(&p, "website").as_deref(), verified).await?
            }
        };
        person_map.insert(id, local);
    }

    let mut podcast_map: HashMap<i64, i64> = HashMap::new();
    for p in arr("podcasts") {
        let Some(id) = n(&p, "id") else { continue };
        let index_id = n(&p, "podcastindex_id").filter(|i| *i > 0);
        let feed_url = s(&p, "feed_url").as_deref().and_then(normalize_feed_url);
        let mut existing: Option<i64> = None;
        if let Some(pi) = index_id {
            existing = sqlx::query_scalar("SELECT id FROM podcasts WHERE podcastindex_id = ?").bind(pi).fetch_optional(&mut *conn).await?;
        }
        if existing.is_none() {
            if let Some(u) = &feed_url {
                existing = sqlx::query_scalar("SELECT id FROM podcasts WHERE feed_url = ?").bind(u).fetch_optional(&mut *conn).await?;
            }
        }
        let local = match existing {
            Some(l) => {
                report.podcasts_matched += 1;
                l
            }
            None => {
                report.podcasts_added += 1;
                sqlx::query_scalar(
                    "INSERT INTO podcasts (podcastindex_id, podcast_guid, feed_url, title, description, author, image, link, next_crawl_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
                )
                .bind(index_id)
                .bind(s(&p, "podcast_guid"))
                .bind(&feed_url)
                .bind(s(&p, "title").unwrap_or_else(|| "Untitled podcast".into()))
                .bind(s(&p, "description"))
                .bind(s(&p, "author"))
                .bind(s(&p, "image"))
                .bind(s(&p, "link"))
                .bind(crate::db::now())
                .fetch_one(&mut *conn)
                .await?
            }
        };
        podcast_map.insert(id, local);
    }

    let mut episode_map: HashMap<i64, i64> = HashMap::new();
    for e in arr("episodes") {
        let (Some(id), Some(pid)) = (n(&e, "id"), n(&e, "podcast_id").and_then(|p| podcast_map.get(&p).copied())) else {
            report.skipped += 1;
            continue;
        };
        let guid = s(&e, "guid");
        let url = s(&e, "enclosure_url");
        let found: Option<i64> = sqlx::query_scalar(
            "SELECT id FROM episodes WHERE podcast_id = ?1 AND ((guid IS NOT NULL AND guid = ?2) OR (enclosure_url IS NOT NULL AND enclosure_url = ?3)) LIMIT 1",
        )
        .bind(pid)
        .bind(&guid)
        .bind(&url)
        .fetch_optional(&mut *conn)
        .await?;
        let local = match found {
            Some(l) => l,
            None => {
                report.episodes_added += 1;
                podcasts::insert_episode(conn, pid, guid.as_deref(), url.as_deref(), &s(&e, "title").unwrap_or_else(|| "Untitled episode".into()), s(&e, "pub_date").as_deref()).await?
            }
        };
        episode_map.insert(id, local);
    }

    for c in arr("credits") {
        let person = n(&c, "person_id").and_then(|p| person_map.get(&p).copied());
        let podcast = n(&c, "podcast_id").and_then(|p| podcast_map.get(&p).copied());
        let episode = match n(&c, "episode_id") {
            Some(e) => match episode_map.get(&e) {
                Some(l) => Some(*l),
                None => {
                    report.skipped += 1;
                    continue;
                }
            },
            None => None,
        };
        let (Some(person_id), Some(podcast_id)) = (person, podcast) else {
            report.skipped += 1;
            continue;
        };
        // Feed credits are re-derived by our own crawler; only bring community knowledge over.
        if s(&c, "source").as_deref() == Some("feed") {
            continue;
        }
        let role = s(&c, "role").unwrap_or_else(|| "host".into());
        let group = s(&c, "group");
        let (_, created) = credits::add(conn, &credits::NewCredit {
            person_id,
            podcast_id,
            episode_id: episode,
            role: &role,
            group: group.as_deref(),
            source: "community",
            verified: c.get("verified").and_then(|v| v.as_bool()).unwrap_or(false),
            submission_id: None,
        })
        .await?;
        report.credits_added += created as usize;
    }
    Ok(report)
}
