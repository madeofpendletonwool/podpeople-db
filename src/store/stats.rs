use serde::Serialize;

use super::{Episode, Person, Podcast, EPISODE_COLS, PERSON_COLS, PODCAST_COLS};
use crate::db::Db;
use crate::error::AppResult;

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Stats {
    pub people: i64,
    pub podcasts: i64,
    pub podcasts_with_people: i64,
    pub credits: i64,
    pub episode_credits: i64,
    pub community_credits: i64,
    pub unreviewed_submissions: i64,
}

pub async fn get(db: &Db) -> AppResult<Stats> {
    Ok(sqlx::query_as(
        "SELECT
            (SELECT COUNT(*) FROM people WHERE hidden = 0) AS people,
            (SELECT COUNT(*) FROM podcasts) AS podcasts,
            (SELECT COUNT(DISTINCT podcast_id) FROM credits WHERE hidden = 0) AS podcasts_with_people,
            (SELECT COUNT(*) FROM credits WHERE hidden = 0) AS credits,
            (SELECT COUNT(*) FROM credits WHERE hidden = 0 AND episode_id IS NOT NULL) AS episode_credits,
            (SELECT COUNT(*) FROM credits WHERE hidden = 0 AND source = 'community') AS community_credits,
            (SELECT COUNT(*) FROM submissions WHERE status = 'live') AS unreviewed_submissions",
    )
    .fetch_one(db)
    .await?)
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct CreditRecord {
    pub id: i64,
    pub person_id: i64,
    pub podcast_id: i64,
    pub episode_id: Option<i64>,
    pub role: String,
    #[sqlx(rename = "person_group")]
    pub group: String,
    pub source: String,
    pub verified: bool,
    pub updated_at: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Deletion {
    pub entity: String,
    pub entity_id: i64,
    pub deleted_at: String,
}

#[derive(Debug, Serialize)]
pub struct Changes {
    pub since: String,
    /// Pass this back as `since` next time.
    pub until: String,
    pub people: Vec<Person>,
    pub podcasts: Vec<Podcast>,
    pub episodes: Vec<Episode>,
    pub credits: Vec<CreditRecord>,
    pub deletions: Vec<Deletion>,
}

/// Everything public that changed after `since` (inclusive), for mirrors and full dumps.
/// Episodes are limited to ones someone is credited on; mirrors re-crawl feeds themselves.
pub async fn changes(db: &Db, since: &str) -> AppResult<Changes> {
    let until = crate::db::now();
    let people = sqlx::query_as::<_, Person>(sqlx::AssertSqlSafe(format!(
        "SELECT {PERSON_COLS} FROM people p WHERE p.hidden = 0 AND p.updated_at >= ? ORDER BY p.id"
    )))
    .bind(since)
    .fetch_all(db)
    .await?;
    let podcasts = sqlx::query_as::<_, Podcast>(sqlx::AssertSqlSafe(format!(
        "SELECT {PODCAST_COLS} FROM podcasts WHERE updated_at >= ? ORDER BY id"
    )))
    .bind(since)
    .fetch_all(db)
    .await?;
    let episodes = sqlx::query_as::<_, Episode>(sqlx::AssertSqlSafe(format!(
        "SELECT {EPISODE_COLS} FROM episodes e
         WHERE e.updated_at >= ? AND EXISTS (SELECT 1 FROM credits c WHERE c.episode_id = e.id AND c.hidden = 0)
         ORDER BY e.id"
    )))
    .bind(since)
    .fetch_all(db)
    .await?;
    let credits = sqlx::query_as::<_, CreditRecord>(
        "SELECT c.id, c.person_id, c.podcast_id, c.episode_id, c.role, c.person_group, c.source, c.verified, c.updated_at
         FROM credits c JOIN people p ON p.id = c.person_id
         WHERE c.hidden = 0 AND p.hidden = 0 AND c.updated_at >= ? ORDER BY c.id",
    )
    .bind(since)
    .fetch_all(db)
    .await?;
    let deletions = sqlx::query_as::<_, Deletion>(
        // Hidden rows look deleted to mirrors.
        "SELECT entity, entity_id, deleted_at FROM deletions WHERE deleted_at >= ?1
         UNION ALL SELECT 'person', id, updated_at FROM people WHERE hidden = 1 AND updated_at >= ?1
         UNION ALL SELECT 'credit', c.id, c.updated_at FROM credits c JOIN people p ON p.id = c.person_id
            WHERE (c.hidden = 1 OR p.hidden = 1) AND (c.updated_at >= ?1 OR p.updated_at >= ?1)
         ORDER BY 3",
    )
    .bind(since)
    .fetch_all(db)
    .await?;
    Ok(Changes { since: since.to_string(), until, people, podcasts, episodes, credits, deletions })
}
