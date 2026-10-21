use serde::{Deserialize, Serialize};
use sqlx::SqliteConnection;

use super::people;
use crate::db::Db;
use crate::error::{AppError, AppResult};

/// What a submission changed, so it can be reviewed and undone.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Payload {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credit_ids: Vec<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub created_people: Vec<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_podcast_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_episode_id: Option<i64>,
    /// Person edits: field values before and after.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<serde_json::Value>,
    /// Empty fields of existing people that this submission filled in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fills: Option<Vec<Fill>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fill {
    pub person_id: i64,
    pub fields: Vec<String>,
}

pub struct NewSubmission<'a> {
    pub kind: &'static str,
    pub summary: String,
    pub podcast_id: Option<i64>,
    pub person_id: Option<i64>,
    pub client: &'a str,
    pub instance_id: Option<&'a str>,
    pub ip_hash: Option<&'a str>,
}

pub async fn create(conn: &mut SqliteConnection, s: &NewSubmission<'_>) -> AppResult<i64> {
    Ok(sqlx::query_scalar(
        "INSERT INTO submissions (kind, payload, summary, podcast_id, person_id, client, instance_id, ip_hash)
         VALUES (?, '{}', ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(s.kind)
    .bind(&s.summary)
    .bind(s.podcast_id)
    .bind(s.person_id)
    .bind(s.client)
    .bind(s.instance_id)
    .bind(s.ip_hash)
    .fetch_one(&mut *conn)
    .await?)
}

pub async fn set_payload(conn: &mut SqliteConnection, id: i64, payload: &Payload, summary: &str) -> AppResult<()> {
    sqlx::query("UPDATE submissions SET payload = ?, summary = ? WHERE id = ?")
        .bind(serde_json::to_string(payload)?)
        .bind(summary)
        .bind(id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Submission {
    pub id: i64,
    pub kind: String,
    pub payload: String,
    pub summary: String,
    pub podcast_id: Option<i64>,
    pub podcast_title: Option<String>,
    pub person_id: Option<i64>,
    pub client: String,
    pub instance_id: Option<String>,
    pub ip_hash: Option<String>,
    pub status: String,
    pub created_at: String,
    pub reviewed_at: Option<String>,
    pub reviewer: Option<String>,
}

const SELECT: &str = "SELECT s.id, s.kind, s.payload, s.summary, s.podcast_id, pc.title AS podcast_title, s.person_id,
        s.client, s.instance_id, s.ip_hash, s.status, s.created_at, s.reviewed_at, a.username AS reviewer
     FROM submissions s
     LEFT JOIN podcasts pc ON pc.id = s.podcast_id
     LEFT JOIN admins a ON a.id = s.reviewed_by";

pub async fn list(db: &Db, status: &str, limit: i64, offset: i64) -> AppResult<Vec<Submission>> {
    let order = if status == "live" { "ASC" } else { "DESC" };
    let sql = format!("{SELECT} WHERE s.status = ? ORDER BY s.created_at {order}, s.id {order} LIMIT ? OFFSET ?");
    Ok(sqlx::query_as::<_, Submission>(sqlx::AssertSqlSafe(sql)).bind(status).bind(limit).bind(offset).fetch_all(db).await?)
}

pub async fn get(conn: &mut SqliteConnection, id: i64) -> AppResult<Option<Submission>> {
    let sql = format!("{SELECT} WHERE s.id = ?");
    Ok(sqlx::query_as::<_, Submission>(sqlx::AssertSqlSafe(sql)).bind(id).fetch_optional(&mut *conn).await?)
}

pub async fn count_live(db: &Db) -> AppResult<i64> {
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM submissions WHERE status = 'live'").fetch_one(db).await?)
}

/// Submissions from one IP hash in the last hour (rate limiting that survives restarts).
pub async fn recent_from_ip(db: &Db, ip_hash: &str) -> AppResult<i64> {
    let since = crate::db::fmt_ts(chrono::Utc::now() - chrono::Duration::hours(1));
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM submissions WHERE ip_hash = ? AND created_at > ?")
        .bind(ip_hash)
        .bind(since)
        .fetch_one(db)
        .await?)
}

/// Approve: mark everything the submission created as verified.
pub async fn approve(conn: &mut SqliteConnection, id: i64, admin_id: i64) -> AppResult<()> {
    let sub = get(conn, id).await?.ok_or(AppError::NotFound)?;
    if sub.status != "live" {
        return Err(AppError::bad_request("submission was already reviewed"));
    }
    let payload: Payload = serde_json::from_str(&sub.payload).unwrap_or_default();
    sqlx::query("UPDATE credits SET verified = 1 WHERE submission_id = ?").bind(id).execute(&mut *conn).await?;
    for pid in &payload.created_people {
        sqlx::query("UPDATE people SET verified = 1 WHERE id = ?").bind(pid).execute(&mut *conn).await?;
    }
    mark(conn, id, "approved", admin_id).await
}

/// Revert: undo everything the submission did. Credits it added are deleted, people and podcasts
/// it created are deleted if nothing else references them, person edits are rolled back.
pub async fn revert(conn: &mut SqliteConnection, id: i64, admin_id: i64) -> AppResult<()> {
    let sub = get(conn, id).await?.ok_or(AppError::NotFound)?;
    if sub.status == "reverted" {
        return Ok(());
    }
    let payload: Payload = serde_json::from_str(&sub.payload).unwrap_or_default();
    sqlx::query("DELETE FROM credits WHERE submission_id = ?").bind(id).execute(&mut *conn).await?;
    for pid in &payload.created_people {
        people::delete_if_orphan(conn, *pid).await?;
    }
    if let Some(eid) = payload.created_episode_id {
        sqlx::query("DELETE FROM episodes WHERE id = ? AND NOT EXISTS (SELECT 1 FROM credits WHERE episode_id = ?)")
            .bind(eid)
            .bind(eid)
            .execute(&mut *conn)
            .await?;
    }
    if let Some(pc) = payload.created_podcast_id {
        // Only podcasts with no feed: crawled podcasts are useful on their own.
        sqlx::query("DELETE FROM podcasts WHERE id = ? AND feed_url IS NULL AND NOT EXISTS (SELECT 1 FROM credits WHERE podcast_id = ?)")
            .bind(pc)
            .bind(pc)
            .execute(&mut *conn)
            .await?;
    }
    for fill in payload.fills.iter().flatten() {
        let clear = |f: &str| fill.fields.iter().any(|x| x == f).then_some("");
        people::update(conn, fill.person_id, &people::PersonEdit { name: None, bio: clear("bio"), img: clear("img"), website: clear("website") }).await?;
    }
    if let (Some(person_id), Some(before)) = (sub.person_id, payload.before.as_ref()) {
        let s = |k: &str| before.get(k).map(|v| v.as_str().unwrap_or(""));
        people::update(conn, person_id, &people::PersonEdit { name: s("name"), bio: s("bio"), img: s("img"), website: s("website") }).await?;
    }
    mark(conn, id, "reverted", admin_id).await
}

async fn mark(conn: &mut SqliteConnection, id: i64, status: &str, admin_id: i64) -> AppResult<()> {
    sqlx::query("UPDATE submissions SET status = ?, reviewed_by = ?, reviewed_at = ? WHERE id = ?")
        .bind(status)
        .bind(admin_id)
        .bind(crate::db::now())
        .bind(id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Live submission ids sharing the given one's IP hash or PinePods instance (for bulk revert).
pub async fn related_live(conn: &mut SqliteConnection, id: i64) -> AppResult<Vec<i64>> {
    Ok(sqlx::query_scalar(
        "SELECT s2.id FROM submissions s JOIN submissions s2
            ON (s2.ip_hash = s.ip_hash AND s.ip_hash IS NOT NULL) OR (s2.instance_id = s.instance_id AND s.instance_id IS NOT NULL)
         WHERE s.id = ? AND s2.status = 'live' ORDER BY s2.id",
    )
    .bind(id)
    .fetch_all(&mut *conn)
    .await?)
}
