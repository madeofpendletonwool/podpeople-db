use serde::Serialize;
use sqlx::{Sqlite, SqliteConnection};

use super::{Episode, Person, PersonRef, PodcastRef, EPISODE_COLS, PERSON_COLS, PERSON_REF_COLS};
use crate::db::Db;
use crate::error::AppResult;
use crate::normalize::{normalize_name, slugify};

/// Resolve a person id, following merge aliases. Hidden people resolve to `None`.
pub async fn get(db: &Db, id: i64) -> AppResult<Option<Person>> {
    let sql = format!(
        "SELECT {PERSON_COLS} FROM people p
         WHERE p.hidden = 0 AND p.id = COALESCE((SELECT person_id FROM person_aliases WHERE old_id = ?1), ?1)"
    );
    Ok(sqlx::query_as::<_, Person>(sqlx::AssertSqlSafe(sql)).bind(id).fetch_optional(db).await?)
}

/// Admin lookup: no alias resolution, hidden people included.
pub async fn get_any(conn: &mut SqliteConnection, id: i64) -> AppResult<Option<Person>> {
    let sql = format!("SELECT {PERSON_COLS} FROM people p WHERE p.id = ?");
    Ok(sqlx::query_as::<_, Person>(sqlx::AssertSqlSafe(sql)).bind(id).fetch_optional(&mut *conn).await?)
}

/// Match a feed's `<podcast:person>` to an existing person, or create one.
///
/// Matching order: someone with the same name already credited on this podcast, then someone with
/// the same website, then anyone with the same normalized name. Feed people are verified (the
/// feed is the show's own statement), and a match gains the feed's image/website if it had none.
pub async fn match_or_create_from_feed(
    conn: &mut SqliteConnection,
    podcast_id: i64,
    name: &str,
    img: Option<&str>,
    website: Option<&str>,
) -> AppResult<i64> {
    let norm = normalize_name(name);
    let existing: Option<i64> = sqlx::query_scalar(
        "SELECT p.id FROM people p JOIN credits c ON c.person_id = p.id
         WHERE c.podcast_id = ? AND p.name_normalized = ? AND p.hidden = 0
         ORDER BY p.id LIMIT 1",
    )
    .bind(podcast_id)
    .bind(&norm)
    .fetch_optional(&mut *conn)
    .await?;
    let existing = match (existing, website) {
        (Some(id), _) => Some(id),
        (None, Some(site)) => {
            sqlx::query_scalar("SELECT id FROM people WHERE website = ? AND name_normalized = ? AND hidden = 0 ORDER BY id LIMIT 1")
                .bind(site)
                .bind(&norm)
                .fetch_optional(&mut *conn)
                .await?
        }
        (None, None) => None,
    };
    let existing = match existing {
        Some(id) => Some(id),
        None => {
            sqlx::query_scalar("SELECT id FROM people WHERE name_normalized = ? AND hidden = 0 ORDER BY verified DESC, id LIMIT 1")
                .bind(&norm)
                .fetch_optional(&mut *conn)
                .await?
        }
    };
    if let Some(id) = existing {
        sqlx::query(
            "UPDATE people SET
                img = COALESCE(NULLIF(img, ''), ?2),
                website = COALESCE(NULLIF(website, ''), ?3),
                verified = 1
             WHERE id = ?1 AND (img IS NULL OR img = '' OR website IS NULL OR website = '' OR verified = 0)",
        )
        .bind(id)
        .bind(img)
        .bind(website)
        .execute(&mut *conn)
        .await?;
        return Ok(id);
    }
    insert(conn, name, None, img, website, true).await
}

pub async fn insert(
    conn: &mut SqliteConnection,
    name: &str,
    bio: Option<&str>,
    img: Option<&str>,
    website: Option<&str>,
    verified: bool,
) -> AppResult<i64> {
    let id = sqlx::query_scalar(
        "INSERT INTO people (slug, name, name_normalized, bio, img, website, verified)
         VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(slugify(name))
    .bind(name)
    .bind(normalize_name(name))
    .bind(bio)
    .bind(img)
    .bind(website)
    .bind(verified)
    .fetch_one(&mut *conn)
    .await?;
    Ok(id)
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct PersonSearchHit {
    #[sqlx(flatten)]
    #[serde(flatten)]
    pub person: PersonRef,
    pub podcast_count: i64,
    /// Up to three podcast titles, " · " separated, to tell namesakes apart.
    pub known_for: Option<String>,
}

/// Typeahead search. Exact name first, then prefix and word-prefix matches, then substring;
/// ties broken by how many podcasts someone is on.
pub async fn search(db: &Db, query: &str, limit: i64) -> AppResult<Vec<PersonSearchHit>> {
    let q = normalize_name(query);
    if q.is_empty() {
        return Ok(Vec::new());
    }
    let like = format!("%{}%", q.replace('%', "").replace('_', ""));
    let prefix = format!("{}%", q.replace('%', "").replace('_', ""));
    let word_prefix = format!("% {}%", q.replace('%', "").replace('_', ""));
    let sql = format!(
        "SELECT {PERSON_REF_COLS},
            (SELECT COUNT(DISTINCT c.podcast_id) FROM credits c WHERE c.person_id = p.id AND c.hidden = 0) AS podcast_count,
            (SELECT group_concat(title, ' · ') FROM (
                SELECT DISTINCT pc.title FROM credits c JOIN podcasts pc ON pc.id = c.podcast_id
                WHERE c.person_id = p.id AND c.hidden = 0 LIMIT 3)) AS known_for
         FROM people p
         WHERE p.hidden = 0 AND p.name_normalized LIKE ?1
         ORDER BY
            CASE WHEN p.name_normalized = ?2 THEN 0
                 WHEN p.name_normalized LIKE ?3 THEN 1
                 WHEN p.name_normalized LIKE ?4 THEN 2
                 ELSE 3 END,
            podcast_count DESC, p.name
         LIMIT ?5"
    );
    Ok(sqlx::query_as::<_, PersonSearchHit>(sqlx::AssertSqlSafe(sql))
        .bind(like)
        .bind(&q)
        .bind(prefix)
        .bind(word_prefix)
        .bind(limit)
        .fetch_all(db)
        .await?)
}

/// Exact normalized-name lookup (legacy `/api/host-search` semantics are fuzzier; see search()).
pub async fn find_by_name(db: &Db, name: &str) -> AppResult<Vec<Person>> {
    let sql = format!("SELECT {PERSON_COLS} FROM people p WHERE p.hidden = 0 AND p.name_normalized = ? ORDER BY p.verified DESC, p.id");
    Ok(sqlx::query_as::<_, Person>(sqlx::AssertSqlSafe(sql)).bind(normalize_name(name)).fetch_all(db).await?)
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct PersonPodcast {
    #[sqlx(flatten)]
    pub podcast: PodcastRef,
    /// Distinct roles, comma separated, most important first.
    pub roles: String,
    /// Credited on the show itself (a regular), not only on individual episodes.
    pub podcast_level: bool,
    pub episode_count: i64,
    pub latest_episode: Option<String>,
    pub verified: bool,
}

/// Every podcast a person is credited on, regulars first.
pub async fn podcasts_for(db: &Db, person_id: i64) -> AppResult<Vec<PersonPodcast>> {
    Ok(sqlx::query_as::<_, PersonPodcast>(
        "SELECT pc.id, pc.podcastindex_id, pc.title, pc.image, pc.feed_url,
            group_concat(DISTINCT c.role) AS roles,
            MAX(c.episode_id IS NULL) AS podcast_level,
            COUNT(DISTINCT c.episode_id) AS episode_count,
            MAX(e.pub_date) AS latest_episode,
            MAX(c.verified) AS verified
         FROM credits c
         JOIN podcasts pc ON pc.id = c.podcast_id
         LEFT JOIN episodes e ON e.id = c.episode_id
         WHERE c.person_id = ? AND c.hidden = 0
         GROUP BY pc.id
         ORDER BY podcast_level DESC, episode_count DESC, pc.title",
    )
    .bind(person_id)
    .fetch_all(db)
    .await?)
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct PersonEpisode {
    #[sqlx(flatten)]
    #[serde(flatten)]
    pub episode: Episode,
    pub podcast_title: String,
    pub podcast_image: Option<String>,
    pub podcastindex_id: Option<i64>,
    pub feed_url: Option<String>,
    pub role: String,
}

/// Episodes a person is individually credited on, newest first.
///
/// Podcast-level regulars are deliberately NOT expanded to every episode of their shows here:
/// that's the client's call (PinePods already has those episodes), and it keeps one-time guests
/// from showing a show's whole back catalogue.
pub async fn episodes_for(db: &Db, person_id: i64, limit: i64, offset: i64) -> AppResult<Vec<PersonEpisode>> {
    let sql = format!(
        "SELECT {EPISODE_COLS}, pc.title AS podcast_title, pc.image AS podcast_image,
            pc.podcastindex_id, pc.feed_url, group_concat(DISTINCT c.role) AS role
         FROM credits c
         JOIN episodes e ON e.id = c.episode_id
         JOIN podcasts pc ON pc.id = e.podcast_id
         WHERE c.person_id = ? AND c.hidden = 0
         GROUP BY e.id
         ORDER BY e.pub_date DESC, e.id DESC
         LIMIT ? OFFSET ?"
    );
    Ok(sqlx::query_as::<_, PersonEpisode>(sqlx::AssertSqlSafe(sql))
        .bind(person_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(db)
        .await?)
}

pub async fn episode_count_for(db: &Db, person_id: i64) -> AppResult<i64> {
    Ok(sqlx::query_scalar(
        "SELECT COUNT(DISTINCT episode_id) FROM credits WHERE person_id = ? AND episode_id IS NOT NULL AND hidden = 0",
    )
    .bind(person_id)
    .fetch_one(db)
    .await?)
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct RankedPerson {
    #[sqlx(flatten)]
    #[serde(flatten)]
    pub person: PersonRef,
    pub podcast_count: i64,
    pub episode_count: i64,
    pub known_for: Option<String>,
    pub created_at: String,
}

const RANKED_SELECT: &str = "SELECT p.id, p.slug, p.name, p.img, p.verified, p.created_at,
        COUNT(DISTINCT c.podcast_id) AS podcast_count,
        COUNT(DISTINCT c.episode_id) AS episode_count,
        (SELECT group_concat(title, ' · ') FROM (
            SELECT DISTINCT pc.title FROM credits c2 JOIN podcasts pc ON pc.id = c2.podcast_id
            WHERE c2.person_id = p.id AND c2.hidden = 0 LIMIT 2)) AS known_for
     FROM people p JOIN credits c ON c.person_id = p.id AND c.hidden = 0
     WHERE p.hidden = 0";

/// Most recently added people (that are credited on something).
pub async fn recent(db: &Db, limit: i64) -> AppResult<Vec<RankedPerson>> {
    let sql = format!("{RANKED_SELECT} GROUP BY p.id ORDER BY p.created_at DESC, p.id DESC LIMIT ?");
    Ok(sqlx::query_as::<_, RankedPerson>(sqlx::AssertSqlSafe(sql)).bind(limit).fetch_all(db).await?)
}

/// People on the most podcasts, then the most episodes.
pub async fn top(db: &Db, limit: i64) -> AppResult<Vec<RankedPerson>> {
    let sql = format!("{RANKED_SELECT} GROUP BY p.id ORDER BY podcast_count DESC, episode_count DESC, p.name LIMIT ?");
    Ok(sqlx::query_as::<_, RankedPerson>(sqlx::AssertSqlSafe(sql)).bind(limit).fetch_all(db).await?)
}

pub struct PersonEdit<'a> {
    pub name: Option<&'a str>,
    pub bio: Option<&'a str>,
    pub img: Option<&'a str>,
    pub website: Option<&'a str>,
}

/// Apply an edit. `None` fields are left alone; `Some("")` clears a field.
pub async fn update(conn: &mut SqliteConnection, id: i64, edit: &PersonEdit<'_>) -> AppResult<()> {
    if let Some(name) = edit.name {
        sqlx::query("UPDATE people SET name = ?, name_normalized = ?, slug = ? WHERE id = ?")
            .bind(name)
            .bind(normalize_name(name))
            .bind(slugify(name))
            .bind(id)
            .execute(&mut *conn)
            .await?;
    }
    for (col, val) in [("bio", edit.bio), ("img", edit.img), ("website", edit.website)] {
        if let Some(v) = val {
            let v = (!v.is_empty()).then_some(v);
            sqlx::query(sqlx::AssertSqlSafe(format!("UPDATE people SET {col} = ? WHERE id = ?")))
                .bind(v)
                .bind(id)
                .execute(&mut *conn)
                .await?;
        }
    }
    Ok(())
}

/// Merge `duplicate` into `canonical`: move credits (dropping ones that would collide), fill
/// empty fields from the duplicate, record an alias so the old id keeps resolving, delete it.
pub async fn merge(conn: &mut SqliteConnection, canonical: i64, duplicate: i64) -> AppResult<()> {
    if canonical == duplicate {
        return Err(crate::error::AppError::bad_request("cannot merge a person into themselves"));
    }
    sqlx::query(
        "UPDATE OR IGNORE credits SET person_id = ?1 WHERE person_id = ?2",
    )
    .bind(canonical)
    .bind(duplicate)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "UPDATE people SET
            bio = COALESCE(NULLIF(bio, ''), (SELECT bio FROM people WHERE id = ?2)),
            img = COALESCE(NULLIF(img, ''), (SELECT img FROM people WHERE id = ?2)),
            website = COALESCE(NULLIF(website, ''), (SELECT website FROM people WHERE id = ?2)),
            verified = MAX(verified, (SELECT verified FROM people WHERE id = ?2))
         WHERE id = ?1",
    )
    .bind(canonical)
    .bind(duplicate)
    .execute(&mut *conn)
    .await?;
    sqlx::query("UPDATE person_aliases SET person_id = ?1 WHERE person_id = ?2")
        .bind(canonical)
        .bind(duplicate)
        .execute(&mut *conn)
        .await?;
    sqlx::query("INSERT OR REPLACE INTO person_aliases (old_id, person_id) VALUES (?2, ?1)")
        .bind(canonical)
        .bind(duplicate)
        .execute(&mut *conn)
        .await?;
    // Remaining credits are exact duplicates of ones the canonical person already has.
    sqlx::query("DELETE FROM people WHERE id = ?").bind(duplicate).execute(&mut *conn).await?;
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct DuplicateGroup {
    pub name_normalized: String,
    pub people: Vec<RankedPerson>,
}

/// People sharing a normalized name: merge candidates for admins.
pub async fn duplicate_groups(db: &Db) -> AppResult<Vec<DuplicateGroup>> {
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT name_normalized FROM people WHERE hidden = 0 GROUP BY name_normalized HAVING COUNT(*) > 1 ORDER BY name_normalized",
    )
    .fetch_all(db)
    .await?;
    let mut groups = Vec::new();
    for name in names {
        let sql = format!(
            "SELECT p.id, p.slug, p.name, p.img, p.verified, p.created_at,
                (SELECT COUNT(DISTINCT podcast_id) FROM credits WHERE person_id = p.id) AS podcast_count,
                (SELECT COUNT(DISTINCT episode_id) FROM credits WHERE person_id = p.id) AS episode_count,
                (SELECT group_concat(title, ' · ') FROM (
                    SELECT DISTINCT pc.title FROM credits c2 JOIN podcasts pc ON pc.id = c2.podcast_id
                    WHERE c2.person_id = p.id LIMIT 2)) AS known_for
             FROM people p WHERE p.hidden = 0 AND p.name_normalized = ? ORDER BY podcast_count DESC, p.id"
        );
        let people = sqlx::query_as::<_, RankedPerson>(sqlx::AssertSqlSafe(sql)).bind(&name).fetch_all(db).await?;
        groups.push(DuplicateGroup { name_normalized: name, people });
    }
    Ok(groups)
}

/// Delete a person if nothing credits them any more (used when reverting a submission).
pub async fn delete_if_orphan(conn: &mut SqliteConnection, id: i64) -> AppResult<bool> {
    let res = sqlx::query("DELETE FROM people WHERE id = ? AND NOT EXISTS (SELECT 1 FROM credits WHERE person_id = ?)")
        .bind(id)
        .bind(id)
        .execute(&mut *conn)
        .await?;
    Ok(res.rows_affected() > 0)
}

pub type Tx<'a> = sqlx::Transaction<'a, Sqlite>;
