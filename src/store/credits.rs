use serde::Serialize;
use sqlx::SqliteConnection;

use super::{PersonRef, PERSON_REF_COLS};
use crate::db::Db;
use crate::error::AppResult;
use crate::normalize::{group_for_role, normalize_role};

pub struct NewCredit<'a> {
    pub person_id: i64,
    pub podcast_id: i64,
    pub episode_id: Option<i64>,
    pub role: &'a str,
    pub group: Option<&'a str>,
    pub source: &'static str,
    pub verified: bool,
    pub submission_id: Option<i64>,
}

/// Add a credit, or return the existing identical one. `.1` is true when a row was created.
pub async fn add(conn: &mut SqliteConnection, c: &NewCredit<'_>) -> AppResult<(i64, bool)> {
    let role = normalize_role(c.role);
    let group = group_for_role(&role, c.group);
    let existing: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM credits
         WHERE person_id = ? AND podcast_id = ? AND IFNULL(episode_id, 0) = IFNULL(?, 0) AND role = ? AND source = ?",
    )
    .bind(c.person_id)
    .bind(c.podcast_id)
    .bind(c.episode_id)
    .bind(&role)
    .bind(c.source)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some(id) = existing {
        // Re-submitting a credit an admin hid leaves it hidden.
        if c.verified {
            sqlx::query("UPDATE credits SET verified = 1 WHERE id = ? AND verified = 0").bind(id).execute(&mut *conn).await?;
        }
        return Ok((id, false));
    }
    let id = sqlx::query_scalar(
        "INSERT INTO credits (person_id, podcast_id, episode_id, role, person_group, source, verified, submission_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(c.person_id)
    .bind(c.podcast_id)
    .bind(c.episode_id)
    .bind(&role)
    .bind(&group)
    .bind(c.source)
    .bind(c.verified)
    .bind(c.submission_id)
    .fetch_one(&mut *conn)
    .await?;
    Ok((id, true))
}

/// After a crawl: drop feed credits the feed no longer asserts.
pub async fn prune_feed_credits(conn: &mut SqliteConnection, podcast_id: i64, keep: &[i64]) -> AppResult<u64> {
    sqlx::query("CREATE TEMP TABLE IF NOT EXISTS keep_credits (id INTEGER PRIMARY KEY)").execute(&mut *conn).await?;
    sqlx::query("DELETE FROM keep_credits").execute(&mut *conn).await?;
    for chunk in keep.chunks(500) {
        let placeholders = vec!["(?)"; chunk.len()].join(",");
        let mut q = sqlx::query(sqlx::AssertSqlSafe(format!("INSERT OR IGNORE INTO keep_credits (id) VALUES {placeholders}")));
        for id in chunk {
            q = q.bind(id);
        }
        q.execute(&mut *conn).await?;
    }
    let res = sqlx::query(
        "DELETE FROM credits WHERE podcast_id = ? AND source = 'feed' AND id NOT IN (SELECT id FROM keep_credits)",
    )
    .bind(podcast_id)
    .execute(&mut *conn)
    .await?;
    sqlx::query("DELETE FROM keep_credits").execute(&mut *conn).await?;
    Ok(res.rows_affected())
}

/// A person as they appear on one podcast, with every way they're credited there merged.
#[derive(Debug, Clone, Serialize)]
pub struct PodcastPerson {
    pub person: PersonRef,
    /// Distinct roles, most significant first.
    pub roles: Vec<String>,
    pub group: String,
    /// "podcast": credited on the show itself. "episodes": only on individual episodes.
    pub scope: &'static str,
    pub episode_count: i64,
    /// "feed" and/or "community".
    pub sources: Vec<String>,
    /// True when the credit came from the feed or an admin reviewed it.
    pub verified: bool,
}

#[derive(sqlx::FromRow)]
struct PodcastPersonRow {
    #[sqlx(flatten)]
    person: PersonRef,
    roles: String,
    person_group: String,
    podcast_level: bool,
    episode_count: i64,
    sources: String,
    credit_verified: bool,
}

fn role_rank(role: &str) -> u8 {
    match role {
        "host" => 0,
        "co-host" => 1,
        "guest host" => 2,
        "guest" => 9,
        _ => 5,
    }
}

/// People on a podcast: `.0` are the show's people (podcast-level credits of any role, plus
/// anyone credited as host/co-host on a good share of episodes, since many feeds tag hosts per
/// item); `.1` are guests and other episode-only credits, most frequent first.
pub async fn people_for_podcast(db: &Db, podcast_id: i64, guest_limit: i64) -> AppResult<(Vec<PodcastPerson>, Vec<PodcastPerson>)> {
    let sql = format!(
        "SELECT {PERSON_REF_COLS},
            group_concat(DISTINCT c.role) AS roles,
            MIN(c.person_group) AS person_group,
            MAX(c.episode_id IS NULL) AS podcast_level,
            COUNT(DISTINCT c.episode_id) AS episode_count,
            group_concat(DISTINCT c.source) AS sources,
            MAX(c.verified) AS credit_verified
         FROM credits c JOIN people p ON p.id = c.person_id
         WHERE c.podcast_id = ? AND c.hidden = 0 AND p.hidden = 0
         GROUP BY p.id
         ORDER BY podcast_level DESC, episode_count DESC, p.name"
    );
    let rows = sqlx::query_as::<_, PodcastPersonRow>(sqlx::AssertSqlSafe(sql)).bind(podcast_id).fetch_all(db).await?;
    // Feeds that tag hosts per item rather than on the channel: someone tagged "host" counts as a
    // regular only if they're on a fair share of the tagged episodes, so a one-off guest host
    // stays with the guests.
    let tagged_episodes: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT episode_id) FROM credits WHERE podcast_id = ? AND episode_id IS NOT NULL AND hidden = 0",
    )
    .bind(podcast_id)
    .fetch_one(db)
    .await?;
    let regular_threshold = ((tagged_episodes as f64) * 0.2).ceil().max(2.0) as i64;
    let mut show = Vec::new();
    let mut guests = Vec::new();
    for r in rows {
        let mut roles: Vec<String> = r.roles.split(',').map(str::to_string).collect();
        roles.sort_by_key(|r| role_rank(r));
        let is_regular = r.podcast_level
            || (roles.iter().any(|r| crate::normalize::is_host_role(r)) && r.episode_count >= regular_threshold);
        let person = PodcastPerson {
            person: r.person,
            roles,
            group: r.person_group,
            scope: if r.podcast_level { "podcast" } else { "episodes" },
            episode_count: r.episode_count,
            sources: r.sources.split(',').map(str::to_string).collect(),
            verified: r.credit_verified,
        };
        if is_regular {
            show.push(person);
        } else if (guests.len() as i64) < guest_limit {
            guests.push(person);
        }
    }
    show.sort_by(|a, b| {
        (a.scope != "podcast")
            .cmp(&(b.scope != "podcast"))
            .then(role_rank(&a.roles[0]).cmp(&role_rank(&b.roles[0])))
            .then(b.episode_count.cmp(&a.episode_count))
    });
    Ok((show, guests))
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct EpisodeCredit {
    #[sqlx(flatten)]
    pub person: PersonRef,
    pub credit_id: i64,
    pub episode_id: i64,
    pub role: String,
    #[sqlx(rename = "person_group")]
    pub group: String,
    pub source: String,
    #[sqlx(rename = "credit_verified")]
    pub verified: bool,
}

/// Episode-level credits for a set of episodes (one query).
pub async fn for_episodes(db: &Db, episode_ids: &[i64]) -> AppResult<Vec<EpisodeCredit>> {
    if episode_ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for chunk in episode_ids.chunks(500) {
        let placeholders = vec!["?"; chunk.len()].join(",");
        let sql = format!(
            "SELECT {PERSON_REF_COLS}, c.id AS credit_id, c.episode_id, c.role, c.person_group, c.source,
                c.verified AS credit_verified
             FROM credits c JOIN people p ON p.id = c.person_id
             WHERE c.episode_id IN ({placeholders}) AND c.hidden = 0 AND p.hidden = 0
             ORDER BY c.episode_id, CASE c.role WHEN 'host' THEN 0 WHEN 'co-host' THEN 1 WHEN 'guest' THEN 3 ELSE 2 END, p.name"
        );
        let mut q = sqlx::query_as::<_, EpisodeCredit>(sqlx::AssertSqlSafe(sql));
        for id in chunk {
            q = q.bind(id);
        }
        out.extend(q.fetch_all(db).await?);
    }
    Ok(out)
}

/// Community credits on a podcast's episodes, for integrations that already have the feed's own
/// tags and only need what the community added.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct CommunityEpisodeCredit {
    #[sqlx(flatten)]
    pub person: PersonRef,
    pub role: String,
    #[sqlx(rename = "person_group")]
    pub group: String,
    pub episode_guid: Option<String>,
    pub enclosure_url: Option<String>,
    pub episode_title: String,
    #[sqlx(rename = "credit_verified")]
    pub verified: bool,
}

pub async fn community_episode_credits(db: &Db, podcast_id: i64) -> AppResult<Vec<CommunityEpisodeCredit>> {
    let sql = format!(
        "SELECT {PERSON_REF_COLS}, c.role, c.person_group, e.guid AS episode_guid, e.enclosure_url,
            e.title AS episode_title, c.verified AS credit_verified
         FROM credits c JOIN people p ON p.id = c.person_id JOIN episodes e ON e.id = c.episode_id
         WHERE c.podcast_id = ? AND c.source = 'community' AND c.hidden = 0 AND p.hidden = 0
         ORDER BY e.pub_date DESC"
    );
    Ok(sqlx::query_as::<_, CommunityEpisodeCredit>(sqlx::AssertSqlSafe(sql)).bind(podcast_id).fetch_all(db).await?)
}
