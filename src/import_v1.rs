//! One-time import of a v1 (Go) PodPeopleDB database into the v2 schema.
//!
//! The v1 file is opened read-only and never modified, so rolling back is just running the old
//! image again. Host ids are kept as person ids because PinePods stores them (`PeopleDBID`).
//! v1's pending submissions become live-but-unreviewed submissions in the review queue.

use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;

use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Row, SqlitePool};

use crate::db::{fmt_ts, parse_ts, Db};
use crate::error::{AppError, AppResult};
use crate::normalize::{normalize_feed_url, normalize_name, normalize_role, slugify};
use crate::store::submissions::Payload;

#[derive(Debug, Default, serde::Serialize)]
pub struct ImportReport {
    pub admins: usize,
    pub people: usize,
    pub podcasts: usize,
    pub episodes: usize,
    pub podcast_credits: usize,
    pub episode_credits: usize,
    pub pending_submissions: usize,
    pub skipped: usize,
}

fn ts(v: Option<String>) -> String {
    v.as_deref().and_then(parse_ts).map(fmt_ts).unwrap_or_else(crate::db::now)
}

async fn has_table(pool: &SqlitePool, name: &str) -> AppResult<bool> {
    Ok(sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?")
        .bind(name)
        .fetch_one(pool)
        .await?
        > 0)
}

pub async fn import(v1_path: &Path, db: &Db) -> AppResult<ImportReport> {
    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", v1_path.display()))?.read_only(true);
    let v1 = SqlitePool::connect_with(opts).await?;
    if !has_table(&v1, "hosts").await? || !has_table(&v1, "host_podcasts").await? {
        return Err(AppError::Internal(format!("{} is not a v1 PodPeopleDB database", v1_path.display())));
    }
    let mut report = ImportReport::default();
    let mut tx = db.begin().await?;

    // Admins: bcrypt hashes carry over and are upgraded to argon2 on next login.
    for row in sqlx::query("SELECT username, password, created_at FROM admins").fetch_all(&v1).await? {
        let username: String = row.try_get("username")?;
        let hash: String = row.try_get("password")?;
        let created: Option<String> = row.try_get("created_at").ok();
        let res = sqlx::query("INSERT OR IGNORE INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)")
            .bind(username)
            .bind(hash)
            .bind(ts(created))
            .execute(&mut *tx)
            .await?;
        report.admins += res.rows_affected() as usize;
    }

    // Podcasts, keyed by their v1 id (= Podcast Index id).
    let mut podcast_ids: HashMap<i64, i64> = HashMap::new();
    for row in sqlx::query("SELECT id, title, feed_url FROM podcasts").fetch_all(&v1).await? {
        let index_id: i64 = row.try_get("id")?;
        let title: String = row.try_get::<Option<String>, _>("title")?.unwrap_or_default();
        let feed_url = row.try_get::<Option<String>, _>("feed_url")?.as_deref().and_then(normalize_feed_url);
        // v1 used 0 for "not from the Index".
        let index_col = (index_id > 0).then_some(index_id);
        let existing: Option<i64> = match &feed_url {
            Some(u) => sqlx::query_scalar("SELECT id FROM podcasts WHERE feed_url = ?").bind(u).fetch_optional(&mut *tx).await?,
            None => None,
        };
        let id = match existing {
            Some(id) => id,
            None => {
                sqlx::query_scalar(
                    "INSERT INTO podcasts (podcastindex_id, feed_url, title, next_crawl_at) VALUES (?, ?, ?, ?)
                     ON CONFLICT(podcastindex_id) DO UPDATE SET title = excluded.title RETURNING id",
                )
                .bind(index_col)
                .bind(&feed_url)
                .bind(if title.trim().is_empty() { "Untitled podcast" } else { title.trim() })
                .bind(crate::db::now())
                .fetch_one(&mut *tx)
                .await?
            }
        };
        podcast_ids.insert(index_id, id);
        report.podcasts += 1;
    }

    // People, keeping their ids.
    let hosts = sqlx::query("SELECT id, name, description, link, img, created_at FROM hosts").fetch_all(&v1).await?;
    let approved_hosts: Vec<i64> = sqlx::query_scalar("SELECT DISTINCT host_id FROM host_podcasts WHERE status = 'approved'")
        .fetch_all(&v1)
        .await?;
    for row in hosts {
        let id: i64 = row.try_get("id")?;
        let name: String = row.try_get::<Option<String>, _>("name")?.unwrap_or_default();
        let name = crate::normalize::clean_name(&name);
        if normalize_name(&name).is_empty() {
            report.skipped += 1;
            continue;
        }
        let opt = |col: &str| -> Option<String> {
            row.try_get::<Option<String>, _>(col).ok().flatten().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
        };
        let created = ts(row.try_get("created_at").ok());
        sqlx::query(
            "INSERT INTO people (id, slug, name, name_normalized, bio, img, website, verified, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(slugify(&name))
        .bind(&name)
        .bind(normalize_name(&name))
        .bind(opt("description"))
        .bind(crate::normalize::clean_url(opt("img").as_deref()))
        .bind(crate::normalize::clean_url(opt("link").as_deref()))
        .bind(approved_hosts.contains(&id))
        .bind(&created)
        .bind(&created)
        .execute(&mut *tx)
        .await?;
        report.people += 1;
    }

    // Podcast-level credits. v1 rejected rows are dropped; pending rows become live, unreviewed
    // submissions (one per person) so they show up in the review queue.
    let mut pending: HashMap<i64, Vec<i64>> = HashMap::new();
    for row in sqlx::query("SELECT host_id, podcast_id, role, status, created_at FROM host_podcasts").fetch_all(&v1).await? {
        let host_id: i64 = row.try_get("host_id")?;
        let v1_podcast: i64 = row.try_get("podcast_id")?;
        let status: String = row.try_get::<Option<String>, _>("status")?.unwrap_or_else(|| "pending".into());
        let role = normalize_role(&row.try_get::<Option<String>, _>("role")?.unwrap_or_default());
        let (Some(&podcast_id), true) = (podcast_ids.get(&v1_podcast), status != "rejected") else {
            report.skipped += 1;
            continue;
        };
        let created = ts(row.try_get("created_at").ok());
        let credit_id: Option<i64> = sqlx::query_scalar(
            "INSERT OR IGNORE INTO credits (person_id, podcast_id, role, person_group, source, verified, created_at, updated_at)
             SELECT ?, ?, ?, ?, 'community', ?, ?, ? WHERE EXISTS (SELECT 1 FROM people WHERE id = ?)
             RETURNING id",
        )
        .bind(host_id)
        .bind(podcast_id)
        .bind(&role)
        .bind(crate::normalize::group_for_role(&role, None))
        .bind(status == "approved")
        .bind(&created)
        .bind(&created)
        .bind(host_id)
        .fetch_optional(&mut *tx)
        .await?;
        match credit_id {
            Some(cid) => {
                report.podcast_credits += 1;
                if status != "approved" {
                    pending.entry(host_id).or_default().push(cid);
                }
            }
            None => report.skipped += 1,
        }
    }

    // Episodes (the crawler refreshes these; importing keeps episode guest credits intact).
    let mut episode_ids: HashMap<i64, i64> = HashMap::new();
    let guest_episodes: std::collections::HashSet<i64> = if has_table(&v1, "episode_guests").await? {
        sqlx::query_scalar("SELECT episode_id FROM episode_guests").fetch_all(&v1).await?.into_iter().collect()
    } else {
        Default::default()
    };
    if has_table(&v1, "episodes").await? {
        for row in sqlx::query(
            "SELECT id, podcast_id, title, description, audio_url, pub_date, duration, season_number, episode_number, image_url, link, guid
             FROM episodes",
        )
        .fetch_all(&v1)
        .await?
        {
            let v1_id: i64 = row.try_get("id")?;
            let v1_podcast: i64 = row.try_get("podcast_id")?;
            // v1 cached episodes of podcasts it never stored. Only keep those someone is credited
            // on, under a placeholder podcast the crawler fills in from the Index.
            if !podcast_ids.contains_key(&v1_podcast) && guest_episodes.contains(&v1_id) && v1_podcast > 0 {
                let id: i64 = sqlx::query_scalar(
                    "INSERT INTO podcasts (podcastindex_id, title, next_crawl_at) VALUES (?, ?, ?)
                     ON CONFLICT(podcastindex_id) DO UPDATE SET title = title RETURNING id",
                )
                .bind(v1_podcast)
                .bind(format!("Podcast {v1_podcast}"))
                .bind(crate::db::now())
                .fetch_one(&mut *tx)
                .await?;
                podcast_ids.insert(v1_podcast, id);
                report.podcasts += 1;
            }
            let Some(&podcast_id) = podcast_ids.get(&v1_podcast) else {
                report.skipped += 1;
                continue;
            };
            let s = |col: &str| row.try_get::<Option<String>, _>(col).ok().flatten().filter(|v| !v.trim().is_empty());
            let n = |col: &str| row.try_get::<Option<i64>, _>(col).ok().flatten();
            let id: i64 = sqlx::query_scalar(
                "INSERT INTO episodes (podcast_id, guid, enclosure_url, title, description, link, image, pub_date, duration, season, episode_number)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT(podcast_id, guid) WHERE guid IS NOT NULL DO UPDATE SET guid = excluded.guid
                 RETURNING id",
            )
            .bind(podcast_id)
            .bind(s("guid"))
            .bind(s("audio_url"))
            .bind(s("title").unwrap_or_else(|| "Untitled episode".into()))
            .bind(s("description").map(|d| d.chars().take(4000).collect::<String>()))
            .bind(s("link"))
            .bind(s("image_url"))
            .bind(s("pub_date").as_deref().and_then(parse_ts).map(fmt_ts))
            .bind(n("duration"))
            .bind(n("season_number"))
            .bind(n("episode_number"))
            .fetch_one(&mut *tx)
            .await?;
            episode_ids.insert(v1_id, id);
            report.episodes += 1;
        }
    }

    if has_table(&v1, "episode_guests").await? {
        for row in sqlx::query("SELECT episode_id, host_id, role, status, created_at FROM episode_guests").fetch_all(&v1).await? {
            let v1_episode: i64 = row.try_get("episode_id")?;
            let host_id: i64 = row.try_get("host_id")?;
            let status: String = row.try_get::<Option<String>, _>("status")?.unwrap_or_else(|| "pending".into());
            let role = normalize_role(&row.try_get::<Option<String>, _>("role")?.unwrap_or_else(|| "guest".into()));
            let Some(&episode_id) = episode_ids.get(&v1_episode).filter(|_| status != "rejected") else {
                report.skipped += 1;
                continue;
            };
            let created = ts(row.try_get("created_at").ok());
            let credit_id: Option<i64> = sqlx::query_scalar(
                "INSERT OR IGNORE INTO credits (person_id, podcast_id, episode_id, role, person_group, source, verified, created_at, updated_at)
                 SELECT ?, e.podcast_id, e.id, ?, ?, 'community', ?, ?, ? FROM episodes e
                 WHERE e.id = ? AND EXISTS (SELECT 1 FROM people WHERE id = ?)
                 RETURNING id",
            )
            .bind(host_id)
            .bind(&role)
            .bind(crate::normalize::group_for_role(&role, None))
            .bind(status == "approved")
            .bind(&created)
            .bind(&created)
            .bind(episode_id)
            .bind(host_id)
            .fetch_optional(&mut *tx)
            .await?;
            match credit_id {
                Some(cid) => {
                    report.episode_credits += 1;
                    if status != "approved" {
                        pending.entry(host_id).or_default().push(cid);
                    }
                }
                None => report.skipped += 1,
            }
        }
    }

    for (host_id, credit_ids) in pending {
        let name: String = sqlx::query_scalar("SELECT name FROM people WHERE id = ?").bind(host_id).fetch_one(&mut *tx).await?;
        let podcast_id: Option<i64> = sqlx::query_scalar("SELECT podcast_id FROM credits WHERE id = ?").bind(credit_ids[0]).fetch_optional(&mut *tx).await?;
        let verified: bool = sqlx::query_scalar("SELECT verified FROM people WHERE id = ?").bind(host_id).fetch_one(&mut *tx).await?;
        let payload = Payload {
            created_people: if verified { vec![] } else { vec![host_id] },
            credit_ids: credit_ids.clone(),
            ..Default::default()
        };
        let sub_id: i64 = sqlx::query_scalar(
            "INSERT INTO submissions (kind, payload, summary, podcast_id, client) VALUES ('credits', ?, ?, ?, 'v1-import') RETURNING id",
        )
        .bind(serde_json::to_string(&payload)?)
        .bind(format!("{name} (pending in v1)"))
        .bind(podcast_id)
        .fetch_one(&mut *tx)
        .await?;
        for cid in &credit_ids {
            sqlx::query("UPDATE credits SET submission_id = ? WHERE id = ?").bind(sub_id).bind(cid).execute(&mut *tx).await?;
        }
        report.pending_submissions += 1;
    }

    tx.commit().await?;
    v1.close().await;
    Ok(report)
}
