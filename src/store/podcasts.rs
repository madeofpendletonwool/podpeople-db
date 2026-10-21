use std::collections::HashMap;

use serde::Serialize;
use sqlx::SqliteConnection;

use super::credits::{self, NewCredit};
use super::{people, Episode, Podcast, EPISODE_COLS, PODCAST_COLS};
use crate::db::Db;
use crate::error::AppResult;
use crate::feed::ParsedFeed;
use crate::index::IndexFeed;
use crate::normalize::{clean_url, normalize_name, split_names};

pub async fn get(db: &Db, id: i64) -> AppResult<Option<Podcast>> {
    let sql = format!("SELECT {PODCAST_COLS} FROM podcasts WHERE id = ?");
    Ok(sqlx::query_as::<_, Podcast>(sqlx::AssertSqlSafe(sql)).bind(id).fetch_optional(db).await?)
}

pub async fn by_index_id(db: &Db, index_id: i64) -> AppResult<Option<Podcast>> {
    let sql = format!("SELECT {PODCAST_COLS} FROM podcasts WHERE podcastindex_id = ?");
    Ok(sqlx::query_as::<_, Podcast>(sqlx::AssertSqlSafe(sql)).bind(index_id).fetch_optional(db).await?)
}

pub async fn by_feed_url(db: &Db, feed_url: &str) -> AppResult<Option<Podcast>> {
    let sql = format!("SELECT {PODCAST_COLS} FROM podcasts WHERE feed_url = ?");
    Ok(sqlx::query_as::<_, Podcast>(sqlx::AssertSqlSafe(sql)).bind(feed_url).fetch_optional(db).await?)
}

pub async fn by_guid(db: &Db, guid: &str) -> AppResult<Option<Podcast>> {
    let sql = format!("SELECT {PODCAST_COLS} FROM podcasts WHERE podcast_guid = ? ORDER BY id LIMIT 1");
    Ok(sqlx::query_as::<_, Podcast>(sqlx::AssertSqlSafe(sql)).bind(guid).fetch_optional(db).await?)
}

/// Insert a podcast known to the Podcast Index, or fill in an existing row that matches by feed
/// URL (a podcast first added by URL that later turns out to be indexed).
pub async fn upsert_from_index(db: &Db, f: &IndexFeed) -> AppResult<i64> {
    let feed_url = crate::normalize::normalize_feed_url(&f.url);
    if let Some(url) = &feed_url {
        if let Some(existing) = by_feed_url(db, url).await? {
            sqlx::query("UPDATE podcasts SET podcastindex_id = COALESCE(podcastindex_id, ?) WHERE id = ?")
                .bind(f.id)
                .bind(existing.id)
                .execute(db)
                .await?;
            return Ok(existing.id);
        }
    }
    let nonempty = |s: &str| (!s.trim().is_empty()).then(|| s.trim().to_string());
    let id = sqlx::query_scalar(
        "INSERT INTO podcasts (podcastindex_id, podcast_guid, feed_url, title, description, author, owner_name, image, link, next_crawl_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(podcastindex_id) DO UPDATE SET feed_url = COALESCE(podcasts.feed_url, excluded.feed_url)
         RETURNING id",
    )
    .bind(f.id)
    .bind(nonempty(&f.podcast_guid))
    .bind(feed_url)
    .bind(if f.title.trim().is_empty() { "Untitled podcast".to_string() } else { f.title.trim().to_string() })
    .bind(nonempty(&f.description))
    .bind(nonempty(&f.author))
    .bind(nonempty(&f.owner_name))
    .bind(clean_url(f.image().as_deref()))
    .bind(clean_url(Some(&f.link)))
    .bind(crate::db::now())
    .fetch_one(db)
    .await?;
    Ok(id)
}

/// Insert a podcast by feed URL (not in the Podcast Index, or the caller only knows the URL).
pub async fn insert_by_feed_url(db: &Db, feed_url: &str, title: &str) -> AppResult<i64> {
    let id = sqlx::query_scalar(
        "INSERT INTO podcasts (feed_url, title, next_crawl_at) VALUES (?, ?, ?)
         ON CONFLICT(feed_url) WHERE feed_url IS NOT NULL DO UPDATE SET feed_url = excluded.feed_url
         RETURNING id",
    )
    .bind(feed_url)
    .bind(title)
    .bind(crate::db::now())
    .fetch_one(db)
    .await?;
    Ok(id)
}

/// A podcast with no public feed (#7): only what the contributor tells us.
pub async fn insert_manual(db: &Db, title: &str, link: Option<&str>, image: Option<&str>, author: Option<&str>) -> AppResult<i64> {
    Ok(sqlx::query_scalar(
        "INSERT INTO podcasts (title, link, image, author) VALUES (?, ?, ?, ?) RETURNING id",
    )
    .bind(title)
    .bind(link)
    .bind(image)
    .bind(author)
    .fetch_one(db)
    .await?)
}

#[derive(Debug, Default, Serialize)]
pub struct IngestStats {
    pub episodes_added: usize,
    pub episodes_updated: usize,
    pub credits_added: usize,
    pub credits_removed: u64,
}

/// Store a parsed feed: podcast metadata, every item as an episode, and every `<podcast:person>`
/// as a feed credit. Feed credits the feed no longer carries are removed; community credits are
/// never touched.
pub async fn ingest_feed(conn: &mut SqliteConnection, podcast_id: i64, feed: &ParsedFeed) -> AppResult<IngestStats> {
    let mut stats = IngestStats::default();
    sqlx::query(
        "UPDATE podcasts SET
            title = CASE WHEN ?2 != '' THEN ?2 ELSE title END,
            description = COALESCE(?3, description),
            author = COALESCE(?4, author),
            owner_name = COALESCE(?5, owner_name),
            image = COALESCE(?6, image),
            link = COALESCE(?7, link),
            podcast_guid = COALESCE(?8, podcast_guid),
            has_person_tags = ?9
         WHERE id = ?1",
    )
    .bind(podcast_id)
    .bind(feed.title.trim())
    .bind(feed.description.as_deref().map(|d| d.chars().take(4000).collect::<String>()))
    .bind(&feed.author)
    .bind(&feed.owner_name)
    .bind(clean_url(feed.image.as_deref()))
    .bind(clean_url(feed.link.as_deref()))
    .bind(&feed.podcast_guid)
    .bind(feed.has_person_tags())
    .execute(&mut *conn)
    .await?;

    // Existing episodes, keyed both ways so items without a GUID still match by enclosure.
    #[derive(sqlx::FromRow)]
    struct Existing {
        id: i64,
        guid: Option<String>,
        enclosure_url: Option<String>,
        title: String,
        pub_date: Option<String>,
        duration: Option<i64>,
        image: Option<String>,
    }
    let existing: Vec<Existing> = sqlx::query_as(
        "SELECT id, guid, enclosure_url, title, pub_date, duration, image FROM episodes WHERE podcast_id = ?",
    )
    .bind(podcast_id)
    .fetch_all(&mut *conn)
    .await?;
    let mut by_guid: HashMap<String, usize> = HashMap::new();
    let mut by_url: HashMap<String, usize> = HashMap::new();
    for (i, e) in existing.iter().enumerate() {
        if let Some(g) = &e.guid {
            by_guid.insert(g.clone(), i);
        }
        if let Some(u) = &e.enclosure_url {
            by_url.insert(u.clone(), i);
        }
    }

    let mut keep_credits = Vec::new();
    for person in &feed.people {
        let pid = people::match_or_create_from_feed(conn, podcast_id, &person.name, clean_url(person.img.as_deref()).as_deref(), clean_url(person.href.as_deref()).as_deref()).await?;
        let (cid, created) = credits::add(conn, &NewCredit {
            person_id: pid,
            podcast_id,
            episode_id: None,
            role: person.role.as_deref().unwrap_or("host"),
            group: person.group.as_deref(),
            source: "feed",
            verified: true,
            submission_id: None,
        })
        .await?;
        stats.credits_added += created as usize;
        keep_credits.push(cid);
    }

    for item in &feed.items {
        let guid = item.guid.clone().filter(|g| !g.is_empty());
        let found = guid
            .as_ref()
            .and_then(|g| by_guid.get(g))
            .or_else(|| item.enclosure_url.as_ref().and_then(|u| by_url.get(u)))
            .copied();
        let title = if item.title.trim().is_empty() { "Untitled episode" } else { item.title.trim() };
        let description = item.description.as_deref().map(|d| d.chars().take(4000).collect::<String>());
        let episode_id = match found {
            Some(i) => {
                let e = &existing[i];
                let changed = e.title != title
                    || e.pub_date != item.pub_date
                    || e.duration != item.duration
                    || e.image != item.image
                    || e.enclosure_url != item.enclosure_url
                    || (e.guid.is_none() && guid.is_some());
                if changed {
                    sqlx::query(
                        "UPDATE episodes SET guid = COALESCE(?2, guid), enclosure_url = ?3, title = ?4, description = ?5,
                            link = ?6, image = ?7, pub_date = ?8, duration = ?9, season = ?10, episode_number = ?11
                         WHERE id = ?1",
                    )
                    .bind(e.id)
                    .bind(&guid)
                    .bind(&item.enclosure_url)
                    .bind(title)
                    .bind(&description)
                    .bind(clean_url(item.link.as_deref()))
                    .bind(clean_url(item.image.as_deref()))
                    .bind(&item.pub_date)
                    .bind(item.duration)
                    .bind(item.season)
                    .bind(item.episode_number)
                    .execute(&mut *conn)
                    .await?;
                    stats.episodes_updated += 1;
                }
                e.id
            }
            None => {
                // A duplicate GUID inside the same feed would violate the unique index; the
                // ON CONFLICT keeps the first.
                let id: i64 = sqlx::query_scalar(
                    "INSERT INTO episodes (podcast_id, guid, enclosure_url, title, description, link, image, pub_date, duration, season, episode_number)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                     ON CONFLICT(podcast_id, guid) WHERE guid IS NOT NULL DO UPDATE SET guid = excluded.guid
                     RETURNING id",
                )
                .bind(podcast_id)
                .bind(&guid)
                .bind(&item.enclosure_url)
                .bind(title)
                .bind(&description)
                .bind(clean_url(item.link.as_deref()))
                .bind(clean_url(item.image.as_deref()))
                .bind(&item.pub_date)
                .bind(item.duration)
                .bind(item.season)
                .bind(item.episode_number)
                .fetch_one(&mut *conn)
                .await?;
                stats.episodes_added += 1;
                id
            }
        };
        for person in &item.people {
            let pid = people::match_or_create_from_feed(conn, podcast_id, &person.name, clean_url(person.img.as_deref()).as_deref(), clean_url(person.href.as_deref()).as_deref()).await?;
            let (cid, created) = credits::add(conn, &NewCredit {
                person_id: pid,
                podcast_id,
                episode_id: Some(episode_id),
                role: person.role.as_deref().unwrap_or("host"),
                group: person.group.as_deref(),
                source: "feed",
                verified: true,
                submission_id: None,
            })
            .await?;
            stats.credits_added += created as usize;
            keep_credits.push(cid);
        }
    }

    stats.credits_removed = credits::prune_feed_credits(conn, podcast_id, &keep_credits).await?;
    Ok(stats)
}

pub async fn record_crawl(db: &Db, podcast_id: i64, etag: Option<&str>, last_modified: Option<&str>, next_hours: i64) -> AppResult<()> {
    let next = crate::db::fmt_ts(chrono::Utc::now() + chrono::Duration::hours(next_hours));
    sqlx::query(
        "UPDATE podcasts SET etag = COALESCE(?2, etag), last_modified = COALESCE(?3, last_modified),
            last_crawled_at = ?4, next_crawl_at = ?5, crawl_error = NULL, crawl_failures = 0
         WHERE id = ?1",
    )
    .bind(podcast_id)
    .bind(etag)
    .bind(last_modified)
    .bind(crate::db::now())
    .bind(next)
    .execute(db)
    .await?;
    Ok(())
}

/// Back off linearly (6h per consecutive failure, capped at a week).
pub async fn record_crawl_failure(db: &Db, podcast_id: i64, error: &str) -> AppResult<()> {
    let failures: i64 = sqlx::query_scalar("UPDATE podcasts SET crawl_failures = crawl_failures + 1, crawl_error = ? WHERE id = ? RETURNING crawl_failures")
        .bind(error.chars().take(500).collect::<String>())
        .bind(podcast_id)
        .fetch_one(db)
        .await?;
    let next = crate::db::fmt_ts(chrono::Utc::now() + chrono::Duration::hours((6 * failures).min(24 * 7)));
    sqlx::query("UPDATE podcasts SET next_crawl_at = ? WHERE id = ?").bind(next).bind(podcast_id).execute(db).await?;
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
pub struct CrawlTarget {
    pub id: i64,
    pub feed_url: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

pub async fn crawl_target(db: &Db, id: i64) -> AppResult<Option<CrawlTarget>> {
    Ok(sqlx::query_as("SELECT id, feed_url, etag, last_modified FROM podcasts WHERE id = ? AND feed_url IS NOT NULL")
        .bind(id)
        .fetch_optional(db)
        .await?)
}

/// Indexed podcasts we have no feed URL for yet (v1 didn't store them).
pub async fn missing_feed_urls(db: &Db, limit: i64) -> AppResult<Vec<(i64, i64)>> {
    Ok(sqlx::query_as(
        "SELECT id, podcastindex_id FROM podcasts
         WHERE feed_url IS NULL AND podcastindex_id IS NOT NULL AND crawl_failures < 5 ORDER BY id LIMIT ?",
    )
    .bind(limit)
    .fetch_all(db)
    .await?)
}

/// Fill a podcast's feed URL (and anything else missing) from its Podcast Index entry.
pub async fn fill_from_index(db: &Db, id: i64, f: &IndexFeed) -> AppResult<()> {
    let nonempty = |s: &str| (!s.trim().is_empty()).then(|| s.trim().to_string());
    let feed_url = crate::normalize::normalize_feed_url(&f.url);
    // Another row may already own this feed URL; leave that to an admin merge.
    let taken: bool = match &feed_url {
        Some(u) => sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM podcasts WHERE feed_url = ? AND id != ?").bind(u).bind(id).fetch_one(db).await? > 0,
        None => true,
    };
    sqlx::query(
        "UPDATE podcasts SET
            feed_url = COALESCE(feed_url, ?2),
            title = CASE WHEN title = 'Podcast ' || podcastindex_id AND ?3 IS NOT NULL THEN ?3 ELSE title END,
            image = COALESCE(image, ?4), author = COALESCE(author, ?5), podcast_guid = COALESCE(podcast_guid, ?6),
            next_crawl_at = ?7
         WHERE id = ?1",
    )
    .bind(id)
    .bind(if taken { None } else { feed_url })
    .bind(nonempty(&f.title))
    .bind(clean_url(f.image().as_deref()))
    .bind(nonempty(&f.author))
    .bind(nonempty(&f.podcast_guid))
    .bind(crate::db::now())
    .execute(db)
    .await?;
    Ok(())
}

pub async fn due_for_crawl(db: &Db, limit: i64) -> AppResult<Vec<CrawlTarget>> {
    Ok(sqlx::query_as(
        "SELECT id, feed_url, etag, last_modified FROM podcasts
         WHERE feed_url IS NOT NULL AND (next_crawl_at IS NULL OR next_crawl_at <= ?)
         ORDER BY next_crawl_at IS NOT NULL, next_crawl_at LIMIT ?",
    )
    .bind(crate::db::now())
    .bind(limit)
    .fetch_all(db)
    .await?)
}

/// Episodes newest first.
pub async fn episodes(db: &Db, podcast_id: i64, limit: i64, offset: i64) -> AppResult<Vec<Episode>> {
    let sql = format!(
        "SELECT {EPISODE_COLS} FROM episodes e WHERE e.podcast_id = ? ORDER BY e.pub_date DESC, e.id DESC LIMIT ? OFFSET ?"
    );
    Ok(sqlx::query_as::<_, Episode>(sqlx::AssertSqlSafe(sql)).bind(podcast_id).bind(limit).bind(offset).fetch_all(db).await?)
}

pub async fn episode_count(db: &Db, podcast_id: i64) -> AppResult<i64> {
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM episodes WHERE podcast_id = ?").bind(podcast_id).fetch_one(db).await?)
}

pub async fn episode(db: &Db, id: i64) -> AppResult<Option<Episode>> {
    let sql = format!("SELECT {EPISODE_COLS} FROM episodes e WHERE e.id = ?");
    Ok(sqlx::query_as::<_, Episode>(sqlx::AssertSqlSafe(sql)).bind(id).fetch_optional(db).await?)
}

/// Find an episode of a podcast by GUID, then by enclosure URL.
pub async fn find_episode(db: &Db, podcast_id: i64, guid: Option<&str>, enclosure_url: Option<&str>) -> AppResult<Option<Episode>> {
    if let Some(g) = guid.filter(|g| !g.is_empty()) {
        let sql = format!("SELECT {EPISODE_COLS} FROM episodes e WHERE e.podcast_id = ? AND e.guid = ?");
        if let Some(e) = sqlx::query_as::<_, Episode>(sqlx::AssertSqlSafe(sql)).bind(podcast_id).bind(g).fetch_optional(db).await? {
            return Ok(Some(e));
        }
    }
    if let Some(u) = enclosure_url.filter(|u| !u.is_empty()) {
        let sql = format!("SELECT {EPISODE_COLS} FROM episodes e WHERE e.podcast_id = ? AND e.enclosure_url = ?");
        return Ok(sqlx::query_as::<_, Episode>(sqlx::AssertSqlSafe(sql)).bind(podcast_id).bind(u).fetch_optional(db).await?);
    }
    Ok(None)
}

/// Create an episode a contributor described (not, or not yet, in our crawl).
pub async fn insert_episode(
    conn: &mut SqliteConnection,
    podcast_id: i64,
    guid: Option<&str>,
    enclosure_url: Option<&str>,
    title: &str,
    pub_date: Option<&str>,
) -> AppResult<i64> {
    Ok(sqlx::query_scalar(
        "INSERT INTO episodes (podcast_id, guid, enclosure_url, title, pub_date) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(podcast_id, guid) WHERE guid IS NOT NULL DO UPDATE SET guid = excluded.guid
         RETURNING id",
    )
    .bind(podcast_id)
    .bind(guid.filter(|g| !g.is_empty()))
    .bind(enclosure_url.filter(|u| !u.is_empty()))
    .bind(title)
    .bind(pub_date)
    .fetch_one(&mut *conn)
    .await?)
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct PopularPodcast {
    pub id: i64,
    pub podcastindex_id: Option<i64>,
    pub title: String,
    pub image: Option<String>,
    pub description: Option<String>,
    pub people_count: i64,
}

/// Podcasts with the most people credited.
pub async fn popular(db: &Db, limit: i64) -> AppResult<Vec<PopularPodcast>> {
    Ok(sqlx::query_as(
        "SELECT pc.id, pc.podcastindex_id, pc.title, pc.image, pc.description,
            COUNT(DISTINCT c.person_id) AS people_count
         FROM podcasts pc JOIN credits c ON c.podcast_id = pc.id AND c.hidden = 0
         GROUP BY pc.id ORDER BY people_count DESC, pc.title LIMIT ?",
    )
    .bind(limit)
    .fetch_all(db)
    .await?)
}

/// Local podcast title search (complements the Podcast Index search for non-indexed shows).
pub async fn search(db: &Db, query: &str, limit: i64) -> AppResult<Vec<PopularPodcast>> {
    let like = format!("%{}%", query.trim().replace('%', "").replace('_', ""));
    Ok(sqlx::query_as(
        "SELECT pc.id, pc.podcastindex_id, pc.title, pc.image, pc.description,
            (SELECT COUNT(DISTINCT person_id) FROM credits WHERE podcast_id = pc.id AND hidden = 0) AS people_count
         FROM podcasts pc WHERE pc.title LIKE ? ORDER BY people_count DESC, pc.title LIMIT ?",
    )
    .bind(like)
    .bind(limit)
    .fetch_all(db)
    .await?)
}

/// Names the feed hints at but nobody has credited yet: `itunes:author` and the owner name, split
/// into individual names. Shown as one-tap "Is this a host?" confirmations.
pub async fn suggestions(db: &Db, podcast: &Podcast) -> AppResult<Vec<String>> {
    let credited: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT p.name_normalized FROM credits c JOIN people p ON p.id = c.person_id WHERE c.podcast_id = ? AND c.hidden = 0",
    )
    .bind(podcast.id)
    .fetch_all(db)
    .await?;
    let title_norm = normalize_name(&podcast.title);
    let mut out: Vec<String> = Vec::new();
    for source in [podcast.author.as_deref(), podcast.owner_name.as_deref()].into_iter().flatten() {
        for name in split_names(source) {
            let norm = normalize_name(&name);
            // Skip company-ish authors ("NPR", "Wondery", the show title itself) and one-word handles.
            if norm.split(' ').count() < 2
                || norm == title_norm
                || looks_like_org(&norm)
                || credited.contains(&norm)
                || out.iter().any(|n| normalize_name(n) == norm)
            {
                continue;
            }
            out.push(name);
        }
    }
    Ok(out.into_iter().take(5).collect())
}

fn looks_like_org(norm: &str) -> bool {
    const ORG_WORDS: &[&str] = &[
        "podcast", "podcasts", "media", "network", "radio", "studios", "studio", "productions", "llc", "inc",
        "news", "show", "audio", "entertainment", "company", "group", "the", "fm", "tv", "channel",
    ];
    norm.split(' ').any(|w| ORG_WORDS.contains(&w))
}
