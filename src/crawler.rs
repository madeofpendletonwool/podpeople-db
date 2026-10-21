//! Feed crawling: resolve a podcast from whatever an integration knows about it, fetch its feed,
//! and store its episodes and `<podcast:person>` credits.

use std::time::Duration;

use futures::StreamExt;

use crate::error::{AppError, AppResult};
use crate::net::Fetched;
use crate::state::AppState;
use crate::store::podcasts::{self, IngestStats};
use crate::store::Podcast;

/// How a caller identifies a podcast.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct PodcastKey {
    #[serde(default, deserialize_with = "crate::normalize::de_opt_i64")]
    pub id: Option<i64>,
    #[serde(default, deserialize_with = "crate::normalize::de_opt_i64")]
    pub podcastindex_id: Option<i64>,
    pub feed_url: Option<String>,
    pub guid: Option<String>,
}

impl PodcastKey {
    pub fn is_empty(&self) -> bool {
        self.id.is_none()
            && self.podcastindex_id.filter(|i| *i > 0).is_none()
            && self.feed_url.as_deref().is_none_or(|u| u.trim().is_empty())
            && self.guid.as_deref().is_none_or(|g| g.trim().is_empty())
    }
}

/// Find a podcast we already know, without any network access.
pub async fn find(state: &AppState, key: &PodcastKey) -> AppResult<Option<Podcast>> {
    if let Some(id) = key.id {
        return podcasts::get(&state.db, id).await;
    }
    if let Some(pi) = key.podcastindex_id.filter(|i| *i > 0) {
        if let Some(p) = podcasts::by_index_id(&state.db, pi).await? {
            return Ok(Some(p));
        }
    }
    if let Some(url) = key.feed_url.as_deref().and_then(crate::normalize::normalize_feed_url) {
        if let Some(p) = podcasts::by_feed_url(&state.db, &url).await? {
            return Ok(Some(p));
        }
    }
    if let Some(guid) = key.guid.as_deref().filter(|g| !g.trim().is_empty()) {
        if let Some(p) = podcasts::by_guid(&state.db, guid.trim()).await? {
            return Ok(Some(p));
        }
    }
    Ok(None)
}

/// Find a podcast, adding it (from the Podcast Index or straight from its feed) if it's new.
/// A newly added podcast is crawled before returning, so its people are there on first view.
pub async fn find_or_add(state: &AppState, key: &PodcastKey) -> AppResult<Option<Podcast>> {
    if let Some(p) = find(state, key).await? {
        return Ok(Some(p));
    }
    let new_id = if let Some(pi) = key.podcastindex_id.filter(|i| *i > 0) {
        match state.index.podcast_by_id(pi).await? {
            Some(feed) => Some(podcasts::upsert_from_index(&state.db, &feed).await?),
            None => None,
        }
    } else {
        None
    };
    let new_id = match (new_id, key.feed_url.as_deref().and_then(crate::normalize::normalize_feed_url)) {
        (Some(id), _) => id,
        (None, Some(url)) => {
            // Validate it's really a feed before storing anything.
            let parsed = match state.http.fetch_feed(&url, None, None).await? {
                Fetched::Body { bytes, .. } => crate::feed::parse(&bytes).map_err(AppError::bad_request)?,
                Fetched::NotModified => return Err(AppError::Upstream("unexpected 304".into())),
            };
            let id = podcasts::insert_by_feed_url(&state.db, &url, &parsed.title).await?;
            ingest(state, id, &parsed).await?;
            podcasts::record_crawl(&state.db, id, None, None, state.config.recrawl_hours).await?;
            return podcasts::get(&state.db, id).await;
        }
        (None, None) => return Ok(None),
    };
    // Bounded: a slow feed shouldn't hang the page. The background crawler retries.
    if tokio::time::timeout(Duration::from_secs(20), crawl(state, new_id)).await.is_err() {
        tracing::info!("initial crawl of podcast {new_id} is slow; continuing in the background");
        let st = state.clone();
        tokio::spawn(async move {
            let _ = crawl(&st, new_id).await;
        });
    }
    podcasts::get(&state.db, new_id).await
}

async fn ingest(state: &AppState, podcast_id: i64, parsed: &crate::feed::ParsedFeed) -> AppResult<IngestStats> {
    let mut tx = state.db.begin().await?;
    let stats = podcasts::ingest_feed(&mut tx, podcast_id, parsed).await?;
    tx.commit().await?;
    Ok(stats)
}

/// Fetch and ingest one podcast's feed. Concurrent crawls of the same podcast collapse into one.
pub async fn crawl(state: &AppState, podcast_id: i64) -> AppResult<Option<IngestStats>> {
    let Some(_guard) = state.crawl_lock(podcast_id) else {
        return Ok(None);
    };
    let Some(target) = podcasts::crawl_target(&state.db, podcast_id).await? else {
        return Ok(None);
    };
    let result: AppResult<Option<IngestStats>> = async {
        match state.http.fetch_feed(&target.feed_url, target.etag.as_deref(), target.last_modified.as_deref()).await? {
            Fetched::NotModified => {
                podcasts::record_crawl(&state.db, podcast_id, None, None, state.config.recrawl_hours).await?;
                Ok(None)
            }
            Fetched::Body { bytes, etag, last_modified, .. } => {
                let parsed = crate::feed::parse(&bytes).map_err(AppError::Upstream)?;
                let stats = ingest(state, podcast_id, &parsed).await?;
                podcasts::record_crawl(&state.db, podcast_id, etag.as_deref(), last_modified.as_deref(), state.config.recrawl_hours).await?;
                tracing::debug!("crawled podcast {podcast_id}: {stats:?}");
                Ok(Some(stats))
            }
        }
    }
    .await;
    if let Err(e) = &result {
        tracing::warn!("crawl of podcast {podcast_id} ({}) failed: {e}", target.feed_url);
        podcasts::record_crawl_failure(&state.db, podcast_id, &e.to_string()).await?;
    }
    result
}

/// Background loop: re-crawl podcasts as they come due.
pub async fn run(state: AppState) {
    let mut tick = tokio::time::interval(Duration::from_secs(300));
    loop {
        tick.tick().await;
        backfill_feed_urls(&state).await;
        let due = match podcasts::due_for_crawl(&state.db, 50).await {
            Ok(d) => d,
            Err(e) => {
                tracing::error!("crawler: listing due podcasts failed: {e}");
                continue;
            }
        };
        if due.is_empty() {
            continue;
        }
        tracing::info!("crawler: {} podcasts due", due.len());
        futures::stream::iter(due)
            .for_each_concurrent(4, |t| {
                let st = state.clone();
                async move {
                    let _ = crawl(&st, t.id).await;
                }
            })
            .await;
    }
}

/// Look up feed URLs for indexed podcasts that don't have one, so they can be crawled.
async fn backfill_feed_urls(state: &AppState) {
    let Ok(missing) = podcasts::missing_feed_urls(&state.db, 25).await else { return };
    for (id, index_id) in missing {
        let res = match state.index.podcast_by_id(index_id).await {
            Ok(Some(feed)) => podcasts::fill_from_index(&state.db, id, &feed).await,
            Ok(None) => podcasts::record_crawl_failure(&state.db, id, "not in the Podcast Index").await,
            Err(e) => {
                tracing::warn!("feed URL backfill for index id {index_id} failed: {e}");
                return;
            }
        };
        if let Err(e) = res {
            tracing::warn!("feed URL backfill for podcast {id} failed: {e}");
        }
    }
}
