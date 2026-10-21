//! Podcast Index lookups, through the PinePods search API (which holds the Index credentials).

use serde::Deserialize;

use crate::error::{AppError, AppResult};
use crate::net::Http;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct IndexFeed {
    pub id: i64,
    pub title: String,
    pub url: String,
    pub original_url: String,
    pub link: String,
    pub description: String,
    pub author: String,
    pub owner_name: String,
    pub image: String,
    pub artwork: String,
    pub podcast_guid: String,
}

impl IndexFeed {
    pub fn image(&self) -> Option<String> {
        [&self.artwork, &self.image].into_iter().find(|s| !s.is_empty()).cloned()
    }
}

#[derive(Clone)]
pub struct PodcastIndex {
    http: Http,
    base: String,
}

impl PodcastIndex {
    pub fn new(http: Http, base: String) -> Self {
        PodcastIndex { http, base }
    }

    /// Look a podcast up by its Podcast Index feed id. `Ok(None)` when the index doesn't know it.
    pub async fn podcast_by_id(&self, id: i64) -> AppResult<Option<IndexFeed>> {
        #[derive(Deserialize)]
        struct Resp {
            #[serde(default)]
            feed: Option<serde_json::Value>,
        }
        let resp = self
            .http
            .client()
            .get(format!("{}/api/podcast", self.base))
            .query(&[("id", id.to_string())])
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(AppError::Upstream(format!("podcast index lookup returned HTTP {}", resp.status())));
        }
        let body: Resp = resp.json().await?;
        // The Index answers unknown ids with `"feed": []`.
        let Some(feed) = body.feed.filter(|f| f.is_object()) else { return Ok(None) };
        let feed: IndexFeed = serde_json::from_value(feed)?;
        Ok((feed.id > 0).then_some(feed))
    }

    pub async fn search_podcasts(&self, query: &str) -> AppResult<Vec<IndexFeed>> {
        #[derive(Deserialize)]
        struct Resp {
            #[serde(default)]
            feeds: Vec<IndexFeed>,
        }
        let resp = self
            .http
            .client()
            .get(format!("{}/api/search", self.base))
            .query(&[("query", query), ("index", "podcastindex")])
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(AppError::Upstream(format!("podcast search returned HTTP {}", resp.status())));
        }
        Ok(resp.json::<Resp>().await?.feeds)
    }
}
