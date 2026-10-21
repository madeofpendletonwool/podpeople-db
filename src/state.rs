use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use crate::config::Config;
use crate::db::Db;
use crate::index::PodcastIndex;
use crate::net::Http;
use crate::notify::Notifier;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub config: Arc<Config>,
    pub http: Http,
    pub index: PodcastIndex,
    pub notify: Notifier,
    crawling: Arc<Mutex<HashSet<i64>>>,
}

/// Held while a podcast is being crawled.
pub struct CrawlGuard {
    id: i64,
    set: Arc<Mutex<HashSet<i64>>>,
}

impl Drop for CrawlGuard {
    fn drop(&mut self) {
        self.set.lock().unwrap().remove(&self.id);
    }
}

impl AppState {
    pub fn new(db: Db, config: Config) -> Self {
        let http = Http::new(config.allow_private_urls);
        let index = PodcastIndex::new(http.clone(), config.search_api_url.clone());
        let notify = Notifier::new(http.clone(), &config);
        AppState { db, config: Arc::new(config), http, index, notify, crawling: Default::default() }
    }

    /// `None` when the podcast is already being crawled.
    pub fn crawl_lock(&self, id: i64) -> Option<CrawlGuard> {
        let mut set = self.crawling.lock().unwrap();
        set.insert(id).then(|| CrawlGuard { id, set: self.crawling.clone() })
    }

    /// Salted hash of a client IP; raw IPs are never stored.
    pub fn hash_ip(&self, ip: &str) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(format!("{}:{}", self.config.ip_hash_salt, ip).as_bytes());
        hex::encode(&digest[..12])
    }
}
