use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
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
    /// Failed admin logins per hashed IP: (count, window start).
    logins: Arc<Mutex<HashMap<String, (u32, Instant)>>>,
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
        AppState { db, config: Arc::new(config), http, index, notify, crawling: Default::default(), logins: Default::default() }
    }

    /// `None` when the podcast is already being crawled.
    pub fn crawl_lock(&self, id: i64) -> Option<CrawlGuard> {
        let mut set = self.crawling.lock().unwrap();
        set.insert(id).then(|| CrawlGuard { id, set: self.crawling.clone() })
    }

    /// Allow 10 login attempts per IP per 15 minutes. Counts every attempt; success resets.
    pub fn login_attempt_allowed(&self, key: &str) -> bool {
        let mut map = self.logins.lock().unwrap();
        let now = Instant::now();
        map.retain(|_, (_, start)| now.duration_since(*start) < Duration::from_secs(900));
        let entry = map.entry(key.to_string()).or_insert((0, now));
        entry.0 += 1;
        entry.0 <= 10
    }

    pub fn login_succeeded(&self, key: &str) {
        self.logins.lock().unwrap().remove(key);
    }

    /// Salted hash of a client IP; raw IPs are never stored.
    pub fn hash_ip(&self, ip: &str) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(format!("{}:{}", self.config.ip_hash_salt, ip).as_bytes());
        hex::encode(&digest[..12])
    }
}
