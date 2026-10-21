use std::path::PathBuf;

/// Runtime configuration, read once from the environment at startup.
#[derive(Clone, Debug)]
pub struct Config {
    pub port: u16,
    /// Public origin of this site, e.g. `https://podpeopledb.com`. Used for absolute links and to
    /// decide whether session cookies are `Secure`.
    pub base_url: String,
    /// SQLite file for the v2 schema.
    pub db_path: PathBuf,
    /// A v1 (Go) database to import on first boot when `db_path` doesn't exist yet. Defaults to the
    /// v1 location next to the v2 file; the v1 file is only ever read.
    pub v1_db_path: Option<PathBuf>,
    /// Admin created on first boot when no admin exists.
    pub admin_username: String,
    pub admin_password: String,
    /// PinePods search API (Podcast Index proxy), e.g. `https://search.pinepods.online`.
    pub search_api_url: String,
    pub ntfy_url: String,
    pub ntfy_topic: Option<String>,
    /// Max community submissions per IP per hour.
    pub submissions_per_hour: u32,
    /// How often a podcast's feed is re-crawled.
    pub recrawl_hours: i64,
    /// Turn off the background crawler (tests, read-only mirrors).
    pub crawler_enabled: bool,
    /// Allow fetching feeds from private/loopback addresses. Only for local testing.
    pub allow_private_urls: bool,
    /// Secret mixed into IP hashes so stored hashes can't be reversed with a rainbow table.
    pub ip_hash_salt: String,
}

fn env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        // v1 docker-compose examples quoted values (NTFY_URL="https://ntfy.sh").
        .map(|v| v.trim().trim_matches('"').trim_matches('\'').to_string())
        .filter(|v| !v.is_empty())
}

fn env_bool(key: &str, default: bool) -> bool {
    env(key)
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(default)
}

impl Config {
    pub fn from_env() -> Self {
        let db_path = PathBuf::from(
            env("DB_PATH").unwrap_or_else(|| "/app/podpeople-data/podpeople-v2.sqlite".into()),
        );
        let v1_db_path = env("V1_DB_PATH").map(PathBuf::from).or_else(|| {
            db_path.parent().map(|dir| dir.join("podpeopledb.sqlite"))
        });
        let admin_password = env("ADMIN_PASSWORD").unwrap_or_else(|| {
            tracing::warn!("ADMIN_PASSWORD is not set; the first-boot admin uses the default password 'admin'");
            "admin".into()
        });
        Config {
            port: env("PORT").and_then(|p| p.parse().ok()).unwrap_or(8085),
            base_url: env("BASE_URL")
                .unwrap_or_else(|| "http://localhost:8085".into())
                .trim_end_matches('/')
                .to_string(),
            db_path,
            v1_db_path,
            admin_username: env("ADMIN_USERNAME").unwrap_or_else(|| "admin".into()),
            admin_password,
            search_api_url: env("SEARCH_API_URL")
                .unwrap_or_else(|| "https://search.pinepods.online".into())
                .trim_end_matches('/')
                .to_string(),
            ntfy_url: env("NTFY_URL").unwrap_or_else(|| "https://ntfy.sh".into()),
            ntfy_topic: env("NTFY_TOPIC"),
            submissions_per_hour: env("SUBMISSIONS_PER_HOUR").and_then(|v| v.parse().ok()).unwrap_or(120),
            recrawl_hours: env("RECRAWL_HOURS").and_then(|v| v.parse().ok()).unwrap_or(24),
            crawler_enabled: env_bool("CRAWLER_ENABLED", true),
            allow_private_urls: env_bool("ALLOW_PRIVATE_URLS", false),
            ip_hash_salt: env("IP_HASH_SALT").unwrap_or_else(|| "podpeople".into()),
        }
    }

    pub fn secure_cookies(&self) -> bool {
        self.base_url.starts_with("https://")
    }

    /// Config for tests: in-memory-ish defaults, crawler off.
    pub fn for_tests(db_path: PathBuf) -> Self {
        Config {
            port: 0,
            base_url: "http://localhost".into(),
            db_path,
            v1_db_path: None,
            admin_username: "admin".into(),
            admin_password: "admin-password".into(),
            search_api_url: "http://127.0.0.1:9".into(),
            ntfy_url: "http://127.0.0.1:9".into(),
            ntfy_topic: None,
            submissions_per_hour: 1000,
            recrawl_hours: 24,
            crawler_enabled: false,
            allow_private_urls: true,
            ip_hash_salt: "test".into(),
        }
    }
}
