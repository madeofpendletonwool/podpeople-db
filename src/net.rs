//! Outbound HTTP: one shared client plus an SSRF guard for URLs that come from users or feeds.

use std::net::IpAddr;
use std::time::Duration;

use futures::StreamExt;

use crate::error::{AppError, AppResult};

pub const USER_AGENT: &str = concat!("PodPeopleDB/", env!("CARGO_PKG_VERSION"), " (+https://podpeopledb.com)");

/// Feeds bigger than this are refused. The largest real-world feeds are ~20MB.
const MAX_FEED_BYTES: usize = 40 * 1024 * 1024;
const MAX_IMAGE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone)]
pub struct Http {
    client: reqwest::Client,
    allow_private: bool,
}

pub enum Fetched {
    NotModified,
    Body {
        bytes: bytes::Bytes,
        etag: Option<String>,
        last_modified: Option<String>,
        content_type: Option<String>,
    },
}

impl Http {
    pub fn new(allow_private: bool) -> Self {
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                if attempt.previous().len() >= 5 {
                    return attempt.error("too many redirects");
                }
                if !allow_private && is_obviously_private(attempt.url()) {
                    return attempt.error("redirect to a private address");
                }
                attempt.follow()
            }))
            .build()
            .expect("http client");
        Http { client, allow_private }
    }

    /// Plain client for trusted, configured endpoints (the search API, ntfy).
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Reject URLs that resolve to loopback, private, link-local or otherwise internal addresses.
    pub async fn ensure_public(&self, raw: &str) -> AppResult<url::Url> {
        let url = url::Url::parse(raw).map_err(|_| AppError::bad_request("invalid URL"))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(AppError::bad_request("only http(s) URLs are allowed"));
        }
        if self.allow_private {
            return Ok(url);
        }
        let host = url.host_str().ok_or_else(|| AppError::bad_request("URL has no host"))?;
        let port = url.port_or_known_default().unwrap_or(80);
        let addrs = tokio::net::lookup_host((host, port))
            .await
            .map_err(|_| AppError::bad_request("could not resolve host"))?;
        for addr in addrs {
            if !is_public_ip(addr.ip()) {
                return Err(AppError::bad_request("URL points at a private address"));
            }
        }
        Ok(url)
    }

    /// Fetch a feed with conditional-GET validators and a size cap.
    pub async fn fetch_feed(&self, url: &str, etag: Option<&str>, last_modified: Option<&str>) -> AppResult<Fetched> {
        let url = self.ensure_public(url).await?;
        let mut req = self
            .client
            .get(url)
            .header("Accept", "application/rss+xml, application/xml;q=0.9, text/xml;q=0.8, */*;q=0.5");
        if let Some(e) = etag {
            req = req.header("If-None-Match", e);
        }
        if let Some(lm) = last_modified {
            req = req.header("If-Modified-Since", lm);
        }
        let resp = req.send().await?;
        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(Fetched::NotModified);
        }
        if !resp.status().is_success() {
            return Err(AppError::Upstream(format!("feed returned HTTP {}", resp.status())));
        }
        let header = |name: &str| resp.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_string);
        let etag = header("etag");
        let last_modified = header("last-modified");
        let content_type = header("content-type");
        let bytes = read_capped(resp, MAX_FEED_BYTES).await?;
        Ok(Fetched::Body { bytes, etag, last_modified, content_type })
    }

    /// Fetch an image for the image proxy. Returns (bytes, content type).
    pub async fn fetch_image(&self, url: &str) -> AppResult<(bytes::Bytes, String)> {
        let url = self.ensure_public(url).await?;
        let resp = self.client.get(url).timeout(Duration::from_secs(15)).send().await?;
        if !resp.status().is_success() {
            return Err(AppError::NotFound);
        }
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        if !ct.starts_with("image/") || ct.contains("svg") {
            // SVG can carry script; everything we proxy is rendered as <img>, but don't risk it.
            return Err(AppError::bad_request("not an image"));
        }
        let bytes = read_capped(resp, MAX_IMAGE_BYTES).await?;
        Ok((bytes, ct))
    }
}

async fn read_capped(resp: reqwest::Response, max: usize) -> AppResult<bytes::Bytes> {
    if resp.content_length().is_some_and(|len| len as usize > max) {
        return Err(AppError::Upstream("response too large".into()));
    }
    let mut buf = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if buf.len() + chunk.len() > max {
            return Err(AppError::Upstream("response too large".into()));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf.into())
}

fn is_obviously_private(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => !is_public_ip(IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => !is_public_ip(IpAddr::V6(ip)),
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost") || d.ends_with(".localhost") || d.ends_with(".internal"),
        None => true,
    }
}

pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (64..=127).contains(&o[1])) // CGNAT
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // benchmarking
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(v4));
            }
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || (s[0] & 0xfe00) == 0xfc00 // unique local
                || (s[0] & 0xffc0) == 0xfe80) // link local
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_ips() {
        assert!(!is_public_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("10.1.2.3".parse().unwrap()));
        assert!(!is_public_ip("192.168.0.4".parse().unwrap()));
        assert!(!is_public_ip("169.254.169.254".parse().unwrap()));
        assert!(!is_public_ip("::1".parse().unwrap()));
        assert!(!is_public_ip("::ffff:10.0.0.1".parse().unwrap()));
        assert!(is_public_ip("1.1.1.1".parse().unwrap()));
        assert!(is_public_ip("2606:4700::1111".parse().unwrap()));
    }
}
