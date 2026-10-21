pub mod legacy;
pub mod v2;

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;

use crate::error::AppError;

/// The submitting client's IP, honoring the usual reverse-proxy headers.
pub struct ClientIp(pub String);

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let h = |name: &str| parts.headers.get(name).and_then(|v| v.to_str().ok()).map(str::trim).filter(|v| !v.is_empty());
        let ip = h("cf-connecting-ip")
            .or_else(|| h("x-real-ip"))
            .or_else(|| h("x-forwarded-for").and_then(|v| v.split(',').next()).map(str::trim))
            .map(str::to_string)
            .or_else(|| parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip().to_string()))
            .unwrap_or_else(|| "unknown".into());
        Ok(ClientIp(ip))
    }
}

/// "pinepods" when a PinePods server forwards a submission (it sends `X-PodPeople-Client`).
pub fn client_kind(parts_headers: &axum::http::HeaderMap) -> &'static str {
    match parts_headers.get("x-podpeople-client").and_then(|v| v.to_str().ok()) {
        Some(v) if v.to_ascii_lowercase().starts_with("pinepods") => "pinepods",
        Some(_) => "api",
        None => "web",
    }
}

pub fn clamp_limit(v: Option<i64>, default: i64, max: i64) -> i64 {
    v.unwrap_or(default).clamp(1, max)
}
