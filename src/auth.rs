//! Admin authentication: argon2id passwords, server-side sessions keyed by a hashed cookie token,
//! and a per-session CSRF token for every state-changing admin request.

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::Argon2;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{header, HeaderMap};
use rand::RngExt;
use sha2::{Digest, Sha256};

use crate::db::Db;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

pub const COOKIE: &str = "pp_session";
const SESSION_DAYS: i64 = 14;

pub fn hash_password(password: &str) -> AppResult<String> {
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| AppError::Internal(e.to_string()))
}

/// Verify against an argon2 PHC string or a v1 bcrypt hash.
pub fn verify_password(password: &str, stored: &str) -> bool {
    if stored.starts_with("$2") {
        return bcrypt::verify(password, stored).unwrap_or(false);
    }
    PasswordHash::new(stored)
        .map(|h| Argon2::default().verify_password(password.as_bytes(), &h).is_ok())
        .unwrap_or(false)
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Create the first admin from the environment when there is none.
pub async fn ensure_admin(db: &Db, username: &str, password: &str) -> AppResult<()> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM admins").fetch_one(db).await?;
    if count == 0 {
        sqlx::query("INSERT INTO admins (username, password_hash) VALUES (?, ?)")
            .bind(username)
            .bind(hash_password(password)?)
            .execute(db)
            .await?;
        tracing::info!("created admin user '{username}'");
    }
    Ok(())
}

/// Check credentials; on success returns the admin id. Upgrades bcrypt hashes to argon2.
pub async fn login(db: &Db, username: &str, password: &str) -> AppResult<Option<i64>> {
    let row: Option<(i64, String)> = sqlx::query_as("SELECT id, password_hash FROM admins WHERE username = ?")
        .bind(username.trim())
        .fetch_optional(db)
        .await?;
    let Some((id, stored)) = row else {
        // Spend comparable time on unknown users.
        let _ = verify_password(password, "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        return Ok(None);
    };
    if !verify_password(password, &stored) {
        return Ok(None);
    }
    if stored.starts_with("$2") {
        sqlx::query("UPDATE admins SET password_hash = ? WHERE id = ?")
            .bind(hash_password(password)?)
            .bind(id)
            .execute(db)
            .await?;
    }
    Ok(Some(id))
}

/// Start a session; returns the cookie token.
pub async fn create_session(db: &Db, admin_id: i64) -> AppResult<String> {
    let token = random_token();
    let expires = crate::db::fmt_ts(chrono::Utc::now() + chrono::Duration::days(SESSION_DAYS));
    sqlx::query("DELETE FROM sessions WHERE expires_at < ?").bind(crate::db::now()).execute(db).await?;
    sqlx::query("INSERT INTO sessions (token_hash, admin_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)")
        .bind(token_hash(&token))
        .bind(admin_id)
        .bind(random_token())
        .bind(expires)
        .execute(db)
        .await?;
    Ok(token)
}

pub async fn destroy_session(db: &Db, token: &str) -> AppResult<()> {
    sqlx::query("DELETE FROM sessions WHERE token_hash = ?").bind(token_hash(token)).execute(db).await?;
    Ok(())
}

pub fn session_cookie(token: &str, secure: bool) -> String {
    format!(
        "{COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{}",
        SESSION_DAYS * 86_400,
        if secure { "; Secure" } else { "" }
    )
}

pub fn clear_cookie(secure: bool) -> String {
    format!("{COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}", if secure { "; Secure" } else { "" })
}

pub fn cookie_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == COOKIE)
        .map(|(_, v)| v.to_string())
        .filter(|v| !v.is_empty())
}

/// A logged-in admin. Extracting it from a request fails with 401 when there's no valid session.
#[derive(Clone, Debug)]
pub struct Admin {
    pub id: i64,
    pub username: String,
    pub csrf: String,
}

impl Admin {
    /// Require the session's CSRF token (form field or `X-CSRF-Token` header).
    pub fn check_csrf(&self, provided: Option<&str>) -> AppResult<()> {
        match provided {
            Some(t) if constant_time_eq(t.as_bytes(), self.csrf.as_bytes()) => Ok(()),
            _ => Err(AppError::Forbidden),
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub async fn admin_from_headers(db: &Db, headers: &HeaderMap) -> AppResult<Option<Admin>> {
    let Some(token) = cookie_token(headers) else { return Ok(None) };
    let row: Option<(i64, String, String)> = sqlx::query_as(
        "SELECT a.id, a.username, s.csrf_token FROM sessions s JOIN admins a ON a.id = s.admin_id
         WHERE s.token_hash = ? AND s.expires_at > ?",
    )
    .bind(token_hash(&token))
    .bind(crate::db::now())
    .fetch_optional(db)
    .await?;
    Ok(row.map(|(id, username, csrf)| Admin { id, username, csrf }))
}

impl FromRequestParts<AppState> for Admin {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        admin_from_headers(&state.db, &parts.headers).await?.ok_or(AppError::Unauthorized)
    }
}

/// Optional admin (public pages show moderation shortcuts to logged-in admins).
pub struct MaybeAdmin(pub Option<Admin>);

impl FromRequestParts<AppState> for MaybeAdmin {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        Ok(MaybeAdmin(admin_from_headers(&state.db, &parts.headers).await?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_argon2_and_bcrypt() {
        let h = hash_password("hunter2").unwrap();
        assert!(verify_password("hunter2", &h));
        assert!(!verify_password("hunter3", &h));
        let b = bcrypt::hash("legacy", 4).unwrap();
        assert!(verify_password("legacy", &b));
        assert!(!verify_password("nope", &b));
    }
}
