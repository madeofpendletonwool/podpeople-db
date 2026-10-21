use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    BadRequest(String),
    #[error("not found")]
    NotFound,
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("too many requests, slow down")]
    TooManyRequests,
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error("{0}")]
    Internal(String),
}

impl AppError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        AppError::BadRequest(msg.into())
    }

    pub fn status(&self) -> StatusCode {
        match self {
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::Forbidden => StatusCode::FORBIDDEN,
            AppError::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            AppError::Upstream(_) => StatusCode::BAD_GATEWAY,
            AppError::Db(sqlx::Error::RowNotFound) => StatusCode::NOT_FOUND,
            AppError::Db(_) | AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Message safe to show a client. Database and internal errors are logged, not echoed.
    pub fn public_message(&self) -> String {
        match self {
            AppError::Db(sqlx::Error::RowNotFound) => "not found".into(),
            AppError::Db(_) | AppError::Internal(_) => "internal error".into(),
            other => other.to_string(),
        }
    }

    fn log(&self) {
        if self.status().is_server_error() {
            tracing::error!("{self}");
        }
    }
}

/// JSON error body: `{"error": "..."}`. HTML pages convert errors themselves (see web::page_error).
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        self.log();
        (self.status(), Json(serde_json::json!({ "error": self.public_message() }))).into_response()
    }
}

impl From<reqwest::Error> for AppError {
    fn from(e: reqwest::Error) -> Self {
        AppError::Upstream(e.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::Internal(e.to_string())
    }
}
