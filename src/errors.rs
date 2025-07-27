use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Invalid API key format")]
    InvalidKeyFormat,

    #[error("Invalid checksum")]
    InvalidChecksum,

    #[error("API key not found")]
    KeyNotFound,

    #[error("API key expired")]
    KeyExpired,

    #[error("API key is inactive")]
    KeyInactive,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Token expired")]
    TokenExpired,

    #[error("User not found")]
    UserNotFound,

    #[error("User already exists")]
    UserExists,

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Internal server error")]
    Internal,
}

impl From<serde_json::Error> for ApiError {
    fn from(err: serde_json::Error) -> Self {
        ApiError::InvalidRequest(err.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for ApiError {
    fn from(_err: jsonwebtoken::errors::Error) -> Self {
        ApiError::InvalidToken
    }
}
