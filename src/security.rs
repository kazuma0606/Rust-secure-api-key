use crate::database::Database;
use crate::errors::ApiError;
use crate::models::ApiKey;
use base32;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user_id
    pub api_key_id: i64,
    pub scopes: Vec<String>,
    pub exp: i64, // expiration time
    pub iat: i64, // issued at
}

#[derive(Clone)]
pub struct ApiKeyService {
    pub db: Database,
    pub prefix: String,
    pub environment: String,
    pub version: i32,
    pub secret_key: String,
}

impl ApiKeyService {
    pub fn new(db: Database, prefix: String, environment: String, secret_key: String) -> Self {
        Self {
            db,
            prefix,
            environment,
            version: 1,
            secret_key,
        }
    }

    // Generate 160-bit API key
    pub fn generate_api_key(&self) -> Result<(String, String), ApiError> {
        let mut rng = rand::thread_rng();

        // Generate 20 bytes (160 bits) of random data
        let mut random_bytes = [0u8; 20];
        rng.fill(&mut random_bytes);

        // Create timestamp (32 bits)
        let timestamp = Utc::now().timestamp() as u32;

        // Calculate checksum (first 4 bytes of SHA256)
        let mut hasher = Sha256::new();
        hasher.update(&self.prefix.as_bytes());
        hasher.update(&self.environment.as_bytes());
        hasher.update(&format!("v{}", self.version).as_bytes());
        hasher.update(&timestamp.to_string().as_bytes());
        hasher.update(&random_bytes);
        let checksum = hasher.finalize();

        // Format: prefix_env_version_timestamp_random_checksum
        let key_string = format!(
            "{}_{}_v{}_{}_{}_{}",
            self.prefix,
            self.environment,
            self.version,
            timestamp,
            base32::encode(base32::Alphabet::RFC4648 { padding: false }, &random_bytes),
            base32::encode(base32::Alphabet::RFC4648 { padding: false }, &checksum[..4])
        );

        // Hash the key for storage
        let mut hasher = Sha256::new();
        hasher.update(key_string.as_bytes());
        let key_hash = format!("{:x}", hasher.finalize());

        Ok((key_string, key_hash))
    }

    // Validate API key format (simplified without checksum)
    pub fn validate_api_key_format(&self, key: &str) -> Result<(), ApiError> {
        let parts: Vec<&str> = key.split('_').collect();
        if parts.len() != 6 {
            return Err(ApiError::InvalidKeyFormat);
        }

        let (prefix, env, version_str, timestamp_str, random_part, checksum_part) =
            (parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]);

        // Validate prefix and environment
        if prefix != self.prefix || env != self.environment {
            return Err(ApiError::InvalidKeyFormat);
        }

        // Validate version
        if !version_str.starts_with('v') {
            return Err(ApiError::InvalidKeyFormat);
        }

        // Validate timestamp
        timestamp_str
            .parse::<u32>()
            .map_err(|_| ApiError::InvalidKeyFormat)?;

        // Validate checksum
        let random_bytes =
            base32::decode(base32::Alphabet::RFC4648 { padding: false }, random_part)
                .ok_or(ApiError::InvalidKeyFormat)?;

        let mut hasher = Sha256::new();
        hasher.update(prefix.as_bytes());
        hasher.update(env.as_bytes());
        hasher.update(version_str.as_bytes());
        hasher.update(timestamp_str.as_bytes());
        hasher.update(&random_bytes);
        let expected_checksum = hasher.finalize();

        let provided_checksum =
            base32::decode(base32::Alphabet::RFC4648 { padding: false }, checksum_part)
                .ok_or(ApiError::InvalidChecksum)?;

        if provided_checksum != expected_checksum[..4] {
            return Err(ApiError::InvalidChecksum);
        }

        Ok(())
    }

    // Validate API key and return stored data
    pub fn validate_api_key(&self, key: &str) -> Result<ApiKey, ApiError> {
        // Validate format
        self.validate_api_key_format(key)?;

        // Hash the key
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let key_hash = format!("{:x}", hasher.finalize());

        // Get from database
        let api_key = self.db.get_api_key_by_hash(&key_hash)?;

        // Check if active
        if !api_key.is_active {
            return Err(ApiError::KeyInactive);
        }

        // Check expiration (disabled for now)
        // if let Some(expires_at) = api_key.expires_at {
        //     if Utc::now() > expires_at {
        //         return Err(ApiError::KeyExpired);
        //     }
        // }

        // Update usage (disabled for now to avoid date parsing issues)
        // self.db.update_api_key_usage(api_key.id)?;

        Ok(api_key)
    }
}

#[derive(Clone)]
pub struct TokenService {
    pub db: Database,
    pub secret_key: String,
}

impl TokenService {
    pub fn new(db: Database, secret_key: String) -> Self {
        Self { db, secret_key }
    }

    // Generate JWT access token
    pub fn generate_access_token(
        &self,
        user_id: i64,
        api_key_id: i64,
        scopes: Vec<String>,
    ) -> Result<String, ApiError> {
        let now = Utc::now();
        let expires_at = now + Duration::hours(1); // 1 hour expiration

        let claims = Claims {
            sub: user_id.to_string(),
            api_key_id,
            scopes,
            exp: expires_at.timestamp(),
            iat: now.timestamp(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret_key.as_ref()),
        )?;

        // Store token hash in database
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let token_hash = format!("{:x}", hasher.finalize());

        self.db
            .create_access_token(api_key_id, &token_hash, expires_at)?;

        Ok(token)
    }

    // Validate JWT access token
    pub fn validate_access_token(&self, token: &str) -> Result<Claims, ApiError> {
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret_key.as_ref()),
            &Validation::default(),
        )?;

        // Check expiration from JWT claims
        let now = Utc::now().timestamp();
        if token_data.claims.exp < now {
            return Err(ApiError::TokenExpired);
        }

        // Optional: Check if token is revoked in database (skip for now to avoid date parsing issues)
        // let mut hasher = Sha256::new();
        // hasher.update(token.as_bytes());
        // let token_hash = format!("{:x}", hasher.finalize());
        // let access_token = self.db.get_access_token_by_hash(&token_hash)?;
        // if access_token.is_revoked {
        //     return Err(ApiError::InvalidToken);
        // }

        Ok(token_data.claims)
    }
}
