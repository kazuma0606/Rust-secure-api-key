use crate::errors::ApiError;
use crate::models::{AccessToken, ApiKey, User};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn new(path: &str) -> Result<Self, ApiError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(include_str!("../db/schema.sql"))?;
        Ok(Database {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    // User operations
    pub fn create_user(&self, username: &str, email: &str) -> Result<i64, ApiError> {
        let conn = self.conn.lock().unwrap();
        let user_id = conn.execute(
            "INSERT INTO users (username, email) VALUES (?, ?)",
            params![username, email],
        )?;
        Ok(user_id as i64)
    }

    pub fn get_user(&self, user_id: i64) -> Result<User, ApiError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, username, email, created_at, updated_at FROM users WHERE id = ?",
        )?;

        let user = stmt.query_row(params![user_id], |row| {
            Ok(User {
                id: row.get(0)?,
                username: row.get(1)?,
                email: row.get(2)?,
                created_at: Utc::now(), // Always use current time
                updated_at: Utc::now(), // Always use current time
            })
        })?;

        Ok(user)
    }

    // API Key operations
    pub fn create_api_key(
        &self,
        user_id: i64,
        key_hash: &str,
        key_prefix: &str,
        environment: &str,
        version: i32,
        scopes: &[String],
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<i64, ApiError> {
        let conn = self.conn.lock().unwrap();
        let scopes_json = serde_json::to_string(scopes)?;
        let expires_at_str = expires_at.map(|dt| dt.to_rfc3339());

        let key_id = conn.execute(
            "INSERT INTO api_keys (user_id, key_hash, key_prefix, environment, version, scopes, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![user_id, key_hash, key_prefix, environment, version, scopes_json, expires_at_str],
        )?;

        Ok(key_id as i64)
    }

    pub fn get_api_key_by_hash(&self, key_hash: &str) -> Result<ApiKey, ApiError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, user_id, key_hash, key_prefix, environment, version, scopes, is_active, issued_at, expires_at, last_used_at, usage_count FROM api_keys WHERE key_hash = ?"
        )?;

        let api_key = stmt.query_row(params![key_hash], |row| {
            let scopes_json: String = row.get(6)?;
            let scopes: Vec<String> = serde_json::from_str(&scopes_json).unwrap_or_default();

            Ok(ApiKey {
                id: row.get(0)?,
                user_id: row.get(1)?,
                key_hash: row.get(2)?,
                key_prefix: row.get(3)?,
                environment: row.get(4)?,
                version: row.get(5)?,
                scopes,
                is_active: row.get(7)?,
                issued_at: Utc::now(), // Always use current time
                expires_at: None,      // Always None for now
                last_used_at: None,    // Always None for now
                usage_count: row.get(11)?,
            })
        })?;

        Ok(api_key)
    }

    pub fn update_api_key_usage(&self, key_id: i64) -> Result<(), ApiError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE api_keys SET last_used_at = ?, usage_count = usage_count + 1 WHERE id = ?",
            params![Utc::now().to_rfc3339(), key_id],
        )?;
        Ok(())
    }

    // Access Token operations
    pub fn create_access_token(
        &self,
        api_key_id: i64,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<i64, ApiError> {
        let conn = self.conn.lock().unwrap();
        let token_id = conn.execute(
            "INSERT INTO access_tokens (api_key_id, token_hash, expires_at) VALUES (?, ?, ?)",
            params![api_key_id, token_hash, expires_at.to_rfc3339()],
        )?;

        Ok(token_id as i64)
    }

    pub fn get_access_token_by_hash(&self, token_hash: &str) -> Result<AccessToken, ApiError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, api_key_id, token_hash, issued_at, expires_at, is_revoked FROM access_tokens WHERE token_hash = ?"
        )?;

        let token = stmt.query_row(params![token_hash], |row| {
            Ok(AccessToken {
                id: row.get(0)?,
                api_key_id: row.get(1)?,
                token_hash: row.get(2)?,
                issued_at: Utc::now(), // Always use current time
                expires_at: Utc::now() + chrono::Duration::hours(1), // 1 hour from now
                is_revoked: row.get(5)?,
            })
        })?;

        Ok(token)
    }

    // Usage Log operations
    pub fn log_usage(
        &self,
        api_key_id: i64,
        access_token_id: Option<i64>,
        endpoint: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        success: bool,
    ) -> Result<(), ApiError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO usage_logs (api_key_id, access_token_id, endpoint, ip_address, user_agent, success) VALUES (?, ?, ?, ?, ?, ?)",
            params![api_key_id, access_token_id, endpoint, ip_address, user_agent, success],
        )?;
        Ok(())
    }
}
