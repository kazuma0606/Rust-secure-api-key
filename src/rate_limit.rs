use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
    body::Body,
};
use serde::{Deserialize, Serialize};

// 型エイリアスを定義して循環参照を避ける
type AppState = Arc<(crate::database::Database, crate::security::ApiKeyService, crate::security::TokenService, RateLimitManager)>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_minute: u16,
    pub burst_limit: u16,
    pub window_size_seconds: u16,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 100,
            burst_limit: 20,
            window_size_seconds: 60,
        }
    }
}

impl RateLimitConfig {
    // 認証・認可系API用の設定
    pub fn auth() -> Self {
        Self {
            requests_per_minute: 5,
            burst_limit: 3,
            window_size_seconds: 60,
        }
    }

    // データ読み取り系API用の設定
    pub fn read() -> Self {
        Self {
            requests_per_minute: 200,
            burst_limit: 50,
            window_size_seconds: 60,
        }
    }

    // データ書き込み系API用の設定
    pub fn write() -> Self {
        Self {
            requests_per_minute: 50,
            burst_limit: 10,
            window_size_seconds: 60,
        }
    }

    // APIキー生成用の設定
    pub fn api_key_generation() -> Self {
        Self {
            requests_per_minute: 3,
            burst_limit: 1,
            window_size_seconds: 60,
        }
    }

    // バッチ処理系API用の設定
    pub fn batch() -> Self {
        Self {
            requests_per_minute: 2,
            burst_limit: 1,
            window_size_seconds: 60,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RateLimitEntry {
    pub requests: u16,
    pub window_start: Instant,
}

#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    entries: Arc<Mutex<HashMap<String, RateLimitEntry>>>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn with_default_config() -> Self {
        Self::new(RateLimitConfig::default())
    }

    pub fn check_rate_limit(&self, identifier: &str) -> Result<(), RateLimitError> {
        let mut entries = self.entries.lock().unwrap();
        let now = Instant::now();
        let window_duration = Duration::from_secs(self.config.window_size_seconds as u64);

        // 古いエントリをクリーンアップ
        entries.retain(|_, entry| {
            now.duration_since(entry.window_start) < window_duration
        });

        let entry = entries.entry(identifier.to_string()).or_insert_with(|| {
            RateLimitEntry {
                requests: 0,
                window_start: now,
            }
        });

        // ウィンドウがリセットされているかチェック
        if now.duration_since(entry.window_start) >= window_duration {
            entry.requests = 0;
            entry.window_start = now;
        }

        // バースト制限チェック（分間制限とは独立）
        if entry.requests >= self.config.burst_limit {
            return Err(RateLimitError::BurstLimitExceeded);
        }

        // レート制限チェック
        if entry.requests >= self.config.requests_per_minute {
            return Err(RateLimitError::LimitExceeded);
        }

        entry.requests += 1;
        Ok(())
    }

    pub fn get_remaining_requests(&self, identifier: &str) -> u16 {
        let entries = self.entries.lock().unwrap();
        let now = Instant::now();
        let window_duration = Duration::from_secs(self.config.window_size_seconds as u64);

        if let Some(entry) = entries.get(identifier) {
            if now.duration_since(entry.window_start) >= window_duration {
                return self.config.requests_per_minute;
            }
            
            // バースト制限と分間制限の両方を考慮
            let remaining_by_minute = self.config.requests_per_minute.saturating_sub(entry.requests);
            let remaining_by_burst = self.config.burst_limit.saturating_sub(entry.requests);
            
            // より厳しい制限を返す
            std::cmp::min(remaining_by_minute, remaining_by_burst)
        } else {
            // 新しいエントリの場合、バースト制限を返す
            self.config.burst_limit
        }
    }

    pub fn get_reset_time(&self, identifier: &str) -> Option<Duration> {
        let entries = self.entries.lock().unwrap();
        let now = Instant::now();
        let window_duration = Duration::from_secs(self.config.window_size_seconds as u64);

        if let Some(entry) = entries.get(identifier) {
            let elapsed = now.duration_since(entry.window_start);
            if elapsed < window_duration {
                Some(window_duration - elapsed)
            } else {
                None
            }
        } else {
            None
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("Rate limit exceeded")]
    LimitExceeded,
    #[error("Burst limit exceeded")]
    BurstLimitExceeded,
}

// レート制限ミドルウェア
pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    // クライアント識別子を取得（IPアドレスまたはAPIキー）
    let identifier = extract_client_identifier(&request);
    
    // パスに基づいてレート制限カテゴリを決定
    let category = determine_rate_limit_category(&request);
    let rate_limiter = state.3.get_limiter(&category);
    
    // レート制限チェック
    match rate_limiter.check_rate_limit(&identifier) {
        Ok(_) => {
            let response = next.run(request).await;
            Ok(response)
        }
        Err(RateLimitError::LimitExceeded) => {
            let remaining = rate_limiter.get_remaining_requests(&identifier);
            let reset_time = rate_limiter.get_reset_time(&identifier);
            
            let error_message = format!(
                "Rate limit exceeded for {} endpoint. Remaining requests: {}, Reset in: {:?}",
                category,
                remaining,
                reset_time.map(|d| format!("{}s", d.as_secs()))
            );
            
            Err((StatusCode::TOO_MANY_REQUESTS, error_message))
        }
        Err(RateLimitError::BurstLimitExceeded) => {
            Err((StatusCode::TOO_MANY_REQUESTS, format!("Burst limit exceeded for {} endpoint", category)))
        }
    }
}

// クライアント識別子を抽出する関数
fn extract_client_identifier(request: &Request<Body>) -> String {
    // まずAPIキーを確認
    if let Some(auth_header) = request.headers().get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                let token = &auth_str[7..];
                return format!("api_key:{}", token);
            }
        }
    }

    // APIキーがない場合はIPアドレスを使用
    if let Some(forwarded_for) = request.headers().get("X-Forwarded-For") {
        if let Ok(ip) = forwarded_for.to_str() {
            return format!("ip:{}", ip.split(',').next().unwrap_or(ip).trim());
        }
    }

    // デフォルトはリモートアドレス
    "unknown".to_string()
}

// パスに基づいてレート制限カテゴリを決定する関数
fn determine_rate_limit_category(request: &Request<Body>) -> String {
    let path = request.uri().path();
    
    match path {
        "/api-keys" => "api_key_gen".to_string(),
        "/users" => "write".to_string(),
        "/validate" => "auth".to_string(),
        "/tokens/validate" => "auth".to_string(),
        "/protected" => "read".to_string(),
        _ => "default".to_string(),
    }
}

// レート制限設定を管理する構造体
#[derive(Debug)]
pub struct RateLimitManager {
    limiters: HashMap<String, Arc<RateLimiter>>,
}

impl RateLimitManager {
    pub fn new() -> Self {
        let mut limiters = HashMap::new();
        
        // デフォルト設定
        limiters.insert("default".to_string(), Arc::new(RateLimiter::with_default_config()));
        
        // 認証系API
        limiters.insert("auth".to_string(), Arc::new(RateLimiter::new(RateLimitConfig::auth())));
        
        // 読み取り系API
        limiters.insert("read".to_string(), Arc::new(RateLimiter::new(RateLimitConfig::read())));
        
        // 書き込み系API
        limiters.insert("write".to_string(), Arc::new(RateLimiter::new(RateLimitConfig::write())));
        
        // APIキー生成
        limiters.insert("api_key_gen".to_string(), Arc::new(RateLimiter::new(RateLimitConfig::api_key_generation())));
        
        // バッチ処理
        limiters.insert("batch".to_string(), Arc::new(RateLimiter::new(RateLimitConfig::batch())));

        Self { limiters }
    }

    pub fn get_limiter(&self, category: &str) -> Arc<RateLimiter> {
        self.limiters.get(category)
            .cloned()
            .unwrap_or_else(|| self.limiters.get("default").unwrap().clone())
    }

    pub fn add_limiter(&mut self, category: String, config: RateLimitConfig) {
        self.limiters.insert(category, Arc::new(RateLimiter::new(config)));
    }
}

impl Default for RateLimitManager {
    fn default() -> Self {
        Self::new()
    }
} 