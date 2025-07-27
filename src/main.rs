use axum::{
    routing::post,
    Router,
    http::StatusCode,
    response::Json,
    extract::State,
    middleware,
};
use serde_json::json;
use std::sync::Arc;
use secure_api_key::{
    database::Database,
    security::{ApiKeyService, TokenService},
    models::{CreateUserRequest, CreateApiKeyRequest, ValidateTokenRequest},
    rate_limit::{RateLimitManager, rate_limit_middleware},
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load environment variables
    dotenv::dotenv().ok();

    // Initialize database
    let db = Database::new("db/api_keys.db")
        .expect("Failed to initialize database");

    // Initialize services
    let api_key_service = ApiKeyService::new(
        db.clone(),
        "myapp".to_string(),
        "dev".to_string(),
        std::env::var("JWT_SECRET").unwrap_or_else(|_| "your-secret-key".to_string()),
    );

    let token_service = TokenService::new(
        db.clone(),
        std::env::var("JWT_SECRET").unwrap_or_else(|_| "your-secret-key".to_string()),
    );

    // Initialize rate limit manager
    let rate_limit_manager = RateLimitManager::new();

    // Create shared state
    let state = Arc::new((db, api_key_service, token_service, rate_limit_manager));

    // Create router with rate limiting
    let app = Router::new()
        .route("/users", post(create_user))
        .route("/api-keys", post(create_api_key))
        .route("/validate", post(validate_api_key))
        .route("/tokens/validate", post(validate_token))
        .route("/protected", post(protected_endpoint))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .with_state(state);

    // Start server
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::info!("Starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn create_user(
    State(state): State<Arc<(Database, ApiKeyService, TokenService, RateLimitManager)>>,
    Json(payload): Json<CreateUserRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let (db, _, _, _) = &*state;
    
    match db.create_user(&payload.username, &payload.email) {
        Ok(user_id) => Ok(Json(json!({
            "success": true,
            "user_id": user_id,
            "message": "User created successfully"
        }))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

async fn create_api_key(
    State(state): State<Arc<(Database, ApiKeyService, TokenService, RateLimitManager)>>,
    Json(payload): Json<CreateApiKeyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let (db, api_key_service, token_service, _) = &*state;
    
    // Generate API key
    let (api_key, key_hash) = api_key_service.generate_api_key()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Store in database
    let key_id = db.create_api_key(
        payload.user_id,
        &key_hash,
        &api_key_service.prefix,
        &api_key_service.environment,
        api_key_service.version,
        &payload.scopes,
        None,
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Generate access token
    let access_token = token_service.generate_access_token(
        payload.user_id,
        key_id,
        payload.scopes,
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(json!({
        "success": true,
        "api_key": api_key,
        "access_token": access_token,
        "message": "API key created successfully"
    })))
}

async fn validate_api_key(
    State(state): State<Arc<(Database, ApiKeyService, TokenService, RateLimitManager)>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let (db, api_key_service, _, _) = &*state;
    
    let api_key = payload["api_key"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "API key is required".to_string()))?;

    match api_key_service.validate_api_key(api_key) {
        Ok(api_key_data) => {
            // Update usage count
            let _ = db.update_api_key_usage(api_key_data.id);
            
            Ok(Json(json!({
                "success": true,
                "valid": true,
                "api_key_data": {
                    "id": api_key_data.id,
                    "user_id": api_key_data.user_id,
                    "scopes": api_key_data.scopes,
                    "is_active": api_key_data.is_active
                },
                "message": "API key is valid"
            })))
        }
        Err(e) => Ok(Json(json!({
            "success": false,
            "valid": false,
            "error": e.to_string(),
            "message": "API key is invalid"
        }))),
    }
}

async fn validate_token(
    State(state): State<Arc<(Database, ApiKeyService, TokenService, RateLimitManager)>>,
    Json(payload): Json<ValidateTokenRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let (_, _, token_service, _) = &*state;
    
    match token_service.validate_access_token(&payload.token) {
        Ok(claims) => Ok(Json(json!({
            "success": true,
            "valid": true,
            "claims": {
                "user_id": claims.sub,
                "api_key_id": claims.api_key_id,
                "scopes": claims.scopes,
                "expires_at": claims.exp
            },
            "message": "Token is valid"
        }))),
        Err(e) => Ok(Json(json!({
            "success": false,
            "valid": false,
            "error": e.to_string(),
            "message": "Token is invalid"
        }))),
    }
}

async fn protected_endpoint(
    State(state): State<Arc<(Database, ApiKeyService, TokenService, RateLimitManager)>>,
    Json(payload): Json<ValidateTokenRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let (db, _, token_service, _) = &*state;
    
    // Validate token
    let claims = token_service.validate_access_token(&payload.token)
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;
    
    // Get user information
    let user_id = claims.sub.parse::<i64>()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid user ID".to_string()))?;
    
    let user = db.get_user(user_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(json!({
        "success": true,
        "message": "Access granted to protected endpoint",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email
        },
        "scopes": claims.scopes
    })))
}
