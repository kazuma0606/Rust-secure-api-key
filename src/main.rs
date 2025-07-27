use axum::{
    routing::post,
    Router,
    http::StatusCode,
    response::Json,
    extract::State,
};
use serde_json::json;
use std::sync::Arc;
use secure_api_key::{
    database::Database,
    security::{ApiKeyService, TokenService},
    models::{CreateUserRequest, CreateApiKeyRequest, ValidateTokenRequest},
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

    // Create shared state
    let state = Arc::new((db, api_key_service, token_service));

    // Create router
    let app = Router::new()
        .route("/users", post(create_user))
        .route("/api-keys", post(create_api_key))
        .route("/validate", post(validate_api_key))
        .route("/tokens/validate", post(validate_token))
        .route("/protected", post(protected_endpoint))
        .with_state(state);

    // Start server
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::info!("Starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn create_user(
    State(state): State<Arc<(Database, ApiKeyService, TokenService)>>,
    Json(payload): Json<CreateUserRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let (db, _, _) = &*state;
    
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
    State(state): State<Arc<(Database, ApiKeyService, TokenService)>>,
    Json(payload): Json<CreateApiKeyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let (db, api_key_service, token_service) = &*state;
    
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
        payload.expires_at,
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Generate access token
    let access_token = token_service.generate_access_token(
        payload.user_id,
        key_id,
        payload.scopes,
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let response = json!({
        "api_key": api_key,
        "access_token": access_token,
        "expires_at": chrono::Utc::now() + chrono::Duration::hours(1)
    });
    
    Ok(Json(response))
}

async fn validate_api_key(
    State(state): State<Arc<(Database, ApiKeyService, TokenService)>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let (db, api_key_service, token_service) = &*state;
    
    let api_key = payload["api_key"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "API key is required".to_string()))?;
    
    // Validate API key
    let api_key_data = api_key_service.validate_api_key(api_key)
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;
    
    // Get user
    let user = db.get_user(api_key_data.user_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Generate new access token
    let access_token = token_service.generate_access_token(
        user.id,
        api_key_data.id,
        api_key_data.scopes,
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let response = json!({
        "api_key": api_key,
        "access_token": access_token,
        "expires_at": chrono::Utc::now() + chrono::Duration::hours(1)
    });
    
    Ok(Json(response))
}

async fn validate_token(
    State(state): State<Arc<(Database, ApiKeyService, TokenService)>>,
    Json(payload): Json<ValidateTokenRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let (_, _, token_service) = &*state;
    
    let claims = token_service.validate_access_token(&payload.token)
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;
    
    let response = json!({
        "valid": true,
        "user_id": claims.sub.parse::<i64>().unwrap_or(0),
        "scopes": claims.scopes
    });
    
    Ok(Json(response))
}

async fn protected_endpoint(
    State(state): State<Arc<(Database, ApiKeyService, TokenService)>>,
    Json(payload): Json<ValidateTokenRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let (_, _, token_service) = &*state;
    
    let claims = token_service.validate_access_token(&payload.token)
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;
    
    // Check if user has required scope
    if !claims.scopes.contains(&"read:data".to_string()) {
        return Err((StatusCode::FORBIDDEN, "Insufficient permissions".to_string()));
    }
    
    let response = json!({
        "success": true,
        "message": "Access granted to protected endpoint",
        "user_id": claims.sub,
        "scopes": claims.scopes
    });
    
    Ok(Json(response))
}
