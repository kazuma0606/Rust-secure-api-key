use std::fs;
use std::path::Path;
use secure_api_key::{
    database::Database,
    security::{ApiKeyService, TokenService},
};

#[tokio::test]
async fn test_database_operations() {
    println!("🧪 Testing database operations...");
    
    // test_dbディレクトリが存在しない場合は作成
    let test_db_dir = "tests/test_db";
    if !Path::new(test_db_dir).exists() {
        fs::create_dir_all(test_db_dir).expect("Failed to create test_db directory");
    }
    
    let db_path = format!("{}/test_db_ops.sqlite", test_db_dir);
    let _ = fs::remove_file(&db_path);
    
    let db = Database::new(&db_path).expect("Failed to create test database");
    
    // ユーザー作成テスト
    let user_id = db.create_user("testuser_db_ops", "testuser_db_ops@example.com")
        .expect("Failed to create user");
    assert!(user_id > 0);
    
    // ユーザー取得テスト
    let user = db.get_user(user_id).expect("Failed to get user");
    assert_eq!(user.username, "testuser_db_ops");
    assert_eq!(user.email, "testuser_db_ops@example.com");
    
    // APIキー作成テスト
    let api_key_id = db.create_api_key(
        user_id,
        "test_db_ops_hash",
        "test",
        "dev",
        1,
        &[String::from("read"), String::from("write")],
        None,
    ).expect("Failed to create API key");
    assert!(api_key_id > 0);
    
    // APIキー取得テスト
    let api_key = db.get_api_key_by_hash("test_db_ops_hash").expect("Failed to get API key");
    assert_eq!(api_key.key_hash, "test_db_ops_hash");
    assert_eq!(api_key.user_id, user_id);
    
    println!("✅ Database operations test passed");
}

#[tokio::test]
async fn test_token_generation() {
    println!("🧪 Testing token generation...");
    
    let test_db_dir = "tests/test_db";
    if !Path::new(test_db_dir).exists() {
        fs::create_dir_all(test_db_dir).expect("Failed to create test_db directory");
    }
    
    let db_path = format!("{}/test_token_gen.sqlite", test_db_dir);
    let _ = fs::remove_file(&db_path);
    
    let db = Database::new(&db_path).expect("Failed to create test database");
    
    // ユーザーとAPIキーを作成
    let user_id = db.create_user("token_user_gen", "token_user_gen@example.com")
        .expect("Failed to create user");
    
    let api_key_id = db.create_api_key(
        user_id,
        "test_token_gen_hash",
        "test",
        "dev",
        1,
        &[String::from("read"), String::from("write")],
        None,
    ).expect("Failed to create API key");
    
    let token_service = TokenService::new(db.clone(), "test_secret_key".to_string());
    
    // トークン生成テスト
    let token = token_service.generate_access_token(user_id, api_key_id, vec!["read".to_string(), "write".to_string()])
        .expect("Failed to generate token");
    
    assert!(!token.is_empty());
    
    println!("✅ Token generation test passed");
}

#[tokio::test]
async fn test_token_validation() {
    println!("🧪 Testing token validation...");
    
    let test_db_dir = "tests/test_db";
    if !Path::new(test_db_dir).exists() {
        fs::create_dir_all(test_db_dir).expect("Failed to create test_db directory");
    }
    
    let db_path = format!("{}/test_token_val.sqlite", test_db_dir);
    let _ = fs::remove_file(&db_path);
    
    let db = Database::new(&db_path).expect("Failed to create test database");
    
    // ユーザーとAPIキーを作成
    let user_id = db.create_user("token_user_val", "token_user_val@example.com")
        .expect("Failed to create user");
    
    let api_key_id = db.create_api_key(
        user_id,
        "test_token_val_hash",
        "test",
        "dev",
        1,
        &[String::from("read"), String::from("write")],
        None,
    ).expect("Failed to create API key");
    
    let token_service = TokenService::new(db.clone(), "test_secret_key".to_string());
    
    // トークン生成
    let token = token_service.generate_access_token(user_id, api_key_id, vec!["read".to_string(), "write".to_string()])
        .expect("Failed to generate token");
    
    // トークン検証テスト
    let validation_result = token_service.validate_access_token(&token);
    assert!(validation_result.is_ok());
    
    let claims = validation_result.unwrap();
    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.api_key_id, api_key_id);
    
    println!("✅ Token validation test passed");
}

#[tokio::test]
async fn test_full_workflow() {
    println!("🧪 Testing full workflow...");
    
    let test_db_dir = "tests/test_db";
    if !Path::new(test_db_dir).exists() {
        fs::create_dir_all(test_db_dir).expect("Failed to create test_db directory");
    }
    
    let db_path = format!("{}/test_full_workflow.sqlite", test_db_dir);
    let _ = fs::remove_file(&db_path);
    
    let db = Database::new(&db_path).expect("Failed to create test database");
    
    // 1. ユーザー作成
    let user_id = db.create_user("workflow_user", "workflow_user@example.com")
        .expect("Failed to create user");
    
    // 2. APIキーサービス初期化
    let api_key_service = ApiKeyService::new(
        db.clone(),
        "test".to_string(),
        "dev".to_string(),
        "test_secret_key".to_string(),
    );
    
    // 3. テスト用APIキー生成
    let (test_api_key, key_hash) = api_key_service.generate_api_key()
        .expect("Failed to generate API key");
    
    println!("Generated API key: {}", test_api_key);
    println!("Generated key hash: {}", key_hash);
    
    // 4. 生成されたAPIキーをデータベースに保存
    let api_key_id = db.create_api_key(
        user_id,
        &key_hash,
        "test",
        "dev",
        1,
        &[String::from("read"), String::from("write")],
        None,
    ).expect("Failed to create API key in database");
    
    // 5. APIキー検証
    let validation_result = api_key_service.validate_api_key(&test_api_key);
    match validation_result {
        Ok(api_key_data) => {
            println!("API key validation successful: id={}, user_id={}", api_key_data.id, api_key_data.user_id);
            assert!(api_key_data.id > 0);
            assert_eq!(api_key_data.user_id, user_id);
        }
        Err(e) => {
            println!("API key validation failed: {:?}", e);
            panic!("API key validation failed: {:?}", e);
        }
    }
    
    // 6. トークンサービス初期化
    let token_service = TokenService::new(db.clone(), "test_secret_key".to_string());
    
    // 7. アクセストークン生成
    let access_token = token_service.generate_access_token(user_id, api_key_id, vec!["read".to_string(), "write".to_string()])
        .expect("Failed to generate access token");
    
    // 8. アクセストークン検証
    let token_validation = token_service.validate_access_token(&access_token);
    assert!(token_validation.is_ok());
    
    let token_claims = token_validation.unwrap();
    assert_eq!(token_claims.sub, user_id.to_string());
    assert_eq!(token_claims.api_key_id, api_key_id);
    
    println!("✅ Full workflow test passed");
} 