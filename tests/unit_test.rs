use std::fs;
use std::path::Path;
use secure_api_key::{
    database::Database,
    security::TokenService,
};

#[tokio::test]
async fn test_database_user_operations() {
    println!("🧪 Testing database user operations...");
    
    let test_db_dir = "tests/test_db";
    if !Path::new(test_db_dir).exists() {
        fs::create_dir_all(test_db_dir).expect("Failed to create test_db directory");
    }
    
    let db_path = format!("{}/test_user_ops.sqlite", test_db_dir);
    let _ = fs::remove_file(&db_path);
    
    let db = Database::new(&db_path).expect("Failed to create test database");
    
    // ユーザー作成テスト
    let user_id = db.create_user("testuser_unit_ops", "testuser_unit_ops@example.com")
        .expect("Failed to create user");
    assert!(user_id > 0);
    
    // ユーザー取得テスト
    let user = db.get_user(user_id).expect("Failed to get user");
    assert_eq!(user.username, "testuser_unit_ops");
    assert_eq!(user.email, "testuser_unit_ops@example.com");
    
    println!("✅ Database user operations test passed");
}

#[tokio::test]
async fn test_database_api_key_operations() {
    println!("🧪 Testing database API key operations...");
    
    let test_db_dir = "tests/test_db";
    if !Path::new(test_db_dir).exists() {
        fs::create_dir_all(test_db_dir).expect("Failed to create test_db directory");
    }
    
    let db_path = format!("{}/test_api_key_ops.sqlite", test_db_dir);
    let _ = fs::remove_file(&db_path);
    
    let db = Database::new(&db_path).expect("Failed to create test database");
    
    // ユーザー作成
    let user_id = db.create_user("api_key_user", "api_key_user@example.com")
        .expect("Failed to create user");
    
    // APIキー作成テスト
    let api_key_id = db.create_api_key(
        user_id,
        "test_api_key_ops_hash",
        "test",
        "dev",
        1,
        &[String::from("read"), String::from("write")],
        None,
    ).expect("Failed to create API key");
    assert!(api_key_id > 0);
    
    // APIキー取得テスト
    let api_key = db.get_api_key_by_hash("test_api_key_ops_hash").expect("Failed to get API key");
    assert_eq!(api_key.key_hash, "test_api_key_ops_hash");
    assert_eq!(api_key.user_id, user_id);
    
    println!("✅ Database API key operations test passed");
}

#[tokio::test]
async fn test_token_generation_and_validation() {
    println!("🧪 Testing token generation and validation...");
    
    let test_db_dir = "tests/test_db";
    if !Path::new(test_db_dir).exists() {
        fs::create_dir_all(test_db_dir).expect("Failed to create test_db directory");
    }
    
    let db_path = format!("{}/test_token_gen_val.sqlite", test_db_dir);
    let _ = fs::remove_file(&db_path);
    
    let db = Database::new(&db_path).expect("Failed to create test database");
    
    // ユーザーとAPIキーを作成
    let user_id = db.create_user("gen_val_user_unit", "gen_val_user_unit@example.com")
        .expect("Failed to create user");
    
    let api_key_id = db.create_api_key(
        user_id,
        "test_gen_val_unit_hash",
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
    
    assert!(!token.is_empty());
    
    // トークン検証
    let validation_result = token_service.validate_access_token(&token);
    assert!(validation_result.is_ok());
    
    let claims = validation_result.unwrap();
    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.api_key_id, api_key_id);
    
    println!("✅ Token generation and validation test passed");
} 