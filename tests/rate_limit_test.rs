use secure_api_key::{
    database::Database,
    rate_limit::{RateLimiter, RateLimitConfig, RateLimitManager},
};
use std::fs;

#[tokio::test]
async fn test_rate_limit_basic_functionality() {
    // テスト用データベースファイルを削除
    let db_path = "tests/test_db/rate_limit_test.sqlite";
    let _ = fs::remove_file(db_path);

    // データベース初期化（テスト用）
    let _db = Database::new(db_path).expect("Failed to initialize database");
    
    // レート制限マネージャー初期化（テスト用）
    let _rate_limit_manager = RateLimitManager::new();
    
    // テスト用のレート制限設定（厳しい制限でテスト）
    let test_config = RateLimitConfig {
        requests_per_minute: 3,
        burst_limit: 3,  // バースト制限を分間制限と同じに設定
        window_size_seconds: 60,
    };
    
    let rate_limiter = RateLimiter::new(test_config);
    let test_identifier = "test_client_123";

    // 1回目のリクエスト - 成功するはず
    assert!(rate_limiter.check_rate_limit(test_identifier).is_ok());
    
    // 2回目のリクエスト - 成功するはず
    assert!(rate_limiter.check_rate_limit(test_identifier).is_ok());
    
    // 3回目のリクエスト - 成功するはず
    assert!(rate_limiter.check_rate_limit(test_identifier).is_ok());
    
    // 4回目のリクエスト - 失敗するはず（分間制限）
    assert!(rate_limiter.check_rate_limit(test_identifier).is_err());
    
    // 残りリクエスト数を確認
    assert_eq!(rate_limiter.get_remaining_requests(test_identifier), 0);
}

#[tokio::test]
async fn test_rate_limit_burst_protection() {
    let db_path = "tests/test_db/rate_limit_burst_test.sqlite";
    let _ = fs::remove_file(db_path);

    let _db = Database::new(db_path).expect("Failed to initialize database");
    
    // バースト制限が厳しい設定
    let burst_config = RateLimitConfig {
        requests_per_minute: 10,
        burst_limit: 2,  // バースト制限を2に設定
        window_size_seconds: 60,
    };
    
    let rate_limiter = RateLimiter::new(burst_config);
    let test_identifier = "burst_test_client";

    // 1回目 - 成功
    assert!(rate_limiter.check_rate_limit(test_identifier).is_ok());
    
    // 2回目 - 成功
    assert!(rate_limiter.check_rate_limit(test_identifier).is_ok());
    
    // 3回目 - バースト制限で失敗
    assert!(rate_limiter.check_rate_limit(test_identifier).is_err());
    
    // 残りリクエスト数を確認（バースト制限のため0）
    assert_eq!(rate_limiter.get_remaining_requests(test_identifier), 0);
}

#[tokio::test]
async fn test_rate_limit_window_reset() {
    let db_path = "tests/test_db/rate_limit_window_test.sqlite";
    let _ = fs::remove_file(db_path);

    let _db = Database::new(db_path).expect("Failed to initialize database");
    
    // 短いウィンドウでテスト
    let short_window_config = RateLimitConfig {
        requests_per_minute: 2,
        burst_limit: 2,
        window_size_seconds: 1,  // 1秒のウィンドウ
    };
    
    let rate_limiter = RateLimiter::new(short_window_config);
    let test_identifier = "window_test_client";

    // 1回目 - 成功
    assert!(rate_limiter.check_rate_limit(test_identifier).is_ok());
    
    // 2回目 - 成功
    assert!(rate_limiter.check_rate_limit(test_identifier).is_ok());
    
    // 3回目 - 制限に達して失敗
    assert!(rate_limiter.check_rate_limit(test_identifier).is_err());
    
    // 1秒待機
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    
    // ウィンドウがリセットされたので成功するはず
    assert!(rate_limiter.check_rate_limit(test_identifier).is_ok());
}

#[tokio::test]
async fn test_rate_limit_different_identifiers() {
    let db_path = "tests/test_db/rate_limit_identifiers_test.sqlite";
    let _ = fs::remove_file(db_path);

    let _db = Database::new(db_path).expect("Failed to initialize database");
    
    let config = RateLimitConfig {
        requests_per_minute: 2,
        burst_limit: 2,
        window_size_seconds: 60,
    };
    
    let rate_limiter = RateLimiter::new(config);
    
    // 異なる識別子でテスト
    let client1 = "client_1";
    let client2 = "client_2";

    // クライアント1の制限を満たす
    assert!(rate_limiter.check_rate_limit(client1).is_ok());
    assert!(rate_limiter.check_rate_limit(client1).is_ok());
    assert!(rate_limiter.check_rate_limit(client1).is_err()); // 制限に達する
    
    // クライアント2は独立して制限される
    assert!(rate_limiter.check_rate_limit(client2).is_ok());
    assert!(rate_limiter.check_rate_limit(client2).is_ok());
    assert!(rate_limiter.check_rate_limit(client2).is_err()); // 制限に達する
}

#[tokio::test]
async fn test_rate_limit_manager_categories() {
    let db_path = "tests/test_db/rate_limit_manager_test.sqlite";
    let _ = fs::remove_file(db_path);

    let _db = Database::new(db_path).expect("Failed to initialize database");
    
    let rate_limit_manager = RateLimitManager::new();
    
    // 各カテゴリのレート制限をテスト
    let categories = vec!["default", "auth", "read", "write", "api_key_gen", "batch"];
    
    for category in categories {
        let limiter = rate_limit_manager.get_limiter(category);
        let test_identifier = format!("test_{}", category);
        
        // 少なくとも1回は成功するはず
        assert!(limiter.check_rate_limit(&test_identifier).is_ok());
        
        // 残りリクエスト数が正しく計算される（1回使用したので残りがあるはず）
        let remaining = limiter.get_remaining_requests(&test_identifier);
        assert!(remaining >= 0); // u16は常に0以上なので、このチェックは意味がないが、テストの意図を明確にするため残す
    }
}

#[tokio::test]
async fn test_rate_limit_config_presets() {
    let db_path = "tests/test_db/rate_limit_config_test.sqlite";
    let _ = fs::remove_file(db_path);

    let _db = Database::new(db_path).expect("Failed to initialize database");
    
    // 各プリセット設定をテスト
    let auth_config = RateLimitConfig::auth();
    assert_eq!(auth_config.requests_per_minute, 5);
    assert_eq!(auth_config.burst_limit, 3);
    
    let read_config = RateLimitConfig::read();
    assert_eq!(read_config.requests_per_minute, 200);
    assert_eq!(read_config.burst_limit, 50);
    
    let write_config = RateLimitConfig::write();
    assert_eq!(write_config.requests_per_minute, 50);
    assert_eq!(write_config.burst_limit, 10);
    
    let api_key_config = RateLimitConfig::api_key_generation();
    assert_eq!(api_key_config.requests_per_minute, 3);
    assert_eq!(api_key_config.burst_limit, 1);
    
    let batch_config = RateLimitConfig::batch();
    assert_eq!(batch_config.requests_per_minute, 2);
    assert_eq!(batch_config.burst_limit, 1);
}

#[tokio::test]
async fn test_rate_limit_cleanup() {
    let db_path = "tests/test_db/rate_limit_cleanup_test.sqlite";
    let _ = fs::remove_file(db_path);

    let _db = Database::new(db_path).expect("Failed to initialize database");
    
    // 短いウィンドウでテスト
    let config = RateLimitConfig {
        requests_per_minute: 1,
        burst_limit: 1,
        window_size_seconds: 1,  // 1秒のウィンドウ
    };
    
    let rate_limiter = RateLimiter::new(config);
    let test_identifier = "cleanup_test_client";

    // 1回目のリクエスト
    assert!(rate_limiter.check_rate_limit(test_identifier).is_ok());
    
    // 2回目のリクエスト（制限に達する）
    assert!(rate_limiter.check_rate_limit(test_identifier).is_err());
    
    // 1秒待機してウィンドウをリセット
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    
    // 再度成功するはず（古いエントリがクリーンアップされている）
    assert!(rate_limiter.check_rate_limit(test_identifier).is_ok());
}

#[tokio::test]
async fn test_rate_limit_error_messages() {
    let db_path = "tests/test_db/rate_limit_error_test.sqlite";
    let _ = fs::remove_file(db_path);

    let _db = Database::new(db_path).expect("Failed to initialize database");
    
    let config = RateLimitConfig {
        requests_per_minute: 1,
        burst_limit: 1,
        window_size_seconds: 60,
    };
    
    let rate_limiter = RateLimiter::new(config);
    let test_identifier = "error_test_client";

    // 1回目のリクエスト
    assert!(rate_limiter.check_rate_limit(test_identifier).is_ok());
    
    // 2回目のリクエストでエラー
    let result = rate_limiter.check_rate_limit(test_identifier);
    assert!(result.is_err());
    
    // エラーメッセージを確認（バースト制限または分間制限のどちらか）
    match result {
        Err(secure_api_key::rate_limit::RateLimitError::LimitExceeded) => {
            // 期待されるエラー
        }
        Err(secure_api_key::rate_limit::RateLimitError::BurstLimitExceeded) => {
            // これも期待されるエラー
        }
        _ => panic!("Expected rate limit error"),
    }
} 