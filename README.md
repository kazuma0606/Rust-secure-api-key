# Secure API Key Management System

A robust and secure API key management system built with Rust, featuring hybrid authentication (long-lived API keys for short-lived JWT access tokens), comprehensive rate limiting, and SQLite-based storage.

## Features

### 🔐 Security Features
- **160-bit API Key Entropy**: Secure random generation with SHA256 checksum validation
- **Hybrid Authentication**: Long-lived API keys for JWT access token issuance
- **Comprehensive Rate Limiting**: API-specific rate limiting with burst protection
- **Database Integrity**: Foreign key constraints and unique constraints
- **Usage Tracking**: API key usage monitoring and logging

### 📊 Rate Limiting Configuration

The system implements intelligent rate limiting with different configurations for various API types:

#### Default Rate Limits
```rust
// Default configuration
requests_per_minute: 100,
burst_limit: 20,
window_size_seconds: 60,
```

#### API-Specific Limits
- **Authentication APIs**: 5 requests/minute (burst: 3)
- **Data Read APIs**: 200 requests/minute (burst: 50)
- **Data Write APIs**: 50 requests/minute (burst: 10)
- **API Key Generation**: 3 requests/minute (burst: 1)
- **Batch Processing**: 2 requests/minute (burst: 1)

### 🏗️ Architecture

```
src/
├── database.rs      # SQLite database operations
├── models.rs        # Data structures and serialization
├── security.rs      # API key and JWT token management
├── errors.rs        # Custom error handling
├── rate_limit.rs    # Rate limiting implementation
└── main.rs          # HTTP server and routes
```

## Quick Start

### Prerequisites
- Rust 1.70+
- SQLite3

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd secure-api-key
   ```

2. **Set up environment variables**
   ```bash
   # Create .env file
   echo "JWT_SECRET=your-super-secret-key-here" > .env
   ```

3. **Run the server**
   ```bash
   cargo run
   ```

The server will start on `http://localhost:3000`

### API Endpoints

#### User Management
```bash
# Create user
curl -X POST http://localhost:3000/users \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "email": "test@example.com"}'
```

#### API Key Management
```bash
# Generate API key
curl -X POST http://localhost:3000/api-keys \
  -H "Content-Type: application/json" \
  -d '{"user_id": 1, "scopes": ["read", "write"]}'
```

#### Authentication
```bash
# Validate API key
curl -X POST http://localhost:3000/validate \
  -H "Content-Type: application/json" \
  -d '{"api_key": "your-api-key-here"}'

# Validate JWT token
curl -X POST http://localhost:3000/tokens/validate \
  -H "Content-Type: application/json" \
  -d '{"token": "your-jwt-token-here"}'
```

#### Protected Endpoints
```bash
# Access protected endpoint
curl -X POST http://localhost:3000/protected \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-jwt-token-here" \
  -d '{"token": "your-jwt-token-here"}'
```

## Rate Limiting

The system automatically applies rate limiting to all endpoints. When limits are exceeded, you'll receive a `429 Too Many Requests` response:

```json
{
  "error": "Rate limit exceeded. Remaining requests: 0, Reset in: Some(\"45s\")"
}
```

### Rate Limit Headers
The system includes rate limit information in response headers:
- `X-RateLimit-Limit`: Maximum requests per window
- `X-RateLimit-Remaining`: Remaining requests in current window
- `X-RateLimit-Reset`: Time until rate limit resets

## Testing

Run the comprehensive test suite:

```bash
# Run all tests
cargo test

# Run specific test categories
cargo test --test integration_test
cargo test --test unit_test
```

### Test Coverage
- **Database Operations**: User and API key CRUD operations
- **Token Management**: JWT generation and validation
- **Security Features**: API key validation and checksum verification
- **Rate Limiting**: Rate limit enforcement and error handling

## Configuration

### Environment Variables
```bash
JWT_SECRET=your-jwt-secret-key
RUST_LOG=info
```

### Database Schema
The system uses SQLite with the following schema:
- `users`: User account information
- `api_keys`: API key storage and metadata
- `access_tokens`: JWT token management
- `usage_logs`: API usage tracking

## Security Considerations

### API Key Security
- 160-bit entropy for strong randomness
- SHA256 checksum validation
- Environment-specific prefixes
- Version tracking for key rotation

### Rate Limiting Security
- Client identification via API keys or IP addresses
- Burst protection against DDoS attacks
- Configurable limits per API category
- Automatic cleanup of expired rate limit entries

### Best Practices
1. **Use HTTPS in production**
2. **Rotate JWT secrets regularly**
3. **Monitor rate limit violations**
4. **Implement proper logging**
5. **Use strong API key prefixes**

## Development

### Project Structure
```
├── src/
│   ├── database.rs      # Database operations
│   ├── models.rs        # Data structures
│   ├── security.rs      # Authentication logic
│   ├── errors.rs        # Error handling
│   ├── rate_limit.rs    # Rate limiting
│   ├── lib.rs           # Library exports
│   └── main.rs          # HTTP server
├── tests/
│   ├── integration_test.rs  # Integration tests
│   ├── unit_test.rs         # Unit tests
│   └── test_db/             # Test databases
├── db/
│   └── schema.sql           # Database schema
└── Cargo.toml               # Dependencies
```

### Adding New Endpoints
1. Define the handler function in `main.rs`
2. Add the route to the router
3. Configure appropriate rate limiting
4. Add tests for the new endpoint

### Customizing Rate Limits
```rust
// Create custom rate limit configuration
let custom_config = RateLimitConfig {
    requests_per_minute: 150,
    burst_limit: 30,
    window_size_seconds: 60,
};

// Add to rate limit manager
rate_limit_manager.add_limiter("custom".to_string(), custom_config);
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## Support

For questions or issues, please open an issue on GitHub or contact the development team. 