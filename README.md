# Secure API Key Management System

A robust API key management system built with Rust, featuring 160-bit entropy keys, JWT access tokens, and SQLite storage.

## Features

- **160-bit API Keys**: Cryptographically secure key generation with checksum validation
- **JWT Access Tokens**: Short-lived tokens for API access
- **SQLite Storage**: Lightweight database for key management
- **CORS Support**: Web application ready
- **Usage Logging**: Track API usage and security events

## Project Structure

```
src/
├── lib.rs          # Main library module
├── main.rs         # Application entry point
├── database.rs     # SQLite database operations
├── models.rs       # Data structures
├── security.rs     # API key and JWT token services
├── handlers.rs     # HTTP request handlers
└── errors.rs       # Error types

db/
└── schema.sql      # Database schema
```

## Quick Start

1. **Install dependencies**:
   ```bash
   cargo build
   ```

2. **Set environment variables**:
   ```bash
   # Create .env file
   echo "JWT_SECRET=your-super-secret-jwt-key-change-this-in-production" > .env
   echo "RUST_LOG=info" >> .env
   ```

3. **Run the server**:
   ```bash
   cargo run
   ```

4. **Test the API**:
   ```bash
   # Create a user
   curl -X POST http://localhost:3000/users \
     -H "Content-Type: application/json" \
     -d '{"username": "testuser", "email": "test@example.com"}'

   # Create an API key
   curl -X POST http://localhost:3000/api-keys \
     -H "Content-Type: application/json" \
     -d '{"user_id": 1, "scopes": ["read:data", "write:data"]}'

   # Validate API key and get access token
   curl -X POST http://localhost:3000/validate \
     -H "Content-Type: application/json" \
     -d '{"api_key": "your-api-key-here"}'

   # Validate access token
   curl -X POST http://localhost:3000/tokens/validate \
     -H "Content-Type: application/json" \
     -d '{"token": "your-jwt-token-here"}'

   # Access protected endpoint
   curl -X GET http://localhost:3000/protected \
     -H "Content-Type: application/json" \
     -d '{"token": "your-jwt-token-here"}'
   ```

## API Endpoints

### Users
- `POST /users` - Create a new user

### API Keys
- `POST /api-keys` - Create a new API key
- `POST /validate` - Validate API key and get access token

### Tokens
- `POST /tokens/validate` - Validate JWT access token

### Protected Resources
- `GET /protected` - Example protected endpoint

## Security Features

### API Key Format
```
prefix_env_version_timestamp_random_checksum
```
Example: `myapp_dev_v1_1703123456_k8m2n9p3q7r1s5t4w6x9y2z5_a7b3c1d9`

### Security Measures
- 160-bit entropy (20 bytes random + 32-bit timestamp)
- SHA256 checksum validation
- JWT access tokens with 1-hour expiration
- SQLite database with proper indexing
- Usage logging and monitoring

## Development

### Building
```bash
cargo build
```

### Testing
```bash
cargo test
```

### Running with custom configuration
```bash
RUST_LOG=debug cargo run
```

## Production Considerations

1. **Change JWT Secret**: Use a strong, unique secret key
2. **Database Security**: Consider using a more robust database for production
3. **Rate Limiting**: Implement rate limiting for API endpoints
4. **Monitoring**: Add comprehensive logging and monitoring
5. **HTTPS**: Always use HTTPS in production

## License

MIT License 