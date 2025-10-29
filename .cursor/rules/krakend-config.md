# KrakenD Configuration Rules

## Context
Use when working with KrakenD configuration files, endpoints, or plugin configurations.

## Key Configuration Files
- `krakend-d2.json` - Main production configuration
- `krakend-local-uaa-mock.json` - Local development with UAA mock
- `krakend-example.json` - Example/template configuration
- `openapi-generator/` - Generated configurations from OpenAPI specs

## Critical Patterns

### Endpoint Structure
```json
{
  "endpoint": "/api/v1/resource",
  "method": "GET",
  "backend": [
    {
      "url_pattern": "/resource",
      "host": ["http://host.docker.internal:9000"],
      "method": "GET"
    }
  ],
  "extra_config": {
    "auth/validator": {
      "alg": "RS256",
      "jwk_url": "https://uaa-mock.smit.dev:85/uaa/token_keys"
    }
  }
}
```

### UAA Authentication Plugin Configuration
```json
{
  "extra_config": {
    "plugin/req-resp-modifier": {
      "name": ["uaa-auth"],
      "uaa-auth": {
        "uaa_url": "https://uaa-mock.smit.dev:85/uaa",
        "client_id": "your-client-id",
        "client_secret": "your-client-secret",
        "redis_addr": "localhost:6379"
      }
    }
  }
}
```

### CORS Configuration
```json
{
  "extra_config": {
    "security/cors": {
      "allow_origins": ["https://d2.smit.dev:5173"],
      "allow_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      "allow_headers": ["Authorization", "Content-Type", "X-Requested-With"],
      "expose_headers": ["Content-Length"],
      "max_age": "12h",
      "allow_credentials": true
    }
  }
}
```

## Common Mistakes to Avoid
- Missing leading slash in endpoint paths: `/api/users` not `api/users`
- Incorrect CORS configuration blocking frontend requests
- Missing authentication configuration on protected endpoints
- Wrong backend URL patterns
- Inconsistent environment variable usage

## Environment-Specific Configurations
- Use environment variables for URLs, secrets, and ports
- Maintain separate configs for development, staging, production
- Template-based generation from openapi-generator project

## Validation Steps
1. Validate JSON syntax
2. Test endpoint accessibility
3. Verify authentication flows
4. Check CORS headers
5. Confirm backend connectivity 