# Workspace Context

## Project Overview
This is a KrakenD API Gateway configuration and authentication system with 4 sub-projects:

### 1. openapi-generator/ (Go)
- **Purpose**: Generates KrakenD configuration files from OpenAPI specifications
- **Key files**: `main.go`, `config.go`, `types.go`, `openapi-specs/`
- **Technology**: Go 1.24.4, OpenAPI 3.0

### 2. test-backend/ (Go) 
- **Purpose**: Test API server for validating KrakenD configurations and uaa-auth plugin
- **Key files**: `main.go`, `handler.go`, `token.go`
- **Technology**: Go 1.24.4, Swagger/OpenAPI, REST API

### 3. test-frontend/ (Vue.js)
- **Purpose**: Frontend demo application showcasing KrakenD + UAA authentication flows
- **Key files**: `src/App.vue`, `src/router/`, `src/stores/`, `src/components/`
- **Technology**: Vue.js 3, TypeScript, PrimeVue, Tailwind CSS, Vite

### 4. uaa-auth/ (Go)
- **Purpose**: KrakenD plugin for UAA (User Account and Authentication) integration
- **Key files**: `uaa_auth.go`, `internal/handlers/`, `internal/store/`, `krakend-uaa-mock.json`
- **Main KrakenD config**: `krakend-uaa-mock.json` (primary development configuration)
- **Technology**: Go 1.24.2 (matches KrakenD), KrakenD plugin system, OAuth 2.0, Redis

## Local Development Environment

### Service Architecture
- **Frontend**: `https://d2.smit.dev:5173` (Windows 11 CMD, Vite dev server)
- **Backend**: `http://host.docker.internal:9000` and `:9001` (Windows 11 CMD, Go servers)
- **API Gateway**: `https://api-gateway.smit.dev:2020` (WSL2 Debian Docker, KrakenD)
- **UAA Mock**: `https://uaa-mock.smit.dev:85` (WSL2 Debian, uaa-mock service)
- **Redis**: WSL2 Debian Docker (internal networking)

### Platform Distribution
- **Windows 11**: Frontend (Vue.js), Backend (Go servers)
- **WSL2 (Debian)**: KrakenD API Gateway, UAA Mock, Redis
- **Browser**: Windows Firefox for accessing all services

### Network Configuration
- **Domain Resolution**: Windows hosts file resolves custom domains to local computer public IP
- **Cross-Platform Access**: Windows admin-level portproxy forwards traffic to WSL2 services
- **Docker Networking**: `host.docker.internal` used for Windows-to-Docker communication
- **Mixed Protocols**: HTTPS for user-facing services, HTTP for internal backend communication

### Key Development Considerations
- KrakenD plugins require Linux environment (hence WSL2)
- Cross-platform communication uses port forwarding
- SSL/TLS termination handled at individual service level
- Redis accessible only within WSL2 Docker network
- Development workflow spans multiple command environments

## When Working on Specific Projects
- Mention the project name in your requests for focused context
- Each project has its own technology stack and conventions
- Cross-project changes often involve authentication flow updates
- Consider platform-specific limitations (Windows vs WSL2)

## Common Cross-Project Tasks
- Authentication flow modifications affect uaa-auth + test-frontend
- API changes require updates to openapi-generator specs + test-backend
- Configuration changes impact KrakenD JSON files across projects 
- Network/CORS configuration must account for custom domain setup 