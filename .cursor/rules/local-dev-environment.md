# Local Development Environment Setup

## Overview
Complex multi-platform development environment with Windows 11 + WSL2 Debian setup.

## Service Endpoints

### Production-Like URLs (via Windows hosts file)
```
Frontend:    https://d2.smit.dev:5173      (Windows 11 CMD)
API Gateway: https://api-gateway.smit.dev:2020  (WSL2 Docker)
UAA Mock:    https://uaa-mock.smit.dev:85       (WSL2 Debian)
Backend:     http://host.docker.internal:9000   (Windows 11 CMD)
Backend:     http://host.docker.internal:9001   (Windows 11 CMD)
Redis:       Internal WSL2 Docker network only
```

### Platform Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                    Windows 11 Host                         │
│  ┌─────────────────┐    ┌─────────────────────────────────┐ │
│  │ Frontend        │    │ Backend Services                │ │
│  │ Vue.js + Vite   │    │ Go servers :9000, :9001        │ │
│  │ :5173           │    │ Windows CMD                     │ │
│  └─────────────────┘    └─────────────────────────────────┘ │
│                                                             │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              WSL2 (Debian)                              │ │
│  │  ┌──────────────┐  ┌────────────┐  ┌────────────────┐  │ │
│  │  │ KrakenD      │  │ UAA Mock   │  │ Redis          │  │ │
│  │  │ Docker :2020 │  │ :85        │  │ Docker         │  │ │
│  │  └──────────────┘  └────────────┘  └────────────────┘  │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Network Configuration

### Windows hosts file (`C:\Windows\System32\drivers\etc\hosts`)
```
# Development domains pointing to local public IP
[YOUR_PUBLIC_IP]  d2.smit.dev
[YOUR_PUBLIC_IP]  api-gateway.smit.dev
[YOUR_PUBLIC_IP]  uaa-mock.smit.dev
```

### Port Forwarding (Windows Admin CMD)
```cmd
# Forward traffic from public IP to WSL2 services
netsh interface portproxy add v4tov4 listenaddress=[PUBLIC_IP] listenport=2020 connectaddress=[WSL2_IP] connectport=2020
netsh interface portproxy add v4tov4 listenaddress=[PUBLIC_IP] listenport=85 connectaddress=[WSL2_IP] connectport=85
```

### CORS Configuration Considerations
```json
{
  "allow_origins": [
    "https://d2.smit.dev:5173"
  ],
  "allow_credentials": true
}
```

## Platform-Specific Commands

### Starting Services

#### Frontend (Windows CMD)
```cmd
cd test-frontend
npm run dev
# Runs on https://d2.smit.dev:5173
```

#### Backend (Windows CMD)
```cmd
cd test-backend
go run main.go
# Runs on :9000 and :9001
```

#### KrakenD (WSL2 Debian)
```bash
cd /path/to/project
docker run -it --rm -p 2020:2020 -v $PWD:/etc/krakend/ krakend/krakend:latest run -d -c krakend-local-uaa-mock.json
```

#### UAA Mock (WSL2 Debian)
```bash
cd uaa-mock
./start-uaa-mock.sh
# Runs on :85
```

#### Redis (WSL2 Docker)
```bash
docker run -d --name redis -p 6379:6379 redis:alpine
```

## Development Workflow

### Making Changes
1. **Frontend changes**: Edit in Windows, auto-reload via Vite
2. **Backend changes**: Restart Go servers in Windows CMD
3. **KrakenD config**: Edit JSON, restart Docker container in WSL2
4. **UAA changes**: Restart service in WSL2

### Testing Cross-Service Communication
1. Frontend → API Gateway: `https://d2.smit.dev:5173` → `https://api-gateway.smit.dev:2020`
2. API Gateway → Backend: Docker → `host.docker.internal:9000`
3. API Gateway → UAA: Docker → `uaa-mock.smit.dev:85`
4. UAA → Redis: WSL2 internal networking

## Common Issues & Solutions

### CORS Issues
```javascript
// Frontend fetch configuration
fetch('https://api-gateway.smit.dev:2020/api/endpoint', {
  credentials: 'include',
  headers: {
    'Content-Type': 'application/json'
  }
})
```

### SSL Certificate Issues
- Services use self-signed certificates
- Firefox: Accept security exceptions for each domain
- Development only - not for production

### WSL2 IP Changes
```bash
# Get current WSL2 IP
ip addr show eth0 | grep inet | awk '{print $2}' | cut -d/ -f1

# Update port proxy rules when WSL2 IP changes
```

### Docker Networking
```bash
# Access Windows services from WSL2 Docker
host.docker.internal:9000  # Windows backend service
```

## Environment Variables

### Frontend (.env.local)
```env
VITE_API_GATEWAY_URL=https://api-gateway.smit.dev:2020
VITE_UAA_URL=https://uaa-mock.smit.dev:85
```

### Backend (Windows)
```env
PORT=9000
UAA_URL=https://uaa-mock.smit.dev:85
```

### KrakenD Configuration
```json
{
  "backend": [
    {
      "host": ["http://host.docker.internal:9000"]
    }
  ]
}
```

## Debugging Tips

### Check Service Status
```bash
# Windows services
netstat -an | findstr ":5173"
netstat -an | findstr ":9000"

# WSL2 services
ss -tlnp | grep :2020
ss -tlnp | grep :85
```

### Network Connectivity
```bash
# From WSL2 to Windows
curl http://host.docker.internal:9000/health

# From Windows to WSL2
curl https://api-gateway.smit.dev:2020/health
```

### Logs
- **Frontend**: Browser dev tools + Vite console
- **Backend**: Windows CMD output
- **KrakenD**: Docker logs
- **UAA Mock**: WSL2 service logs 