# Zoraxy REST API Plugin

A Zoraxy plugin that exposes a bearer-token-authenticated REST API for managing proxy rules, upstream servers (load balancer backends), certificates, and TLS configuration. Designed for integration with CI/CD pipelines (Azure DevOps, GitHub Actions, etc.) and automation.

## Architecture

```
Azure DevOps Pipeline                    Zoraxy REST API Plugin
┌─────────────────────┐                  ┌──────────────────────────┐
│ Release Pipeline    │  curl + Bearer   │ Bearer Token Auth        │
│ ─ Deploy to IIS     │ ─────────────►   │ REST API Endpoints       │
│ ─ Register w/ Zoraxy│                  │                          │
│ ─ Upload SAN cert   │                  │ ┌──────────────────────┐ │
└─────────────────────┘                  │ │ Zoraxy HTTP Client   │ │
                                         │ │ (session/cookie auth)│ │
                                         │ └──────────┬───────────┘ │
                                         └────────────┼────────────┘
                                                      │ localhost
                                                      ▼
                                         ┌──────────────────────────┐
                                         │ Zoraxy Admin API         │
                                         │ /api/proxy/*             │
                                         │ /api/cert/*              │
                                         └──────────────────────────┘
```

## Modes

- **Plugin mode**: Launched by Zoraxy via the plugin system. Listens on Zoraxy's assigned port for internal communication and optionally on a fixed port for external API access.
- **Standalone mode**: Run directly. Defaults to port 9776 (override with `LB_MANAGER_PORT` env var or `port` in config.json).

## Configuration

Copy `config.example.json` to `config.json` next to the binary:

```json
{
  "port": 9776,
  "bearer_token": "your-secure-token-here",
  "zoraxy_url": "http://localhost:8000",
  "zoraxy_user": "admin",
  "zoraxy_pass": "your-zoraxy-admin-password"
}
```

Environment variables override config file values:

| Variable | Description |
|----------|-------------|
| `LB_MANAGER_TOKEN` | Bearer token for API auth |
| `LB_MANAGER_PORT` | Fixed listen port (useful for Docker) |
| `ZORAXY_URL` | Zoraxy admin URL |
| `ZORAXY_USER` | Zoraxy admin username |
| `ZORAXY_PASS` | Zoraxy admin password |

## Build

```bash
go build -o zoraxy-rest-api-plugin
```

## Deploy as Zoraxy Plugin

```bash
mkdir -p /path/to/zoraxy/plugin/zoraxy-rest-api-plugin
cp zoraxy-rest-api-plugin /path/to/zoraxy/plugin/zoraxy-rest-api-plugin/
cp config.json /path/to/zoraxy/plugin/zoraxy-rest-api-plugin/
```

Restart Zoraxy — the plugin will appear in the plugin manager.

## Run Standalone

```bash
./zoraxy-rest-api-plugin
# or with env vars:
LB_MANAGER_TOKEN=mysecret ZORAXY_URL=http://localhost:8000 ./zoraxy-rest-api-plugin
```

## API Endpoints

All endpoints require `Authorization: Bearer <token>` header.

### Pipeline Endpoints (Composite)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/register-server` | Create proxy + add upstream + enable sticky sessions + set aliases |
| POST | `/api/deregister-server` | Remove an upstream from a proxy rule |

### Proxy Management

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/proxy/list` | List all proxy rules |
| GET | `/api/proxy/detail?ep=hostname` | Get proxy rule details |
| POST | `/api/proxy/add` | Create a new proxy rule |
| POST | `/api/proxy/edit` | Edit an existing proxy rule |
| POST | `/api/proxy/delete` | Delete a proxy rule |

### Upstream Management

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/upstream/list?ep=hostname` | List upstreams for a proxy |
| POST | `/api/upstream/add` | Add upstream server |
| POST | `/api/upstream/update` | Update upstream server |
| POST | `/api/upstream/remove` | Remove upstream server |

### Certificate Management

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/cert/upload` | Upload PFX certificate (auto-converts to PEM) |
| GET | `/api/cert/list` | List installed certificates |

### Other

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/alias/set` | Set aliases for a proxy |
| GET | `/api/health` | Health check |

## Pipeline Usage Examples

### Register a Server

Creates the proxy rule if it doesn't exist, adds the backend to the load balancer pool, and enables sticky sessions.

```bash
curl -X POST http://zoraxy-host:9776/api/register-server \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "clientui-us.example.com",
    "backend_url": "10.0.1.50:8080",
    "require_tls": true,
    "skip_tls_verify": true,
    "sticky_session": true
  }'
```

**Register Server fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `hostname` | string | yes | Primary hostname for the proxy rule |
| `backend_url` | string | yes | Backend server address (e.g., `10.0.1.50:8080`) |
| `require_tls` | bool | no | Use HTTPS when connecting to backend (default: false) |
| `skip_tls_verify` | bool | no | Skip TLS certificate validation for backend (default: false) |
| `sticky_session` | bool | no | Enable cookie-based session affinity (default: false) |
| `weight` | int | no | Load balancer weight for this upstream (default: 1) |
| `aliases` | []string | no | Additional hostnames that route to this proxy |
| `tags` | []string | no | Tags for organizing proxy rules in Zoraxy |

### Deregister a Server

Removes a backend from the load balancer pool (e.g., during maintenance or decommission).

```bash
curl -X POST http://zoraxy-host:9776/api/deregister-server \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "clientui-us.example.com",
    "backend_url": "10.0.1.50:8080"
  }'
```

### Upload SAN Certificate for Multiple Services

One SAN cert covering multiple proxy rules. Uses `"domains"` array to install the cert under each domain name so Zoraxy can filename-match certs to proxy rules.

```bash
# Download PFX from Azure Key Vault
az keyvault secret download \
  --name my-san-cert \
  --vault-name my-vault \
  --file cert.pfx \
  --encoding base64

# Upload once, install for all domains the SAN covers
PFX_B64=$(base64 -w0 cert.pfx)
curl -X POST http://zoraxy-host:9776/api/cert/upload \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"domains\": [
      \"clientui-us.example.com\",
      \"webapi-us.example.com\",
      \"fileservice-us.example.com\"
    ],
    \"pfx_base64\": \"$PFX_B64\",
    \"password\": \"\"
  }"
```

**Certificate Upload fields (JSON mode):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `domain` | string | yes* | Single domain to install cert under |
| `domains` | []string | yes* | Multiple domains to install cert under (for SAN certs) |
| `pfx_base64` | string | yes | Base64-encoded PFX/PKCS12 file |
| `password` | string | no | PFX password (empty string for no password) |

*Provide either `domain` or `domains`, not both.

Also supports multipart form upload with `file`, `domain`/`domains`, and `password` fields.

### Full Pipeline Example — Multiple Services with Shared SAN Cert

```bash
TOKEN="your-bearer-token"
API="http://zoraxy-host:9776"

# Step 1: Upload SAN cert covering all services
PFX_B64=$(base64 -w0 cert.pfx)
curl -X POST $API/api/cert/upload \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"domains\":[\"clientui-us.example.com\",\"webapi-us.example.com\",\"fileservice-us.example.com\"],\"pfx_base64\":\"$PFX_B64\",\"password\":\"\"}"

# Step 2: Register each service (separate proxy rules, different ports/servers)
curl -X POST $API/api/register-server \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"hostname":"clientui-us.example.com","backend_url":"10.0.1.50:8080","require_tls":true,"skip_tls_verify":true,"sticky_session":true}'

curl -X POST $API/api/register-server \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"hostname":"webapi-us.example.com","backend_url":"10.0.1.50:8081","require_tls":true,"skip_tls_verify":true,"sticky_session":true}'

curl -X POST $API/api/register-server \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"hostname":"fileservice-us.example.com","backend_url":"10.0.1.50:8085","require_tls":true,"skip_tls_verify":true,"sticky_session":true}'

# Step 3: Add second backend to each service for load balancing
curl -X POST $API/api/register-server \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"hostname":"clientui-us.example.com","backend_url":"10.0.1.51:8080","require_tls":true,"skip_tls_verify":true,"sticky_session":true}'
```

## TLS Configuration

The plugin supports full TLS configuration for proxy rules:

| Setting | register-server field | Zoraxy behavior |
|---------|----------------------|-----------------|
| Backend TLS | `require_tls: true` | Connects to upstream via HTTPS |
| Skip cert errors | `skip_tls_verify: true` | Ignores self-signed/expired backend certs |
| Sticky sessions | `sticky_session: true` | Cookie-based session affinity for LB |
| Frontend TLS | Automatic via cert upload | Zoraxy serves HTTPS using installed cert |

**Typical production config**: `require_tls: true` + `skip_tls_verify: true` + `sticky_session: true` with a SAN cert uploaded for all domains.

## Testing with Bruno

A Bruno collection is included in the `bruno/` folder. Open it in [Bruno](https://www.usebruno.com/) and select the "Local" environment. Update the `token` variable to match your `config.json`.
