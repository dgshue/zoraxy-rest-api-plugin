# Zoraxy REST API Plugin

A Zoraxy plugin that exposes a bearer-token-authenticated REST API for managing proxy rules, upstream servers (load balancer backends), aliases, and certificates. Designed for integration with CI/CD pipelines and automation.

## Architecture

```
Azure DevOps Pipeline                    Zoraxy LB Manager Plugin
┌─────────────────────┐                  ┌──────────────────────────┐
│ Release Pipeline    │  curl + Bearer   │ Bearer Token Auth        │
│ ─ Deploy to IIS     │ ─────────────►   │ REST API Endpoints       │
│ ─ Register w/ Zoraxy│                  │                          │
└─────────────────────┘                  │ ┌──────────────────────┐ │
                                         │ │ Zoraxy HTTP Client   │ │
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

- **Plugin mode**: Launched by Zoraxy via the plugin system. Port is assigned by Zoraxy.
- **Standalone mode**: Run directly. Defaults to port 9776 (override with `LB_MANAGER_PORT` env var).

## Configuration

Copy `config.example.json` to `config.json` next to the binary:

```json
{
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
| `ZORAXY_URL` | Zoraxy admin URL |
| `ZORAXY_USER` | Zoraxy admin username |
| `ZORAXY_PASS` | Zoraxy admin password |
| `LB_MANAGER_PORT` | Listen port (standalone mode only) |

## Build

```bash
go build -o zoraxy-lb-plugin
```

## Deploy as Zoraxy Plugin

```bash
mkdir -p /path/to/zoraxy/plugins/zoraxy-lb-plugin
cp zoraxy-lb-plugin /path/to/zoraxy/plugins/zoraxy-lb-plugin/
cp config.json /path/to/zoraxy/plugins/zoraxy-lb-plugin/
```

Restart Zoraxy — the plugin will appear in the plugin manager.

## Run Standalone

```bash
./zoraxy-lb-plugin
# or with env vars:
LB_MANAGER_TOKEN=mysecret ZORAXY_URL=http://localhost:8000 ./zoraxy-lb-plugin
```

## API Endpoints

All endpoints require `Authorization: Bearer <token>` header.

### Pipeline Endpoints (Composite)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/register-server` | Create proxy + add upstream + set aliases in one call |
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

### Other

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/alias/set` | Set aliases for a proxy |
| GET | `/api/cert/list` | List certificates |
| GET | `/api/health` | Health check |

## Example: Register Server (Pipeline Use)

```bash
curl -X POST http://localhost:9776/api/register-server \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "clientui-us.example.com",
    "backend_url": "10.0.1.50:8080",
    "require_tls": true,
    "skip_tls_verify": false,
    "weight": 1,
    "aliases": ["clientui.example.com"],
    "tags": ["us-lb", "client-ui"]
  }'
```

## Testing with Bruno

A Bruno collection is included in the `bruno/` folder. Open it in [Bruno](https://www.usebruno.com/) and select the "Local" environment. Update the `token` variable to match your `config.json`.
