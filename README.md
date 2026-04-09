<div align="center">

# Commands.com Gateway (OSS)

**Deploy your own encrypted relay. Own your infrastructure.**

[![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8.svg)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)
[![Encryption](https://img.shields.io/badge/E2EE-X25519%20%2B%20AES--256--GCM-8B5CF6.svg)](#relay-security)
[![Deploy](https://img.shields.io/badge/Deploy-Railway-0B0D0E.svg)](#deploy-to-railway)

Self-hosted gateway for OAuth, device relay, session sharing, and webhook tunneling.
Memory-only runtime — no Redis, no database, no external dependencies.

```
Agent  <── E2EE ──>  Gateway (you host this)  <── E2EE ──>  Browser / Desktop
```

</div>

---

## Highlights

| | |
|---|---|
| **Zero dependencies** | Single Go binary, in-memory state, no Redis or database required |
| **Built-in console** | Admin UI at `/console` — devices, sessions, shares, dashboard |
| **Flexible auth** | Demo mode for testing, Firebase popup sign-in, or any OIDC provider |
| **E2E encrypted relay** | X25519 + HKDF + AES-256-GCM, direction-split keys, replay protection |
| **Webhook tunneling** | Route external webhooks (Slack, GitHub, etc.) to local agents over WebSocket |
| **One-click deploy** | Railway template with auto-detected public URL |

## Requirements

- Go 1.25+

## Quick Start

```bash
git clone https://github.com/Commands-com/gateway.git
cd gateway
cp .env.example .env
```

Generate a signing key and update `.env`:

```bash
openssl rand -base64 48
```

```env
JWT_SIGNING_KEY=<paste-generated-key>
AUTH_MODE=demo
```

Run:

```bash
go run ./cmd/server
```

Verify:

```bash
curl http://localhost:8080/healthz
curl http://localhost:8080/readyz
```

Open the console at [http://localhost:8080/console](http://localhost:8080/console).

### Desktop Agent Compatibility

For use with the [Commands.com Agent Workspace](https://github.com/Commands-com/agent-workspace):

```bash
export JWT_SIGNING_KEY="$(openssl rand -hex 32)"
PORT=8091 AUTH_MODE=demo \
OAUTH_DEFAULT_CLIENT_ID=commands-desktop-public \
REDIRECT_ALLOWLIST='http://localhost:61696/callback,urn:ietf:wg:oauth:2.0:oob' \
go run ./cmd/server
```

## Deploy to Railway

1. Create a Railway project from this repo.
2. Set environment variables:

| Variable | Value | Notes |
|---|---|---|
| `JWT_SIGNING_KEY` | `openssl rand -base64 48` | Required, >= 32 bytes |
| `AUTH_MODE` | `demo` or `oidc` | See [Auth Modes](#auth-modes) |

`PUBLIC_BASE_URL` is auto-detected from `RAILWAY_PUBLIC_DOMAIN`. Only set it for custom domains.

3. Deploy.
4. Visit `https://<your-domain>/console`.

### Firebase on Railway

For Google/GitHub sign-in via Firebase, add these vars:

| Variable | Value |
|---|---|
| `AUTH_MODE` | `oidc` |
| `OIDC_ISSUER_URL` | `https://securetoken.google.com/<project-id>` |
| `OIDC_CLIENT_ID` | `<project-id>` |
| `FIREBASE_API_KEY` | Your Firebase web API key (public) |
| `FIREBASE_PROJECT_ID` | Your Firebase project ID |

Then add your Railway domain to **Firebase Console > Authentication > Settings > Authorized domains**.

No credentials file needed — OIDC validates tokens via Firebase's public JWKS.

## Auth Modes

| Mode | Use case | Required vars |
|---|---|---|
| `demo` | Local dev, testing | None beyond `JWT_SIGNING_KEY` |

In `demo` mode, the token endpoint additionally accepts the `client_credentials`
grant and `POST /gateway/v1/integrations/routes` auto-registers an unknown
`device_id` on first use. Both affordances exist so headless agents can
bootstrap without a browser redirect or prior identity-key PUT. They are
unavailable in any other auth mode.
| `firebase` | Firebase Admin SDK verification | `FIREBASE_PROJECT_ID` |
| `oidc` | Any OIDC provider (inc. Firebase) | `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID` |

When `FIREBASE_API_KEY` and `FIREBASE_PROJECT_ID` are set, the authorize page shows
Google and GitHub popup sign-in buttons. Works with both `firebase` and `oidc` modes.

## Relay Security

- **Handshake**: X25519 ephemeral key exchange with Ed25519 identity signatures
- **Key derivation**: HKDF-SHA256 with transcript hash salt, direction-split keys
- **Encryption**: AES-256-GCM with deterministic nonces and AAD binding
- **Replay protection**: Monotonic sequence enforcement, idempotency keys, transport tokens
- **Frame validation**: `REQUIRE_ENCRYPTED_FRAMES=true` by default

| Config | Default | Description |
|---|---|---|
| `REQUIRE_ENCRYPTED_FRAMES` | `true` | Reject unencrypted session frames |
| `IDEMPOTENCY_TTL_SECONDS` | `300` | Dedup window for message delivery |
| `TRANSPORT_TOKEN_SECRET` | derived from `JWT_SIGNING_KEY` | WebSocket transport auth |
| `TRANSPORT_TOKEN_TTL_SECONDS` | `3600` | Transport token lifetime |

## Built-in Console

The gateway serves an admin console at `/console`:

- **Dashboard** — connected devices, active sessions, health status
- **Devices** — online/offline status, identity keys, quick session launch
- **Sessions** — E2E encrypted chat with agents, handshake status
- **Shares** — invite management, grant lifecycle, revoke controls

Authenticates through the same OAuth flow as all other clients.

## API Endpoints

<details>
<summary><strong>System</strong></summary>

- `GET /healthz` — liveness
- `GET /readyz` — readiness
- `GET /console` — admin UI

</details>

<details>
<summary><strong>OAuth</strong></summary>

- `GET /.well-known/openid-configuration`
- `GET /.well-known/jwks.json`
- `GET|POST /oauth/authorize`
- `POST /oauth/token`
- `POST /oauth/token/revoke`
- `POST /register` — dynamic client registration

</details>

<details>
<summary><strong>Gateway — Devices & Sessions</strong></summary>

- `GET /gateway/v1/health`
- `PUT /gateway/v1/devices/:device_id/identity-key`
- `GET /gateway/v1/devices/:device_id/identity-key`
- `POST /gateway/v1/sessions/:session_id/handshake/client-init`
- `GET /gateway/v1/sessions/:session_id/handshake/:handshake_id`
- `POST /gateway/v1/sessions/:session_id/handshake/agent-ack`
- `POST /gateway/v1/sessions/:session_id/messages`
- `GET /gateway/v1/sessions/:session_id/events` (SSE)
- `GET /gateway/v1/agent/connect` (WebSocket)

</details>

<details>
<summary><strong>Gateway — Shares</strong></summary>

- `POST /gateway/v1/shares/invites`
- `POST /gateway/v1/shares/invites/accept`
- `GET /gateway/v1/shares/devices/:device_id/grants`
- `POST /gateway/v1/shares/grants/:grant_id/revoke`
- `POST /gateway/v1/shares/grants/:grant_id/leave`

</details>

<details>
<summary><strong>Integrations & Webhook Tunnel</strong></summary>

- `POST /gateway/v1/integrations/routes`
- `PUT /gateway/v1/integrations/routes/:route_id`
- `DELETE /gateway/v1/integrations/routes/:route_id`
- `GET /gateway/v1/integrations/routes`
- `POST /gateway/v1/integrations/routes/:route_id/rotate-token`
- `GET /gateway/v1/integrations/tunnel/connect` (WebSocket)
- `ALL /integrations/:route_id/:route_token` (public ingress)

</details>

## Rate Limits

Public ingress uses in-memory fixed-window rate limiting:

| Config | Default |
|---|---|
| `INGRESS_RATE_WINDOW_SECONDS` | `60` |
| `INGRESS_GLOBAL_LIMIT_PER_WINDOW` | `3000` |
| `INGRESS_IP_LIMIT_PER_WINDOW` | `600` |
| `INGRESS_ROUTE_LIMIT_PER_WINDOW` | `300` |

## Project Layout

```
cmd/server          Process entrypoint
internal/app        Dependency wiring and route registration
internal/config     Environment contract and validation
internal/console    Built-in admin UI (embedded HTML)
internal/oauth      OAuth/OIDC (authorize, token, views)
internal/gateway    Device, share, session, tunnel handlers
internal/jwt        Token signing and verification
internal/idtoken    Upstream identity token verifiers
internal/health     Health/readiness handlers
docs/openapi.yaml   Endpoint contract
```

## Testing

```bash
go test ./...
```

## CORS

Default `ALLOW_ORIGINS=*` is suitable for demo mode. For production, restrict to your app's origin:

```env
ALLOW_ORIGINS=https://app.example.com
```

## Additional Docs

- [Contributing](./CONTRIBUTING.md)
- OpenAPI spec: [`docs/openapi.yaml`](./docs/openapi.yaml)
- Release checklist: [`docs/release.md`](./docs/release.md)
