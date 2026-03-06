# OSS Commands Gateway

Modular OSS gateway for OAuth, device sharing, relay, and webhook tunneling.

## What This Repo Focuses On

- Fast deployment for collaboration testing.
- Explicit auth modes: `demo`, `firebase`, `oidc`.
- Memory-only runtime state (no Redis required).
- Clean OSS baseline for share + relay + webhook flows.

## Project Layout

- `cmd/server` - process entrypoint
- `internal/app` - dependency wiring and route registration
- `internal/config` - environment contract and validation
- `internal/oauth` - OAuth/OIDC surfaces (authorize/token/views)
- `internal/gateway` - device/share/session + websocket tunnel handlers
- `internal/jwt` - issued-token signing and verification
- `internal/idtoken` - upstream identity token verifiers
- `internal/health` - health/readiness handlers
- `docs/openapi.yaml` - endpoint contract
- `docs/release.md` - release checklist

## Prerequisites

- Go 1.25+ (required by Fiber v3)

## Quick Start (Memory Backend)

1. Create env file:

```bash
cp .env.example .env
```

2. Generate a signing key and set env vars:

```bash
# Generate a strong random key
openssl rand -base64 48
```

```bash
PORT=8080
JWT_SIGNING_KEY=<paste-generated-key-here>
AUTH_MODE=demo
STATE_BACKEND=memory
```

3. Run:

```bash
go run ./cmd/server
```

4. Verify:

```bash
curl -s http://localhost:8080/healthz
curl -s http://localhost:8080/readyz
```

### Out-Of-The-Box Local Run (Commands Desktop Compatible)

```bash
export JWT_SIGNING_KEY="$(openssl rand -hex 32)"
PORT=8091 PUBLIC_BASE_URL=http://localhost:8091 AUTH_MODE=demo STATE_BACKEND=memory \
OAUTH_DEFAULT_CLIENT_ID=commands-desktop-public \
REDIRECT_ALLOWLIST='http://localhost:61696/callback,urn:ietf:wg:oauth:2.0:oob' \
OAUTH_REDIRECT_URIS='http://localhost:61696/callback,urn:ietf:wg:oauth:2.0:oob' \
go run ./cmd/server
```

## Commands.com Desktop Compatibility

If you are pairing this OSS gateway with the current commands.com desktop app, set:

```bash
OAUTH_DEFAULT_CLIENT_ID=commands-desktop-public
REDIRECT_ALLOWLIST=http://localhost:61696/callback,urn:ietf:wg:oauth:2.0:oob
OAUTH_REDIRECT_URIS=http://localhost:61696/callback,urn:ietf:wg:oauth:2.0:oob
```

## Built-in Console

The gateway includes a built-in admin console at `/console` with device management,
session chat, and dashboard. It authenticates through the same OAuth flow as all other clients.

## Deploy to Railway (10-Minute Path)

1. Create a Railway project from this repo.
2. Add env vars:
   - `JWT_SIGNING_KEY` — generate with `openssl rand -base64 48`
   - `AUTH_MODE=demo` (or `oidc` for Firebase — see below)
   - `STATE_BACKEND=memory`
   - `PUBLIC_BASE_URL` is auto-detected from `RAILWAY_PUBLIC_DOMAIN`; only set it if using a custom domain
3. Deploy.
4. Visit `https://<your-domain>/console` or set the URL as `Gateway URL` in desktop settings.

## Auth Modes

- `AUTH_MODE=demo`
  - Fast local/shared testing.
  - Non-production mode.
  - OAuth still issues signed gateway tokens.
- `AUTH_MODE=firebase`
  - Verifies Firebase ID tokens server-side using the Firebase Admin SDK.
  - Requires `FIREBASE_PROJECT_ID`.
  - Optional: `FIREBASE_CREDENTIALS_PATH`.
- `AUTH_MODE=oidc`
  - Verifies generic OIDC ID tokens via the issuer's public JWKS.
  - Requires `OIDC_ISSUER_URL` and `OIDC_CLIENT_ID`.
  - Works with Firebase — set `OIDC_ISSUER_URL=https://securetoken.google.com/<project-id>` and `OIDC_CLIENT_ID=<project-id>`. No credentials file needed.

### Firebase Sign-In UI

When `FIREBASE_API_KEY` and `FIREBASE_PROJECT_ID` are set, the OAuth authorize page
shows Google and GitHub sign-in buttons powered by Firebase Authentication (popup flow).
This works with both `AUTH_MODE=firebase` and `AUTH_MODE=oidc`.

Required env vars:
- `FIREBASE_API_KEY` — your Firebase project's web API key (public, safe to expose)
- `FIREBASE_PROJECT_ID` — your Firebase project ID

You must also add your deployment domain (e.g. `gateway-xyz.up.railway.app`) to
**Firebase Console → Authentication → Settings → Authorized domains**.

## Scope Policy

Gateway routes require an authenticated user token.
Only device registration, agent handshake ack, and websocket agent/tunnel connect enforce `device` scope:

- `device`
  - `PUT /gateway/v1/devices/:device_id/identity-key`
  - `POST /gateway/v1/sessions/:session_id/handshake/agent-ack`
  - `GET /gateway/v1/agent/connect` (WebSocket)
  - `GET /gateway/v1/integrations/tunnel/connect` (WebSocket)

## Ingress Rate Limits

Public ingress uses in-memory fixed-window limits (default 60s window):

- `INGRESS_GLOBAL_LIMIT_PER_WINDOW` (default `3000`)
- `INGRESS_IP_LIMIT_PER_WINDOW` (default `600`)
- `INGRESS_ROUTE_LIMIT_PER_WINDOW` (default `300`)

## Relay Security Defaults

- Handshake requires:
  - `device_id`
  - `handshake_id`
  - `client_ephemeral_public_key` (32-byte base64 value)
  - `client_session_nonce`
- Agent ack is signature-verified against device identity key.
- Session messages require `X-Idempotency-Key`.
- Encrypted envelope (`encrypted`, `ciphertext`, `nonce`, `tag`, `seq`) is enforced by default.
- Replay checks are enforced in-memory for:
  - `client_to_agent` message `seq`
  - `agent_to_client` frame `seq`
- WebSocket transport replay protection is enabled when `TRANSPORT_TOKEN_SECRET` is set.
  - If unset in env, it defaults to `JWT_SIGNING_KEY`.

Config knobs:

- `IDEMPOTENCY_TTL_SECONDS` (default `300`)
- `REQUIRE_ENCRYPTED_FRAMES` (default `true`)
- `TRANSPORT_TOKEN_SECRET` (default: `JWT_SIGNING_KEY`)
- `TRANSPORT_TOKEN_TTL_SECONDS` (default `3600`)

## Endpoint Contract

- OpenAPI-level contract: [`docs/openapi.yaml`](./docs/openapi.yaml)
- Release checklist: [`docs/release.md`](./docs/release.md)

## Endpoints

System:

- `GET /healthz`
- `GET /readyz`

OAuth:

- `GET /.well-known/openid-configuration`
- `GET /.well-known/jwks.json`
- `GET|POST /oauth/authorize`
- `POST /oauth/token`
- `POST /oauth/token/revoke`

Gateway relay/share:

- `GET /gateway/v1/health`
- `PUT /gateway/v1/devices/:device_id/identity-key`
- `GET /gateway/v1/devices/:device_id/identity-key`
- `POST /gateway/v1/shares/invites`
- `POST /gateway/v1/shares/invites/accept`
- `GET /gateway/v1/shares/devices/:device_id/grants`
- `POST /gateway/v1/shares/grants/:grant_id/revoke`
- `POST /gateway/v1/shares/grants/:grant_id/leave`
- `POST /gateway/v1/sessions/:session_id/handshake/client-init`
- `GET /gateway/v1/sessions/:session_id/handshake/:handshake_id`
- `POST /gateway/v1/sessions/:session_id/handshake/agent-ack`
- `POST /gateway/v1/sessions/:session_id/messages`
- `GET /gateway/v1/sessions/:session_id/events`
- `GET /gateway/v1/agent/connect` (WebSocket)

Integrations + webhook tunnel:

- `POST /gateway/v1/integrations/routes`
- `PUT /gateway/v1/integrations/routes/:route_id`
- `DELETE /gateway/v1/integrations/routes/:route_id`
- `GET /gateway/v1/integrations/routes`
- `POST /gateway/v1/integrations/routes/:route_id/rotate-token`
- `GET /gateway/v1/integrations/tunnel/connect` (WebSocket)
- `ALL /integrations/:route_id/:route_token` (public ingress)

## Testing

```bash
go test ./...
```

## CORS Configuration

The default `ALLOW_ORIGINS=*` is suitable for `AUTH_MODE=demo` local development.
For production deployments using `firebase` or `oidc` auth modes, restrict
`ALLOW_ORIGINS` to your application's actual origin(s) (e.g.
`ALLOW_ORIGINS=https://app.example.com`). A wildcard origin disables
credential support and weakens browser-side request isolation.

## Notes

- Runtime state is in-memory and single-process.
- This baseline intentionally excludes MCP and Redis dependencies.
