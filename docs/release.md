# OSS Gateway Release Checklist

## Pre-release gates

1. `go test ./...` passes locally.
2. `go vet ./...` passes locally.
3. `gofmt -w $(find . -name '*.go' -type f)` yields no diffs.
4. `go mod tidy` yields no `go.mod`/`go.sum` diffs.
5. CI workflow (`.github/workflows/ci.yml`) is green on the release commit.

## Contract and compatibility checks

1. Review [OpenAPI contract](./openapi.yaml) for any endpoint shape/status changes.
2. If contract changed, document breaking changes in release notes.
3. Validate websocket compatibility for:
   - `/gateway/v1/agent/connect`
   - `/gateway/v1/integrations/tunnel/connect`
4. Validate public webhook ingress contract:
   - `/integrations/{route_id}/{route_token}`
   - status behavior for `404`, `503`, `504`, and forwarded responses.

## Runtime smoke checks

1. Start server with `AUTH_MODE=demo` and `STATE_BACKEND=memory`.
2. Verify health endpoints:
   - `GET /healthz`
   - `GET /readyz`
3. Verify OAuth flow (`/oauth/authorize` -> `/oauth/token`).
4. Verify scope policy:
   - `gateway:share` routes reject tokens without `gateway:share`.
   - `gateway:session` routes reject tokens without `gateway:session`.
   - device routes reject tokens without `device`.
5. Verify reconnect behavior:
   - agent websocket replacement on same `device_id`.
   - tunnel websocket replacement on same `device_id`.

## Release notes minimum template

- Version:
- Date:
- Summary:
- Contract changes:
- Migration notes:
- Known limitations:
