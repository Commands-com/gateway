package app

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"oss-commands-gateway/internal/config"
	"oss-commands-gateway/internal/jwt"
)

// TestAuthenticatedAccessNoScopeGates verifies that any authenticated token
// can access all gateway endpoints — no per-route scope enforcement.
func TestAuthenticatedAccessNoScopeGates(t *testing.T) {
	validIdentityKey := "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="

	cfg := &config.Config{
		Port:                        "8080",
		PublicBaseURL:               "http://localhost:8080",
		AllowOrigins:                []string{"*"},
		RedirectAllowlist:           []string{"http://localhost:61696/callback", "http://localhost:3000/callback", "urn:ietf:wg:oauth:2.0:oob"},
		FrontendURL:                 "https://example.com",
		JWTSigningKey:               "test-signing-key-that-is-at-least-thirty-two-bytes",
		AccessTokenTTL:              time.Hour,
		AuthCodeTTL:                 5 * time.Minute,
		RefreshTokenTTL:             24 * time.Hour,
		DemoTokenTTL:                time.Hour,
		Audience:                    "commands-gateway",
		StateBackend:                config.StateBackendMemory,
		AuthMode:                    config.AuthModeDemo,
		IngressRateWindowSeconds:    60,
		IngressGlobalLimitPerWindow: 1000,
		IngressIPLimitPerWindow:     1000,
		IngressRouteLimitPerWindow:  1000,
	}

	app, err := New(cfg)
	if err != nil {
		t.Fatalf("app init failed: %v", err)
	}

	issuer, err := jwt.NewManager(cfg.JWTSigningKey, cfg.PublicBaseURL, cfg.Audience)
	if err != nil {
		t.Fatalf("jwt init failed: %v", err)
	}

	// Issue a token with only "profile" scope — should still access everything.
	token := issueTestToken(t, issuer, []string{"profile"})

	// PUT identity key — should succeed (was previously gated by device scope)
	status, body := doJSON(t, app, fiber.MethodPut, "/gateway/v1/devices/dev1/identity-key", map[string]any{
		"algorithm":  "ed25519",
		"public_key": validIdentityKey,
	}, token)
	if status != fiber.StatusNoContent {
		t.Fatalf("expected 204 for identity-key PUT, got %d body=%v", status, body)
	}

	// GET devices
	status, body = doJSON(t, app, fiber.MethodGet, "/gateway/v1/devices", nil, token)
	if status != fiber.StatusOK {
		t.Fatalf("expected 200 for devices list, got %d body=%v", status, body)
	}
	if _, ok := body["devices"]; !ok {
		t.Fatalf("expected devices key in response, got %v", body)
	}

	// POST share invite
	status, body = doJSON(t, app, fiber.MethodPost, "/gateway/v1/shares/invites", map[string]any{
		"deviceId": "dev1",
		"email":    "invitee@example.com",
	}, token)
	if status != fiber.StatusCreated {
		t.Fatalf("expected 201 for share invite, got %d body=%v", status, body)
	}

	// POST integration route
	status, body = doJSON(t, app, fiber.MethodPost, "/gateway/v1/integrations/routes", map[string]any{
		"device_id":      "dev1",
		"interface_type": "http",
	}, token)
	if status != fiber.StatusCreated {
		t.Fatalf("expected 201 for integration route, got %d body=%v", status, body)
	}
}

func TestUnauthenticatedRequestsRejected(t *testing.T) {
	cfg := &config.Config{
		Port:                        "8080",
		PublicBaseURL:               "http://localhost:8080",
		AllowOrigins:                []string{"*"},
		RedirectAllowlist:           []string{"http://localhost:61696/callback"},
		FrontendURL:                 "https://example.com",
		JWTSigningKey:               "test-signing-key-that-is-at-least-thirty-two-bytes",
		AccessTokenTTL:              time.Hour,
		AuthCodeTTL:                 5 * time.Minute,
		RefreshTokenTTL:             24 * time.Hour,
		DemoTokenTTL:                time.Hour,
		Audience:                    "commands-gateway",
		StateBackend:                config.StateBackendMemory,
		AuthMode:                    config.AuthModeDemo,
		IngressRateWindowSeconds:    60,
		IngressGlobalLimitPerWindow: 1000,
		IngressIPLimitPerWindow:     1000,
		IngressRouteLimitPerWindow:  1000,
	}

	app, err := New(cfg)
	if err != nil {
		t.Fatalf("app init failed: %v", err)
	}

	endpoints := []struct {
		method string
		path   string
	}{
		{fiber.MethodGet, "/gateway/v1/devices"},
		{fiber.MethodPut, "/gateway/v1/devices/dev1/identity-key"},
		{fiber.MethodPost, "/gateway/v1/shares/invites"},
		{fiber.MethodPost, "/gateway/v1/integrations/routes"},
	}

	for _, ep := range endpoints {
		status, _ := doJSON(t, app, ep.method, ep.path, nil, "")
		if status != fiber.StatusUnauthorized {
			t.Fatalf("expected 401 for unauthenticated %s %s, got %d", ep.method, ep.path, status)
		}
	}
}

func issueTestToken(t *testing.T, jm *jwt.Manager, scopes []string) string {
	t.Helper()
	token, _, err := jm.IssueAccessToken("user-scope-test", "scope@example.com", "Scope Test", scopes, "demo", time.Hour)
	if err != nil {
		t.Fatalf("issue token failed: %v", err)
	}
	return token
}

func doJSON(t *testing.T, app *fiber.App, method, path string, payload map[string]any, token string) (int, map[string]any) {
	t.Helper()
	var raw []byte
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload failed: %v", err)
		}
		raw = encoded
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test failed: %v", err)
	}
	defer resp.Body.Close()

	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body == nil {
		body = map[string]any{}
	}
	return resp.StatusCode, body
}
