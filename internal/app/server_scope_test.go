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

func TestGatewayScopeEnforcement(t *testing.T) {
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

	tokenShare := issueTestToken(t, issuer, []string{"gateway:share"})
	tokenSession := issueTestToken(t, issuer, []string{"gateway:session"})
	tokenDevice := issueTestToken(t, issuer, []string{"device"})

	status, body := doJSON(t, app, fiber.MethodPost, "/gateway/v1/sessions/scope-test/messages", map[string]any{"message_id": "m-1"}, tokenShare)
	if status == fiber.StatusForbidden && body["error"] == "insufficient_scope" {
		t.Fatalf("did not expect scope gate on session endpoint, got %d body=%v", status, body)
	}

	status, body = doJSON(t, app, fiber.MethodPut, "/gateway/v1/devices/devscope1/identity-key", map[string]any{
		"algorithm":  "ed25519",
		"public_key": validIdentityKey,
	}, tokenSession)
	if status != fiber.StatusForbidden {
		t.Fatalf("expected 403 for missing device scope, got %d body=%v", status, body)
	}
	if body["error"] != "insufficient_scope" {
		t.Fatalf("expected insufficient_scope for device endpoint, got %v", body)
	}

	status, body = doJSON(t, app, fiber.MethodGet, "/gateway/v1/devices", nil, tokenShare)
	if status != fiber.StatusOK {
		t.Fatalf("expected authenticated token to list devices, got %d body=%v", status, body)
	}

	status, body = doJSON(t, app, fiber.MethodPut, "/gateway/v1/devices/devscope1/identity-key", map[string]any{
		"algorithm":  "ed25519",
		"public_key": validIdentityKey,
	}, tokenDevice)
	if status != fiber.StatusNoContent {
		t.Fatalf("expected device-scoped token to pass, got %d body=%v", status, body)
	}

	status, body = doJSON(t, app, fiber.MethodGet, "/gateway/v1/devices", nil, tokenSession)
	if status != fiber.StatusOK {
		t.Fatalf("expected session-scoped token to list devices, got %d body=%v", status, body)
	}
	if _, ok := body["devices"]; !ok {
		t.Fatalf("expected devices list response body, got %v", body)
	}

	status, body = doJSON(t, app, fiber.MethodPost, "/gateway/v1/shares/invites", map[string]any{
		"deviceId": "devscope1",
		"email":    "invitee@example.com",
	}, tokenSession)
	if status != fiber.StatusCreated {
		t.Fatalf("expected authenticated token to create share invite, got %d body=%v", status, body)
	}

	status, body = doJSON(t, app, fiber.MethodPost, "/gateway/v1/integrations/routes", map[string]any{
		"device_id":      "devscope1",
		"interface_type": "http",
	}, tokenShare)
	if status != fiber.StatusCreated {
		t.Fatalf("expected authenticated token to create integration route, got %d body=%v", status, body)
	}

	status, body = doJSON(t, app, fiber.MethodPost, "/gateway/v1/integrations/routes", map[string]any{
		"device_id":      "devscope1",
		"interface_type": "http",
	}, tokenSession)
	if status != fiber.StatusCreated {
		t.Fatalf("expected session-scoped token to create integration route, got %d body=%v", status, body)
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
