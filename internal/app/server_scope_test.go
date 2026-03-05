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
	if status != fiber.StatusForbidden {
		t.Fatalf("expected 403 for missing session scope, got %d body=%v", status, body)
	}
	if body["error"] != "insufficient_scope" {
		t.Fatalf("expected insufficient_scope for session endpoint, got %v", body)
	}

	status, body = doJSON(t, app, fiber.MethodPost, "/gateway/v1/shares/invites", map[string]any{"deviceId": "d1", "email": "a@example.com"}, tokenSession)
	if status != fiber.StatusForbidden {
		t.Fatalf("expected 403 for missing share scope, got %d body=%v", status, body)
	}
	if body["error"] != "insufficient_scope" {
		t.Fatalf("expected insufficient_scope for share endpoint, got %v", body)
	}

	status, body = doJSON(t, app, fiber.MethodPut, "/gateway/v1/devices/devscope1/identity-key", map[string]any{"identityKey": "pub"}, tokenSession)
	if status != fiber.StatusForbidden {
		t.Fatalf("expected 403 for missing device scope, got %d body=%v", status, body)
	}
	if body["error"] != "insufficient_scope" {
		t.Fatalf("expected insufficient_scope for device endpoint, got %v", body)
	}

	status, body = doJSON(t, app, fiber.MethodPut, "/gateway/v1/devices/devscope1/identity-key", map[string]any{"identityKey": "pub"}, tokenDevice)
	if status != fiber.StatusOK {
		t.Fatalf("expected device-scoped token to pass, got %d body=%v", status, body)
	}
	if body["deviceId"] != "devscope1" {
		t.Fatalf("expected deviceId=devscope1, got %v", body)
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
