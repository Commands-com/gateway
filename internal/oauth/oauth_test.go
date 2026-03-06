package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"oss-commands-gateway/internal/config"
	"oss-commands-gateway/internal/jwt"
)

func TestAuthorizationCodeAndRefreshFlow(t *testing.T) {
	app := newDemoOAuthTestApp(t)

	authorizeValues := url.Values{}
	authorizeValues.Set("response_type", "code")
	authorizeValues.Set("client_id", "desktop-client")
	authorizeValues.Set("redirect_uri", "http://localhost:61696/callback")
	authorizeValues.Set("scope", "openid gateway:session")
	authorizeValues.Set("state", "st-123")
	authorizeValues.Set("code_challenge", "verifier-123")
	authorizeValues.Set("code_challenge_method", "plain")
	authorizeValues.Set("response_mode", "json")
	authorizeValues.Set("demo_email", "alice@example.com")
	authorizeValues.Set("demo_name", "Alice")

	authResp := mustDoForm(t, app, "POST", "/oauth/authorize", authorizeValues, fiber.StatusOK)
	code, _ := authResp["code"].(string)
	if code == "" {
		t.Fatalf("expected authorization code in response")
	}

	tokenValues := url.Values{}
	tokenValues.Set("grant_type", "authorization_code")
	tokenValues.Set("client_id", "desktop-client")
	tokenValues.Set("code", code)
	tokenValues.Set("redirect_uri", "http://localhost:61696/callback")
	tokenValues.Set("code_verifier", "verifier-123")

	tokenResp := mustDoForm(t, app, "POST", "/oauth/token", tokenValues, fiber.StatusOK)
	accessToken, _ := tokenResp["access_token"].(string)
	refreshToken, _ := tokenResp["refresh_token"].(string)
	if accessToken == "" || refreshToken == "" {
		t.Fatalf("expected access and refresh tokens in exchange response")
	}

	refreshValues := url.Values{}
	refreshValues.Set("grant_type", "refresh_token")
	refreshValues.Set("refresh_token", refreshToken)
	refreshResp := mustDoForm(t, app, "POST", "/oauth/token", refreshValues, fiber.StatusOK)
	if token, _ := refreshResp["access_token"].(string); token == "" {
		t.Fatalf("expected access_token on refresh flow")
	}

	revokeValues := url.Values{}
	revokeValues.Set("token", refreshToken)
	mustDoForm(t, app, "POST", "/oauth/token/revoke", revokeValues, fiber.StatusOK)

	mustDoForm(t, app, "POST", "/oauth/token", refreshValues, fiber.StatusBadRequest)
}

func TestAuthorizeRejectsDisallowedRedirectURI(t *testing.T) {
	app := newDemoOAuthTestApp(t)

	values := url.Values{}
	values.Set("response_type", "code")
	values.Set("client_id", "desktop-client")
	values.Set("redirect_uri", "http://not-allowed/callback")
	values.Set("response_mode", "json")
	values.Set("demo_email", "alice@example.com")

	resp := mustDoForm(t, app, "POST", "/oauth/authorize", values, fiber.StatusBadRequest)
	if resp["error"] != "redirect_uri not allowed" {
		t.Fatalf("expected redirect_uri validation error, got %v", resp["error"])
	}
}

func TestAuthorizeAllowsLoopbackRedirectWithEphemeralPort(t *testing.T) {
	app := newDemoOAuthTestApp(t)

	values := url.Values{}
	values.Set("response_type", "code")
	values.Set("client_id", "desktop-client")
	values.Set("redirect_uri", "http://localhost:49152/callback")
	values.Set("response_mode", "json")
	values.Set("code_challenge", "verifier-123")
	values.Set("code_challenge_method", "plain")
	values.Set("demo_email", "alice@example.com")

	resp := mustDoForm(t, app, "POST", "/oauth/authorize", values, fiber.StatusOK)
	if code, _ := resp["code"].(string); code == "" {
		t.Fatalf("expected authorization code in response")
	}
}

func TestAuthorizeRejectsLoopbackRedirectWrongPath(t *testing.T) {
	app := newDemoOAuthTestApp(t)

	values := url.Values{}
	values.Set("response_type", "code")
	values.Set("client_id", "desktop-client")
	values.Set("redirect_uri", "http://localhost:49152/not-callback")
	values.Set("response_mode", "json")
	values.Set("code_challenge", "verifier-123")
	values.Set("code_challenge_method", "plain")
	values.Set("demo_email", "alice@example.com")

	resp := mustDoForm(t, app, "POST", "/oauth/authorize", values, fiber.StatusBadRequest)
	if resp["error"] != "redirect_uri not allowed" {
		t.Fatalf("expected redirect_uri validation error, got %v", resp["error"])
	}
}

func TestDemoDeterministicUID(t *testing.T) {
	secret := "test-signing-secret-at-least-32-bytes-long"

	// Same email produces same UID
	uid1 := demoDeterministicUID("Alice@Example.com", secret)
	uid2 := demoDeterministicUID("alice@example.com", secret)
	if uid1 != uid2 {
		t.Fatalf("expected same UID for case-variant emails, got %q vs %q", uid1, uid2)
	}

	// Whitespace is trimmed
	uid3 := demoDeterministicUID("  alice@example.com  ", secret)
	if uid1 != uid3 {
		t.Fatalf("expected same UID after trimming, got %q vs %q", uid1, uid3)
	}

	// Different emails produce different UIDs
	uid4 := demoDeterministicUID("bob@example.com", secret)
	if uid1 == uid4 {
		t.Fatalf("expected different UIDs for different emails")
	}

	// Different secrets produce different UIDs
	uid5 := demoDeterministicUID("alice@example.com", "different-secret-also-thirty-two-bytes")
	if uid1 == uid5 {
		t.Fatalf("expected different UIDs for different secrets")
	}

	// Prefix is correct
	if !strings.HasPrefix(uid1, "demo-") {
		t.Fatalf("expected demo- prefix, got %q", uid1)
	}

	// Length is stable: "demo-" + 16 hex chars = 21
	if len(uid1) != 21 {
		t.Fatalf("expected UID length 21, got %d (%q)", len(uid1), uid1)
	}
}

func TestDemoEmailUIDStabilityAcrossFlows(t *testing.T) {
	app := newDemoOAuthTestApp(t)

	authorize := func(email string) string {
		values := url.Values{}
		values.Set("response_type", "code")
		values.Set("client_id", "desktop-client")
		values.Set("redirect_uri", "http://localhost:61696/callback")
		values.Set("scope", "openid device")
		values.Set("code_challenge", "test-verifier")
		values.Set("code_challenge_method", "plain")
		values.Set("response_mode", "json")
		values.Set("demo_email", email)
		resp := mustDoForm(t, app, "POST", "/oauth/authorize", values, fiber.StatusOK)

		code, _ := resp["code"].(string)
		if code == "" {
			t.Fatalf("expected code for email %s", email)
		}

		tokenValues := url.Values{}
		tokenValues.Set("grant_type", "authorization_code")
		tokenValues.Set("code", code)
		tokenValues.Set("redirect_uri", "http://localhost:61696/callback")
		tokenValues.Set("code_verifier", "test-verifier")
		tokenResp := mustDoForm(t, app, "POST", "/oauth/token", tokenValues, fiber.StatusOK)

		accessToken, _ := tokenResp["access_token"].(string)
		if accessToken == "" {
			t.Fatalf("expected access_token for email %s", email)
		}
		return accessToken
	}

	// Two authorizations with the same email should produce tokens with the same subject
	token1 := authorize("alice@example.com")
	token2 := authorize("Alice@Example.com")

	cfg := newDemoOAuthTestApp(t) // need jwt manager to parse
	_ = cfg
	// Parse both tokens and verify subjects match
	jm, err := jwt.NewManager("test-signing-secret-at-least-32-bytes-long", "http://localhost:8080", "commands-gateway-test")
	if err != nil {
		t.Fatalf("jwt init: %v", err)
	}
	claims1, err := jm.ParseAccessToken(token1)
	if err != nil {
		t.Fatalf("parse token1: %v", err)
	}
	claims2, err := jm.ParseAccessToken(token2)
	if err != nil {
		t.Fatalf("parse token2: %v", err)
	}
	if claims1.Subject != claims2.Subject {
		t.Fatalf("expected same subject for same email, got %q vs %q", claims1.Subject, claims2.Subject)
	}
	if !strings.HasPrefix(claims1.Subject, "demo-") {
		t.Fatalf("expected demo- prefix on subject, got %q", claims1.Subject)
	}
}

func TestVerifyPKCE(t *testing.T) {
	s256Verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(s256Verifier))
	s256Challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	tests := []struct {
		name      string
		challenge string
		method    string
		verifier  string
		wantErr   bool
	}{
		{name: "plain ok", challenge: "abc", method: "plain", verifier: "abc", wantErr: false},
		{name: "plain mismatch", challenge: "abc", method: "plain", verifier: "def", wantErr: true},
		{name: "s256 ok", challenge: s256Challenge, method: "S256", verifier: s256Verifier, wantErr: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyPKCE(tc.challenge, tc.method, tc.verifier)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected nil error but got %v", err)
			}
		})
	}
}

func newDemoOAuthTestApp(t *testing.T) *fiber.App {
	t.Helper()

	cfg := &config.Config{
		PublicBaseURL:     "http://localhost:8080",
		RedirectAllowlist: []string{"http://localhost:61696/callback", "urn:ietf:wg:oauth:2.0:oob"},
		AuthMode:          config.AuthModeDemo,
		AuthCodeTTL:       5 * time.Minute,
		AccessTokenTTL:    1 * time.Hour,
		RefreshTokenTTL:   24 * time.Hour,
		Audience:          "commands-gateway-test",
		JWTSigningKey:     "test-signing-secret-at-least-32-bytes-long",
	}
	jm, err := jwt.NewManager(cfg.JWTSigningKey, cfg.PublicBaseURL, cfg.Audience)
	if err != nil {
		t.Fatalf("failed to initialize jwt manager: %v", err)
	}

	h := NewHandler(cfg, jm, nil)

	app := fiber.New()
	app.Get("/oauth/authorize", h.Authorize)
	app.Post("/oauth/authorize", h.Authorize)
	app.Post("/oauth/token", h.Token)
	app.Post("/oauth/token/revoke", h.RevokeToken)
	return app
}

func mustDoForm(t *testing.T, app *fiber.App, method, path string, values url.Values, expectedStatus int) map[string]any {
	t.Helper()

	req := httptest.NewRequest(method, path, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test request failed: %v", err)
	}
	defer resp.Body.Close()

	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != expectedStatus {
		t.Fatalf("unexpected status for %s %s: got %d want %d body=%v", method, path, resp.StatusCode, expectedStatus, out)
	}
	if out == nil {
		return map[string]any{}
	}
	return out
}
