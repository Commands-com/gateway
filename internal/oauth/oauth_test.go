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
	}
	jm, err := jwt.NewManager("test-signing-secret", cfg.PublicBaseURL, cfg.Audience)
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
