package jwt

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestNewManagerRejectsEmptySecret(t *testing.T) {
	_, err := NewManager("", "iss", "aud")
	if err == nil {
		t.Fatal("expected error for empty secret")
	}
}

func TestNewManagerRejectsWhitespaceSecret(t *testing.T) {
	_, err := NewManager("   ", "iss", "aud")
	if err == nil {
		t.Fatal("expected error for whitespace-only secret")
	}
}

func TestIssueAndParseAccessToken(t *testing.T) {
	m, err := NewManager("test-secret-that-is-at-least-32bytes!", "iss", "aud")
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	raw, expiresIn, err := m.IssueAccessToken("user1", "u@example.com", "User One", []string{"device", "gateway:session"}, "demo", time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	if expiresIn != 3600 {
		t.Fatalf("expected expiresIn=3600, got %d", expiresIn)
	}
	if raw == "" {
		t.Fatal("expected non-empty token")
	}

	claims, err := m.ParseAccessToken(raw)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	if claims.Subject != "user1" {
		t.Errorf("subject: got %q want %q", claims.Subject, "user1")
	}
	if claims.Email != "u@example.com" {
		t.Errorf("email: got %q want %q", claims.Email, "u@example.com")
	}
	if claims.Name != "User One" {
		t.Errorf("name: got %q want %q", claims.Name, "User One")
	}
	if claims.Scope != "device gateway:session" {
		t.Errorf("scope: got %q", claims.Scope)
	}
	if claims.AuthMode != "demo" {
		t.Errorf("auth_mode: got %q want %q", claims.AuthMode, "demo")
	}
}

func TestParseAccessTokenRejectsTamperedToken(t *testing.T) {
	m, err := NewManager("test-secret-that-is-at-least-32bytes!", "iss", "aud")
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	raw, _, err := m.IssueAccessToken("user1", "u@example.com", "", nil, "demo", time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	tampered := raw + "x"
	if _, err := m.ParseAccessToken(tampered); err == nil {
		t.Fatal("expected error for tampered token")
	}
}

func TestParseAccessTokenRejectsWrongAudience(t *testing.T) {
	m1, _ := NewManager("test-secret-that-is-at-least-32bytes!", "iss", "aud1")
	m2, _ := NewManager("test-secret-that-is-at-least-32bytes!", "iss", "aud2")

	raw, _, _ := m1.IssueAccessToken("user1", "", "", nil, "demo", time.Hour)
	if _, err := m2.ParseAccessToken(raw); err == nil {
		t.Fatal("expected error for wrong audience")
	}
}

func TestJWKSReturnsExpectedFields(t *testing.T) {
	m, _ := NewManager("test-secret-that-is-at-least-32bytes!", "iss", "aud")
	jwks := m.JWKS()
	keys, ok := jwks["keys"].([]map[string]any)
	if !ok || len(keys) != 1 {
		t.Fatal("expected exactly one key in JWKS")
	}
	key := keys[0]
	if key["kty"] != "OKP" {
		t.Errorf("kty: got %v", key["kty"])
	}
	if key["crv"] != "Ed25519" {
		t.Errorf("crv: got %v", key["crv"])
	}
	if key["alg"] != "EdDSA" {
		t.Errorf("alg: got %v", key["alg"])
	}
	if key["use"] != "sig" {
		t.Errorf("use: got %v", key["use"])
	}
}

// TestKeyDerivationStability ensures the HKDF-based key derivation produces a
// stable public key for a given secret. Changing the KDF parameters would
// invalidate all previously issued tokens — this test catches that.
func TestKeyDerivationStability(t *testing.T) {
	m, err := NewManager("pinned-test-secret-for-stability-check", "iss", "aud")
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	pubB64 := base64.RawURLEncoding.EncodeToString(m.publicKey)

	// This value was computed once from the current KDF and pinned here.
	// If this test fails, it means the key derivation changed and all
	// previously issued JWTs will stop verifying.
	const pinnedPublicKey = "KUN3ntkihB9TYDA1G8QHbjOMw-44rWFpD5V4Wb6jQFA"

	if pubB64 != pinnedPublicKey {
		t.Fatalf("key derivation changed!\ngot:  %s\nwant: %s\nThis will invalidate all previously issued JWTs.", pubB64, pinnedPublicKey)
	}
}
