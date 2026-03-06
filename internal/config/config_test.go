package config

import (
	"testing"
	"time"
)

func TestValidateRequiresJWTSigningKey(t *testing.T) {
	cfg := &Config{
		AuthMode:         AuthModeDemo,
		StateBackend:     StateBackendMemory,
		NodeID:           "test",
		OAuthDefaultClientID: "client",
		OAuthClientName:      "name",
		OAuthRedirectURIs:    []string{"http://localhost/cb"},
		IngressRateWindowSeconds:    60,
		IngressGlobalLimitPerWindow: 100,
		IngressIPLimitPerWindow:     50,
		IngressRouteLimitPerWindow:  25,
		IdempotencyTTLSeconds:       300,
		TransportTokenTTL:           time.Hour,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing JWT signing key")
	}
}

func TestValidateRequiresMinKeyLength(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    "short",
		AuthMode:         AuthModeDemo,
		StateBackend:     StateBackendMemory,
		NodeID:           "test",
		OAuthDefaultClientID: "client",
		OAuthClientName:      "name",
		OAuthRedirectURIs:    []string{"http://localhost/cb"},
		IngressRateWindowSeconds:    60,
		IngressGlobalLimitPerWindow: 100,
		IngressIPLimitPerWindow:     50,
		IngressRouteLimitPerWindow:  25,
		IdempotencyTTLSeconds:       300,
		TransportTokenTTL:           time.Hour,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for short JWT signing key")
	}
}

func TestValidateAcceptsValidConfig(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    "this-is-a-valid-signing-key-with-32b",
		AuthMode:         AuthModeDemo,
		StateBackend:     StateBackendMemory,
		NodeID:           "test-node",
		OAuthDefaultClientID: "client-id",
		OAuthClientName:      "Test App",
		OAuthRedirectURIs:    []string{"http://localhost/cb"},
		IngressRateWindowSeconds:    60,
		IngressGlobalLimitPerWindow: 100,
		IngressIPLimitPerWindow:     50,
		IngressRouteLimitPerWindow:  25,
		IdempotencyTTLSeconds:       300,
		TransportTokenTTL:           time.Hour,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRejectsUnsupportedStateBackend(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    "this-is-a-valid-signing-key-with-32b",
		AuthMode:         AuthModeDemo,
		StateBackend:     "redis",
		NodeID:           "test-node",
		OAuthDefaultClientID: "client-id",
		OAuthClientName:      "Test App",
		OAuthRedirectURIs:    []string{"http://localhost/cb"},
		IngressRateWindowSeconds:    60,
		IngressGlobalLimitPerWindow: 100,
		IngressIPLimitPerWindow:     50,
		IngressRouteLimitPerWindow:  25,
		IdempotencyTTLSeconds:       300,
		TransportTokenTTL:           time.Hour,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for unsupported state backend")
	}
}

func TestValidateRejectsFirebaseWithoutProjectID(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    "this-is-a-valid-signing-key-with-32b",
		AuthMode:         AuthModeFirebase,
		StateBackend:     StateBackendMemory,
		NodeID:           "test-node",
		OAuthDefaultClientID: "client-id",
		OAuthClientName:      "Test App",
		OAuthRedirectURIs:    []string{"http://localhost/cb"},
		IngressRateWindowSeconds:    60,
		IngressGlobalLimitPerWindow: 100,
		IngressIPLimitPerWindow:     50,
		IngressRouteLimitPerWindow:  25,
		IdempotencyTTLSeconds:       300,
		TransportTokenTTL:           time.Hour,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for firebase without project ID")
	}
}

func TestValidateRejectsOIDCWithoutIssuer(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    "this-is-a-valid-signing-key-with-32b",
		AuthMode:         AuthModeOIDC,
		StateBackend:     StateBackendMemory,
		NodeID:           "test-node",
		OAuthDefaultClientID: "client-id",
		OAuthClientName:      "Test App",
		OAuthRedirectURIs:    []string{"http://localhost/cb"},
		IngressRateWindowSeconds:    60,
		IngressGlobalLimitPerWindow: 100,
		IngressIPLimitPerWindow:     50,
		IngressRouteLimitPerWindow:  25,
		IdempotencyTTLSeconds:       300,
		TransportTokenTTL:           time.Hour,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for OIDC without issuer")
	}
}
