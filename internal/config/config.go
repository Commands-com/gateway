package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type AuthMode string

type StateBackend string

const (
	AuthModeDemo     AuthMode = "demo"
	AuthModeFirebase AuthMode = "firebase"
	AuthModeOIDC     AuthMode = "oidc"

	StateBackendMemory StateBackend = "memory"
)

type Config struct {
	Port              string
	PublicBaseURL     string
	AllowOrigins      []string
	RedirectAllowlist []string
	FrontendURL       string
	NodeID            string

	JWTSigningKey    string
	AccessTokenTTL   time.Duration
	AuthCodeTTL      time.Duration
	RefreshTokenTTL  time.Duration
	DemoTokenTTL     time.Duration
	Audience         string
	StateBackend     StateBackend
	AuthMode         AuthMode
	DemoAuthDisabled bool

	OAuthDefaultClientID string
	OAuthClientName      string
	OAuthRedirectURIs    []string

	ProxyHeader string

	IngressRateWindowSeconds    int
	IngressGlobalLimitPerWindow int
	IngressIPLimitPerWindow     int
	IngressRouteLimitPerWindow  int
	IdempotencyTTLSeconds       int

	RequireEncryptedFrames bool
	TransportTokenSecret   string
	TransportTokenTTL      time.Duration

	FirebaseProjectID       string
	FirebaseCredentialsPath string
	FirebaseAPIKey          string

	OIDCIssuerURL string
	OIDCClientID  string
}

func Load() (*Config, error) {
	defaultRedirects := []string{
		"http://localhost:61696/callback",
		"http://localhost:3000/callback",
		"urn:ietf:wg:oauth:2.0:oob",
	}

	cfg := &Config{
		Port:              envOrDefault("PORT", "8080"),
		PublicBaseURL:     strings.TrimSpace(os.Getenv("PUBLIC_BASE_URL")),
		AllowOrigins:      csvOrDefault("ALLOW_ORIGINS", []string{"*"}),
		RedirectAllowlist: csvOrDefault("REDIRECT_ALLOWLIST", defaultRedirects),
		FrontendURL:       envOrDefault("FRONTEND_URL", "https://example.com"),
		NodeID:            envOrDefault("NODE_ID", ""),

		JWTSigningKey:   strings.TrimSpace(os.Getenv("JWT_SIGNING_KEY")),
		AccessTokenTTL:  durationFromSeconds("ACCESS_TOKEN_TTL_SECONDS", 3600),
		AuthCodeTTL:     durationFromSeconds("AUTH_CODE_TTL_SECONDS", 300),
		RefreshTokenTTL: durationFromSeconds("REFRESH_TOKEN_TTL_SECONDS", 2592000),
		DemoTokenTTL:    durationFromSeconds("DEMO_TOKEN_TTL_SECONDS", 3600),
		Audience:        envOrDefault("JWT_AUDIENCE", "commands-gateway"),
		StateBackend:    StateBackend(strings.ToLower(envOrDefault("STATE_BACKEND", string(StateBackendMemory)))),

		AuthMode:         AuthMode(strings.ToLower(envOrDefault("AUTH_MODE", "demo"))),
		DemoAuthDisabled: envBool("DEMO_AUTH_DISABLED", false),

		OAuthDefaultClientID: envOrDefault("OAUTH_DEFAULT_CLIENT_ID", "oss-gateway-public-client"),
		OAuthClientName:      envOrDefault("OAUTH_CLIENT_NAME", "OSS Gateway"),
		OAuthRedirectURIs:    csvOrDefault("OAUTH_REDIRECT_URIS", nil),

		ProxyHeader: strings.TrimSpace(os.Getenv("PROXY_HEADER")),

		IngressRateWindowSeconds:    intFromEnv("INGRESS_RATE_WINDOW_SECONDS", 60, 1, 3600),
		IngressGlobalLimitPerWindow: intFromEnv("INGRESS_GLOBAL_LIMIT_PER_WINDOW", 3000, 1, 1000000),
		IngressIPLimitPerWindow:     intFromEnv("INGRESS_IP_LIMIT_PER_WINDOW", 600, 1, 100000),
		IngressRouteLimitPerWindow:  intFromEnv("INGRESS_ROUTE_LIMIT_PER_WINDOW", 300, 1, 100000),
		IdempotencyTTLSeconds:       intFromEnv("IDEMPOTENCY_TTL_SECONDS", 300, 30, 86400),

		RequireEncryptedFrames: envBool("REQUIRE_ENCRYPTED_FRAMES", true),
		TransportTokenSecret:   strings.TrimSpace(os.Getenv("TRANSPORT_TOKEN_SECRET")),
		TransportTokenTTL:      durationFromSeconds("TRANSPORT_TOKEN_TTL_SECONDS", 3600),

		FirebaseProjectID:       strings.TrimSpace(os.Getenv("FIREBASE_PROJECT_ID")),
		FirebaseCredentialsPath: strings.TrimSpace(os.Getenv("FIREBASE_CREDENTIALS_PATH")),
		FirebaseAPIKey:          strings.TrimSpace(os.Getenv("FIREBASE_API_KEY")),

		OIDCIssuerURL: strings.TrimSpace(os.Getenv("OIDC_ISSUER_URL")),
		OIDCClientID:  strings.TrimSpace(os.Getenv("OIDC_CLIENT_ID")),
	}

	if len(cfg.OAuthRedirectURIs) == 0 {
		cfg.OAuthRedirectURIs = append([]string(nil), cfg.RedirectAllowlist...)
	}
	if cfg.TransportTokenSecret == "" {
		// Derive a separate secret from JWTSigningKey so transport tokens and
		// JWTs use independent key material even when only one env var is set.
		mac := hmac.New(sha256.New, []byte(cfg.JWTSigningKey))
		mac.Write([]byte("transport-token-secret"))
		cfg.TransportTokenSecret = hex.EncodeToString(mac.Sum(nil))
	}

	if cfg.PublicBaseURL == "" {
		railwayDomain := strings.TrimSpace(os.Getenv("RAILWAY_PUBLIC_DOMAIN"))
		if railwayDomain != "" {
			cfg.PublicBaseURL = "https://" + railwayDomain
		} else {
			cfg.PublicBaseURL = "http://localhost:" + cfg.Port
		}
	}
	cfg.PublicBaseURL = strings.TrimRight(cfg.PublicBaseURL, "/")

	// Always allow the built-in console as an OAuth redirect target.
	consoleURI := cfg.PublicBaseURL + "/console"
	hasConsole := false
	for _, u := range cfg.RedirectAllowlist {
		if strings.TrimSpace(u) == consoleURI {
			hasConsole = true
			break
		}
	}
	if !hasConsole {
		cfg.RedirectAllowlist = append(cfg.RedirectAllowlist, consoleURI)
	}

	if strings.TrimSpace(cfg.NodeID) == "" {
		host, _ := os.Hostname()
		host = strings.TrimSpace(host)
		if host == "" {
			host = "node"
		}
		cfg.NodeID = fmt.Sprintf("%s-%d", host, os.Getpid())
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) Validate() error {
	if c.JWTSigningKey == "" {
		return fmt.Errorf("JWT_SIGNING_KEY is required")
	}
	if len([]byte(c.JWTSigningKey)) < 32 {
		return fmt.Errorf("JWT_SIGNING_KEY must be at least 32 bytes")
	}
	if strings.TrimSpace(c.NodeID) == "" {
		return fmt.Errorf("NODE_ID must not be empty")
	}

	if c.StateBackend == "" {
		c.StateBackend = StateBackendMemory
	}
	if c.StateBackend != StateBackendMemory {
		return fmt.Errorf("unsupported STATE_BACKEND=%q (only \"memory\" is supported)", c.StateBackend)
	}
	if c.IngressRateWindowSeconds <= 0 {
		return fmt.Errorf("INGRESS_RATE_WINDOW_SECONDS must be > 0")
	}
	if c.IngressGlobalLimitPerWindow <= 0 || c.IngressIPLimitPerWindow <= 0 || c.IngressRouteLimitPerWindow <= 0 {
		return fmt.Errorf("ingress rate limits must be > 0")
	}
	if c.IdempotencyTTLSeconds <= 0 {
		return fmt.Errorf("IDEMPOTENCY_TTL_SECONDS must be > 0")
	}
	if c.TransportTokenTTL <= 0 {
		return fmt.Errorf("TRANSPORT_TOKEN_TTL_SECONDS must be > 0")
	}

	c.OAuthDefaultClientID = strings.TrimSpace(c.OAuthDefaultClientID)
	if c.OAuthDefaultClientID == "" {
		return fmt.Errorf("OAUTH_DEFAULT_CLIENT_ID is required")
	}
	c.OAuthClientName = strings.TrimSpace(c.OAuthClientName)
	if c.OAuthClientName == "" {
		return fmt.Errorf("OAUTH_CLIENT_NAME is required")
	}
	if len(c.OAuthRedirectURIs) == 0 {
		return fmt.Errorf("at least one OAuth redirect URI is required")
	}

	switch c.AuthMode {
	case AuthModeDemo:
		if c.DemoAuthDisabled {
			return fmt.Errorf("AUTH_MODE=demo but DEMO_AUTH_DISABLED=true")
		}
	case AuthModeFirebase:
		if c.FirebaseProjectID == "" {
			return fmt.Errorf("FIREBASE_PROJECT_ID is required when AUTH_MODE=firebase")
		}
	case AuthModeOIDC:
		if c.OIDCIssuerURL == "" || c.OIDCClientID == "" {
			return fmt.Errorf("OIDC_ISSUER_URL and OIDC_CLIENT_ID are required when AUTH_MODE=oidc")
		}
	default:
		return fmt.Errorf("unsupported AUTH_MODE=%q", c.AuthMode)
	}

	return nil
}

func envOrDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return parsed
}

func durationFromSeconds(key string, fallbackSeconds int) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return time.Duration(fallbackSeconds) * time.Second
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return time.Duration(fallbackSeconds) * time.Second
	}
	return time.Duration(n) * time.Second
}

func intFromEnv(key string, fallback, min, max int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

func csvOrDefault(key string, fallback []string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return append([]string(nil), fallback...)
	}
	parts := strings.Split(raw, ",")
	clean := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			clean = append(clean, v)
		}
	}
	if len(clean) == 0 {
		return append([]string(nil), fallback...)
	}
	return clean
}
