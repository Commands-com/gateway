package oauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"oss-commands-gateway/internal/config"
	"oss-commands-gateway/internal/httputil"
	"oss-commands-gateway/internal/idtoken"
)

func (h *Handler) Authorize(c fiber.Ctx) error {
	req := parseAuthorizeRequest(c)
	if req.ResponseType == "" {
		req.ResponseType = "code"
	}
	if req.ResponseType != "code" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "unsupported response_type"})
	}
	if req.ClientID == "" {
		req.ClientID = h.cfg.OAuthDefaultClientID
	}
	if req.RedirectURI == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "redirect_uri is required"})
	}
	if !h.isRedirectAllowed(req.RedirectURI) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "redirect_uri not allowed"})
	}

	identity, rendered, err := h.resolveIdentity(c, req)
	if rendered {
		return err
	}
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	// Enforce PKCE: code_challenge is mandatory for all clients.
	codeChallenge := strings.TrimSpace(req.CodeChallenge)
	if codeChallenge == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_request", "error_description": "code_challenge is required (PKCE)"})
	}
	challengeMethod, methodErr := normalizeChallengeMethod(req.CodeChallengeMethod)
	if methodErr != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_request", "error_description": methodErr.Error()})
	}

	code, err := httputil.RandomToken(32)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate authorization code"})
	}

	h.store.putAuthCode(code, authorizationCodeRecord{
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scope:               normalizeScope(req.Scope),
		State:               req.State,
		Subject:             identity.UID,
		Email:               identity.Email,
		DisplayName:         identity.DisplayName,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: challengeMethod,
	}, h.cfg.AuthCodeTTL)

	if strings.HasPrefix(req.RedirectURI, "urn:") || strings.EqualFold(req.ResponseMode, "json") || wantsJSON(c) {
		return c.JSON(fiber.Map{
			"code":             code,
			"state":            req.State,
			"redirect_uri":     req.RedirectURI,
			"expires_in":       int64(h.cfg.AuthCodeTTL.Seconds()),
			"code_challenge":   codeChallenge,
			"challenge_method": challengeMethod,
		})
	}

	redirect, err := appendQuery(req.RedirectURI, map[string]string{
		"code":  code,
		"state": req.State,
	})
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid redirect_uri"})
	}
	return c.Redirect().Status(fiber.StatusFound).To(redirect)
}

func (h *Handler) resolveIdentity(c fiber.Ctx, req authorizeRequest) (*idtoken.Identity, bool, error) {
	switch h.cfg.AuthMode {
	case config.AuthModeDemo:
		uid := strings.Clone(strings.TrimSpace(c.FormValue("demo_uid")))
		email := strings.Clone(strings.TrimSpace(c.FormValue("demo_email")))
		name := strings.Clone(strings.TrimSpace(c.FormValue("demo_name")))
		if uid == "" && email == "" && name == "" && c.Method() == fiber.MethodGet {
			_ = c.Type("html")
			return nil, true, c.SendString(renderDemoLogin(req))
		}
		if email != "" {
			// Always derive UID from email when available so the same
			// human gets the same UID regardless of whether the caller
			// also sends demo_uid.
			uid = demoDeterministicUID(email, h.cfg.JWTSigningKey)
		} else if uid == "" {
			uid = "demo-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
		}
		if name == "" {
			name = firstNonEmpty(email, uid)
		}
		return &idtoken.Identity{UID: uid, Email: email, DisplayName: name}, false, nil
	case config.AuthModeFirebase, config.AuthModeOIDC:
		rawIDToken := strings.Clone(firstNonEmpty(
			httputil.BearerToken(c.Get("Authorization")),
			strings.TrimSpace(c.FormValue("id_token")),
			strings.TrimSpace(c.FormValue("firebase_token")),
		))
		if rawIDToken == "" && c.Method() == fiber.MethodGet {
			_ = c.Type("html")
			if h.cfg.FirebaseAPIKey != "" && h.cfg.FirebaseProjectID != "" {
				return nil, true, c.SendString(renderFirebaseLogin(req, h.cfg.FirebaseAPIKey, h.cfg.FirebaseProjectID))
			}
			return nil, true, c.SendString(renderIDTokenForm(req, string(h.cfg.AuthMode)))
		}
		if rawIDToken == "" {
			return nil, false, fmt.Errorf("id token is required")
		}
		if h.idVerify == nil {
			return nil, false, fmt.Errorf("identity verifier is not configured")
		}
		identity, err := h.idVerify.Verify(c.Context(), rawIDToken)
		if err != nil {
			return nil, false, fmt.Errorf("id token verification failed")
		}
		if identity.UID == "" {
			return nil, false, fmt.Errorf("token missing subject")
		}
		if identity.DisplayName == "" {
			identity.DisplayName = firstNonEmpty(identity.Email, identity.UID)
		}
		return identity, false, nil
	default:
		return nil, false, fmt.Errorf("unsupported auth mode")
	}
}

func parseAuthorizeRequest(c fiber.Ctx) authorizeRequest {
	// Clone strings: Fiber/fasthttp returns values backed by a reusable
	// request buffer.  Any value stored beyond the handler lifetime (e.g.
	// in the auth-code record) must be an independent copy.
	read := func(key string) string {
		if v := strings.TrimSpace(c.Query(key)); v != "" {
			return strings.Clone(v)
		}
		return strings.Clone(strings.TrimSpace(c.FormValue(key)))
	}
	return authorizeRequest{
		ResponseType:        read("response_type"),
		ClientID:            read("client_id"),
		RedirectURI:         read("redirect_uri"),
		Scope:               read("scope"),
		State:               read("state"),
		CodeChallenge:       read("code_challenge"),
		CodeChallengeMethod: read("code_challenge_method"),
		ResponseMode:        read("response_mode"),
	}
}

func (h *Handler) isRedirectAllowed(candidate string) bool {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return false
	}
	candidateURL, err := url.Parse(candidate)
	if err != nil {
		return false
	}
	if candidateURL.User != nil {
		return false
	}
	if len(h.cfg.RedirectAllowlist) == 0 {
		return true
	}
	for _, allowed := range h.cfg.RedirectAllowlist {
		allowed = strings.TrimSpace(allowed)
		if allowed == candidate {
			return true
		}
		if loopbackRedirectPortMatch(candidateURL, allowed) {
			return true
		}
	}
	return false
}

func loopbackRedirectPortMatch(candidate *url.URL, allowedRaw string) bool {
	if candidate == nil || !isLoopbackHTTPRedirect(candidate) {
		return false
	}
	if candidate.Port() == "" {
		return false
	}

	allowedURL, err := url.Parse(strings.TrimSpace(allowedRaw))
	if err != nil {
		return false
	}
	if allowedURL.User != nil || !isLoopbackHTTPRedirect(allowedURL) {
		return false
	}

	// For native-app loopback callbacks, allow ephemeral ports but pin path/query.
	if candidate.Path != allowedURL.Path {
		return false
	}
	if candidate.RawQuery != allowedURL.RawQuery {
		return false
	}
	return true
}

func isLoopbackHTTPRedirect(u *url.URL) bool {
	if u == nil {
		return false
	}
	if !strings.EqualFold(u.Scheme, "http") {
		return false
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func normalizeScope(scope string) string {
	clean := strings.Fields(strings.TrimSpace(scope))
	if len(clean) == 0 {
		return "openid profile email device"
	}
	return strings.Join(clean, " ")
}

func normalizeChallengeMethod(method string) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "S256":
		return "S256", nil
	case "PLAIN", "":
		return "plain", nil
	default:
		return "", fmt.Errorf("unsupported code_challenge_method: %s", method)
	}
}

func verifyPKCE(challenge, method, verifier string) error {
	challenge = strings.TrimSpace(challenge)
	if challenge == "" {
		return fmt.Errorf("code_challenge is required")
	}
	verifier = strings.TrimSpace(verifier)
	if verifier == "" {
		return fmt.Errorf("code_verifier is required")
	}
	normalizedMethod, err := normalizeChallengeMethod(method)
	if err != nil {
		return err
	}
	switch normalizedMethod {
	case "plain":
		if verifier != challenge {
			return fmt.Errorf("pkce mismatch")
		}
	case "S256":
		sum := sha256.Sum256([]byte(verifier))
		derived := base64.RawURLEncoding.EncodeToString(sum[:])
		if derived != challenge {
			return fmt.Errorf("pkce mismatch")
		}
	default:
		return fmt.Errorf("unsupported code_challenge_method")
	}
	return nil
}

func appendQuery(rawURL string, updates map[string]string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k, v := range updates {
		if strings.TrimSpace(v) == "" {
			continue
		}
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func wantsJSON(c fiber.Ctx) bool {
	return strings.Contains(strings.ToLower(c.Get(fiber.HeaderAccept)), "application/json")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// demoDeterministicUID derives a stable UID from email so the same human gets
// the same UID regardless of which OAuth flow they use. Uses HMAC-SHA256 keyed
// with the server secret to prevent offline email enumeration.
func demoDeterministicUID(email, secret string) string {
	canonical := strings.TrimSpace(strings.ToLower(email))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonical))
	return "demo-" + hex.EncodeToString(mac.Sum(nil))[:16]
}
