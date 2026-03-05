package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"oss-commands-gateway/internal/config"
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

	code, err := randomToken(32)
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
		uid := strings.TrimSpace(c.FormValue("demo_uid"))
		email := strings.TrimSpace(c.FormValue("demo_email"))
		name := strings.TrimSpace(c.FormValue("demo_name"))
		if uid == "" && email == "" && name == "" && c.Method() == fiber.MethodGet {
			_ = c.Type("html")
			return nil, true, c.SendString(renderDemoLogin(req))
		}
		if uid == "" {
			if email != "" {
				uid = strings.ReplaceAll(strings.Split(email, "@")[0], " ", "_")
			} else {
				uid = "demo-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
			}
		}
		if name == "" {
			name = firstNonEmpty(email, uid)
		}
		return &idtoken.Identity{UID: uid, Email: email, DisplayName: name}, false, nil
	case config.AuthModeFirebase, config.AuthModeOIDC:
		rawIDToken := firstNonEmpty(
			bearer(c.Get("Authorization")),
			strings.TrimSpace(c.FormValue("id_token")),
			strings.TrimSpace(c.FormValue("firebase_token")),
		)
		if rawIDToken == "" && c.Method() == fiber.MethodGet {
			_ = c.Type("html")
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
	read := func(key string) string {
		if v := strings.TrimSpace(c.Query(key)); v != "" {
			return v
		}
		return strings.TrimSpace(c.FormValue(key))
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
	if len(h.cfg.RedirectAllowlist) == 0 {
		return true
	}
	for _, allowed := range h.cfg.RedirectAllowlist {
		if strings.TrimSpace(allowed) == candidate {
			return true
		}
	}
	return false
}

func normalizeScope(scope string) string {
	clean := strings.Fields(strings.TrimSpace(scope))
	if len(clean) == 0 {
		return "openid profile email gateway:session gateway:share"
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

func bearer(authHeader string) string {
	authHeader = strings.TrimSpace(authHeader)
	if authHeader == "" {
		return ""
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(strings.ToLower(authHeader), strings.ToLower(prefix)) {
		return ""
	}
	return strings.TrimSpace(authHeader[len(prefix):])
}

func randomToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
