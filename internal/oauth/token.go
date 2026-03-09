package oauth

import (
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"oss-commands-gateway/internal/httputil"
)

func (h *Handler) Token(c fiber.Ctx) error {
	grantType := strings.TrimSpace(c.FormValue("grant_type"))
	switch grantType {
	case "authorization_code":
		return h.exchangeAuthorizationCode(c)
	case "refresh_token":
		return h.exchangeRefreshToken(c)
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "unsupported grant_type"})
	}
}

// resolveClientID returns the client_id from the request, defaulting to the
// configured public client ID when omitted. This mirrors the behaviour of
// /oauth/authorize and ensures client binding is never skipped.
func (h *Handler) resolveClientID(c fiber.Ctx) string {
	clientID := strings.TrimSpace(c.FormValue("client_id"))
	if clientID == "" {
		clientID = h.cfg.OAuthDefaultClientID
	}
	return clientID
}

func (h *Handler) RevokeToken(c fiber.Ctx) error {
	token := strings.TrimSpace(c.FormValue("token"))
	if token == "" {
		return c.SendStatus(fiber.StatusOK)
	}

	// Validate client ownership before revoking.
	clientID := h.resolveClientID(c)
	rec, ok, err := h.store.getRefreshToken(token)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "server_error"})
	}
	if ok {
		// Enforce client binding. Legacy tokens with an empty stored
		// ClientID predate client binding and are allowed through for
		// any client during a deprecation window.
		if rec.ClientID != "" && clientID != rec.ClientID {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid_client"})
		}
		h.store.deleteRefreshToken(token)
	}
	// Per RFC 7009 §2.2, always return 200 even if the token was not found.
	return c.SendStatus(fiber.StatusOK)
}

func (h *Handler) exchangeAuthorizationCode(c fiber.Ctx) error {
	code := strings.TrimSpace(c.FormValue("code"))
	if code == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "code is required"})
	}

	// Step 1: Non-destructive peek to validate client binding, redirect URI,
	// and PKCE BEFORE consuming the code. This prevents a request with wrong
	// credentials from destroying a valid authorization code (DoS).
	rec, ok, err := h.store.getAuthCode(code)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "server_error"})
	}
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_grant"})
	}

	// Require client_id and enforce strict match against the stored value.
	clientID := h.resolveClientID(c)
	if clientID != rec.ClientID {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid_client"})
	}
	// RFC 6749 §4.1.3: if redirect_uri was included in the authorization
	// request, it MUST be present and identical in the token request.
	redirectURI := strings.TrimSpace(c.FormValue("redirect_uri"))
	if redirectURI == "" || redirectURI != rec.RedirectURI {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_grant"})
	}
	if err := verifyPKCE(rec.CodeChallenge, rec.CodeChallengeMethod, strings.TrimSpace(c.FormValue("code_verifier"))); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_grant", "error_description": err.Error()})
	}

	// Step 2: All validations passed — atomically consume the code.
	// If another request already consumed it between peek and now, treat
	// as invalid_grant.
	rec, ok, err = h.store.consumeAuthCode(code)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "server_error"})
	}
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_grant"})
	}

	scopes := strings.Fields(strings.TrimSpace(rec.Scope))
	accessToken, expiresIn, err := h.jwt.IssueAccessToken(rec.Subject, rec.Email, rec.DisplayName, scopes, string(h.cfg.AuthMode), h.cfg.AccessTokenTTL)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "server_error"})
	}
	refreshToken, err := httputil.RandomToken(40)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "server_error"})
	}
	familyID := "fam_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if err := h.store.putRefreshToken(refreshToken, refreshTokenRecord{
		ClientID:    rec.ClientID,
		Subject:     rec.Subject,
		Email:       rec.Email,
		DisplayName: rec.DisplayName,
		Scope:       rec.Scope,
		FamilyID:    familyID,
	}, h.cfg.RefreshTokenTTL); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "server_error", "error_description": "failed to persist refresh token"})
	}

	return c.JSON(fiber.Map{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    expiresIn,
		"scope":         rec.Scope,
		"refresh_token": refreshToken,
	})
}

func (h *Handler) exchangeRefreshToken(c fiber.Ctx) error {
	raw := strings.TrimSpace(c.FormValue("refresh_token"))
	if raw == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "refresh_token is required"})
	}

	// Step 1: Non-destructive peek to validate client binding BEFORE
	// consuming the token. This prevents a request with the wrong
	// client_id from destroying a valid token.
	clientID := h.resolveClientID(c)
	tokenHash := hashRefreshToken(raw)
	rec, ok, err := h.store.getRefreshToken(raw)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "server_error"})
	}
	if !ok {
		// Token not found — it may have been consumed by a legitimate
		// rotation. Check consumed-token tombstones for the family ID
		// so we can revoke the entire family if this is a replay attack.
		if tombFamilyID, found, _ := h.store.getConsumedTokenFamily(tokenHash); found && tombFamilyID != "" {
			h.store.deleteRefreshTokensByFamily(tombFamilyID)
		}
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_grant"})
	}
	// Enforce client binding. Legacy tokens with an empty stored ClientID
	// predate client binding and are allowed through for any client during
	// a deprecation window to avoid breaking existing sessions on rollout.
	if rec.ClientID != "" && clientID != rec.ClientID {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid_client"})
	}

	// Step 2: Prepare and persist the replacement refresh token BEFORE
	// consuming the old one. This ensures that if replacement persistence
	// fails, the old token remains valid and the session is not stranded.
	newRefreshToken, err := httputil.RandomToken(40)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "server_error"})
	}
	// Bind the new token to the same client. For legacy tokens (empty
	// ClientID) we bind to the current client going forward.
	boundClientID := rec.ClientID
	if boundClientID == "" {
		boundClientID = clientID
	}
	// Propagate the family ID from the old token to the new one.
	// Legacy tokens without a family ID get a new family assigned.
	familyID := rec.FamilyID
	if familyID == "" {
		familyID = "fam_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	}
	if err := h.store.putRefreshToken(newRefreshToken, refreshTokenRecord{
		ClientID:    boundClientID,
		Subject:     rec.Subject,
		Email:       rec.Email,
		DisplayName: rec.DisplayName,
		Scope:       rec.Scope,
		FamilyID:    familyID,
	}, h.cfg.RefreshTokenTTL); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "server_error", "error_description": "failed to persist refresh token"})
	}

	// Step 3: Atomically consume the old token and write a consumed-token
	// tombstone in the same operation. The tombstone maps the token hash
	// to its family ID so that post-consumption replay can still trigger
	// family revocation. If another request already consumed the token
	// between our peek and now, this returns false and we roll back.
	rec, ok, err = h.store.consumeRefreshToken(raw, familyID, h.cfg.RefreshTokenTTL)
	if err != nil {
		h.store.deleteRefreshToken(newRefreshToken)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "server_error"})
	}
	if !ok {
		// Replay detected: a consumed token was reused. Roll back the
		// replacement token and revoke the entire token family to lock
		// out a potential attacker per OAuth 2.0 Security BCP.
		h.store.deleteRefreshToken(newRefreshToken)
		if familyID != "" {
			h.store.deleteRefreshTokensByFamily(familyID)
		}
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_grant"})
	}

	scopes := strings.Fields(strings.TrimSpace(rec.Scope))
	accessToken, expiresIn, err := h.jwt.IssueAccessToken(rec.Subject, rec.Email, rec.DisplayName, scopes, string(h.cfg.AuthMode), h.cfg.AccessTokenTTL)
	if err != nil {
		// Access token issuance failed but old token is consumed and new
		// token is stored. The client can retry with the new refresh token.
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "server_error"})
	}

	return c.JSON(fiber.Map{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    expiresIn,
		"scope":         rec.Scope,
		"refresh_token": newRefreshToken,
	})
}
