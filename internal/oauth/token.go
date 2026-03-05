package oauth

import (
	"strings"

	"github.com/gofiber/fiber/v3"
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

func (h *Handler) RevokeToken(c fiber.Ctx) error {
	token := strings.TrimSpace(c.FormValue("token"))
	if token != "" {
		h.store.deleteRefreshToken(token)
	}
	return c.SendStatus(fiber.StatusOK)
}

func (h *Handler) exchangeAuthorizationCode(c fiber.Ctx) error {
	code := strings.TrimSpace(c.FormValue("code"))
	if code == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "code is required"})
	}
	rec, ok := h.store.consumeAuthCode(code)
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_grant"})
	}

	clientID := strings.TrimSpace(c.FormValue("client_id"))
	if clientID != "" && clientID != rec.ClientID {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid_client"})
	}
	if redirectURI := strings.TrimSpace(c.FormValue("redirect_uri")); redirectURI != "" && redirectURI != rec.RedirectURI {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_grant"})
	}
	if err := verifyPKCE(rec.CodeChallenge, rec.CodeChallengeMethod, strings.TrimSpace(c.FormValue("code_verifier"))); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_grant", "error_description": err.Error()})
	}

	scopes := strings.Fields(strings.TrimSpace(rec.Scope))
	accessToken, expiresIn, err := h.jwt.IssueAccessToken(rec.Subject, rec.Email, rec.DisplayName, scopes, string(h.cfg.AuthMode), h.cfg.AccessTokenTTL)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "server_error"})
	}
	refreshToken, err := randomToken(40)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "server_error"})
	}
	h.store.putRefreshToken(refreshToken, refreshTokenRecord{
		Subject:     rec.Subject,
		Email:       rec.Email,
		DisplayName: rec.DisplayName,
		Scope:       rec.Scope,
	}, h.cfg.RefreshTokenTTL)

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
	rec, ok := h.store.getRefreshToken(raw)
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_grant"})
	}
	scopes := strings.Fields(strings.TrimSpace(rec.Scope))
	accessToken, expiresIn, err := h.jwt.IssueAccessToken(rec.Subject, rec.Email, rec.DisplayName, scopes, string(h.cfg.AuthMode), h.cfg.AccessTokenTTL)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "server_error"})
	}
	return c.JSON(fiber.Map{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   expiresIn,
		"scope":        rec.Scope,
	})
}
