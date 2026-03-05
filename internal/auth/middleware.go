package auth

import (
	"slices"
	"strings"

	"github.com/gofiber/fiber/v3"

	"oss-commands-gateway/internal/jwt"
)

const (
	ScopeDevice         = "device"
	ScopeGatewaySession = "gateway:session"
	ScopeGatewayShare   = "gateway:share"
)

type Principal struct {
	UID         string   `json:"uid"`
	Email       string   `json:"email,omitempty"`
	DisplayName string   `json:"display_name,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
}

const principalCtxKey = "principal"

func PrincipalFromContext(c fiber.Ctx) *Principal {
	v := c.Locals(principalCtxKey)
	if v == nil {
		return nil
	}
	p, _ := v.(*Principal)
	return p
}

func (p *Principal) HasScope(scope string) bool {
	if p == nil {
		return false
	}
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return false
	}
	return slices.Contains(p.Scopes, scope)
}

func RequireUser(jm *jwt.Manager) fiber.Handler {
	return func(c fiber.Ctx) error {
		token := bearer(c.Get("Authorization"))
		if token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing bearer token"})
		}
		claims, err := jm.ParseAccessToken(token)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid access token"})
		}
		subject := strings.TrimSpace(claims.Subject)
		if subject == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid access token"})
		}
		principal := &Principal{
			UID:         subject,
			Email:       strings.TrimSpace(claims.Email),
			DisplayName: strings.TrimSpace(claims.Name),
			Scopes:      normalizeScopes(strings.Fields(strings.TrimSpace(claims.Scope))),
		}
		c.Locals(principalCtxKey, principal)
		c.Locals("claims", claims)
		return c.Next()
	}
}

func RequireScopes(required ...string) fiber.Handler {
	normalizedRequired := normalizeScopes(required)
	return func(c fiber.Ctx) error {
		if len(normalizedRequired) == 0 {
			return c.Next()
		}
		principal := PrincipalFromContext(c)
		if principal == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		}
		missing := make([]string, 0)
		for _, scope := range normalizedRequired {
			if !principal.HasScope(scope) {
				missing = append(missing, scope)
			}
		}
		if len(missing) > 0 {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":           "insufficient_scope",
				"required_scopes": normalizedRequired,
				"missing_scopes":  missing,
			})
		}
		return c.Next()
	}
}

func normalizeScopes(scopes []string) []string {
	clean := make([]string, 0, len(scopes))
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		normalized := strings.TrimSpace(scope)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		clean = append(clean, normalized)
	}
	return clean
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
