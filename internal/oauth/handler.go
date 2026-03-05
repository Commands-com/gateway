package oauth

import (
	"slices"
	"strings"

	"github.com/gofiber/fiber/v3"

	"oss-commands-gateway/internal/config"
	"oss-commands-gateway/internal/idtoken"
	"oss-commands-gateway/internal/jwt"
)

type Handler struct {
	cfg      *config.Config
	jwt      *jwt.Manager
	idVerify idtoken.Verifier
	store    *memoryStore
}

type authorizeRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	ResponseMode        string
}

func NewHandler(cfg *config.Config, jm *jwt.Manager, verifier idtoken.Verifier) *Handler {
	return &Handler{
		cfg:      cfg,
		jwt:      jm,
		idVerify: verifier,
		store:    newMemoryStore(),
	}
}

func (h *Handler) Register(c fiber.Ctx) error {
	redirectURIs := append([]string(nil), h.cfg.OAuthRedirectURIs...)
	if len(redirectURIs) == 0 {
		redirectURIs = append([]string(nil), h.cfg.RedirectAllowlist...)
	}
	if len(redirectURIs) == 0 {
		redirectURIs = []string{"urn:ietf:wg:oauth:2.0:oob"}
	}
	if !slices.Contains(redirectURIs, "urn:ietf:wg:oauth:2.0:oob") {
		redirectURIs = append(redirectURIs, "urn:ietf:wg:oauth:2.0:oob")
	}

	return c.JSON(fiber.Map{
		"client_id":                  h.cfg.OAuthDefaultClientID,
		"token_endpoint_auth_method": "none",
		"redirect_uris":              redirectURIs,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"client_name":                h.cfg.OAuthClientName,
	})
}

func (h *Handler) WellKnown(c fiber.Ctx) error {
	issuer := strings.TrimRight(h.cfg.PublicBaseURL, "/")
	return c.JSON(fiber.Map{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth/authorize",
		"token_endpoint":                        issuer + "/oauth/token",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
		"scopes_supported":                      []string{"openid", "profile", "email", "device", "gateway:session", "gateway:share"},
	})
}

func (h *Handler) JWKS(c fiber.Ctx) error {
	return c.JSON(h.jwt.JWKS())
}
