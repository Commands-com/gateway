package app

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/gofiber/fiber/v3/middleware/recover"

	"oss-commands-gateway/internal/auth"
	"oss-commands-gateway/internal/config"
	"oss-commands-gateway/internal/gateway"
	"oss-commands-gateway/internal/health"
	"oss-commands-gateway/internal/idtoken"
	"oss-commands-gateway/internal/jwt"
	"oss-commands-gateway/internal/oauth"
)

func New(cfg *config.Config) (*fiber.App, error) {
	jwtManager, err := jwt.NewManager(cfg.JWTSigningKey, cfg.PublicBaseURL, cfg.Audience)
	if err != nil {
		return nil, fmt.Errorf("jwt init: %w", err)
	}

	var verifier idtoken.Verifier
	switch cfg.AuthMode {
	case config.AuthModeDemo:
		verifier = nil
	case config.AuthModeFirebase:
		v, err := idtoken.NewFirebaseVerifier(context.Background(), cfg.FirebaseProjectID, cfg.FirebaseCredentialsPath)
		if err != nil {
			return nil, fmt.Errorf("firebase verifier init: %w", err)
		}
		verifier = v
	case config.AuthModeOIDC:
		v, err := idtoken.NewOIDCVerifier(context.Background(), cfg.OIDCIssuerURL, cfg.OIDCClientID)
		if err != nil {
			return nil, fmt.Errorf("oidc verifier init: %w", err)
		}
		verifier = v
	default:
		return nil, fmt.Errorf("unsupported auth mode: %s", cfg.AuthMode)
	}

	oauthHandler := oauth.NewHandler(cfg, jwtManager, verifier)
	gatewayHandler := gateway.NewHandler(cfg)
	healthHandler := health.NewHandler(cfg)
	ingressLimiter := gateway.NewIngressRateLimiter(
		cfg.IngressGlobalLimitPerWindow,
		cfg.IngressIPLimitPerWindow,
		cfg.IngressRouteLimitPerWindow,
		time.Duration(cfg.IngressRateWindowSeconds)*time.Second,
	)

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if fe, ok := err.(*fiber.Error); ok {
				code = fe.Code
			}
			return c.Status(code).JSON(fiber.Map{"error": err.Error(), "code": code})
		},
	})

	app.Use(recover.New())

	allowCredentials := true
	for _, origin := range cfg.AllowOrigins {
		if strings.TrimSpace(origin) == "*" {
			allowCredentials = false
			break
		}
	}

	app.Use(cors.New(cors.Config{
		AllowOrigins:     cfg.AllowOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "Cache-Control", "Last-Event-ID", "X-Idempotency-Key"},
		AllowCredentials: allowCredentials,
	}))

	app.Get("/", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"name":          "OSS Commands Gateway",
			"auth_mode":     cfg.AuthMode,
			"state_backend": cfg.StateBackend,
			"endpoints": fiber.Map{
				"healthz":            "/healthz",
				"readyz":             "/readyz",
				"oauth":              "/oauth",
				"gateway":            "/gateway/v1",
				"webhook_ingress":    "/integrations/:route_id/:route_token",
				"integration_routes": "/gateway/v1/integrations/routes",
			},
		})
	})

	app.Get("/health", healthHandler.Liveness)
	app.Get("/healthz", healthHandler.Liveness)
	app.Get("/readyz", healthHandler.Readiness)

	app.Get("/.well-known/openid-configuration", oauthHandler.WellKnown)
	app.Get("/.well-known/oauth-authorization-server", oauthHandler.WellKnown)
	app.Get("/.well-known/jwks.json", oauthHandler.JWKS)
	app.Post("/register", oauthHandler.Register)

	oauthGroup := app.Group("/oauth")
	oauthGroup.Get("/.well-known/openid-configuration", oauthHandler.WellKnown)
	oauthGroup.Get("/.well-known/jwks.json", oauthHandler.JWKS)
	oauthGroup.Get("/authorize", oauthHandler.Authorize)
	oauthGroup.Post("/authorize", oauthHandler.Authorize)
	oauthGroup.Post("/token", oauthHandler.Token)
	oauthGroup.Post("/token/revoke", oauthHandler.RevokeToken)

	gatewayGroup := app.Group("/gateway/v1")
	gatewayGroup.Get("/health", gatewayHandler.Health)
	gatewayGroup.Use(auth.RequireUser(jwtManager))

	gatewayGroup.Put("/devices/:device_id/identity-key", auth.RequireScopes(auth.ScopeDevice), gatewayHandler.PutDeviceIdentityKey)
	gatewayGroup.Get("/devices/:device_id/identity-key", auth.RequireScopes(auth.ScopeGatewaySession), gatewayHandler.GetDeviceIdentityKey)

	gatewayGroup.Post("/shares/invites", auth.RequireScopes(auth.ScopeGatewayShare), gatewayHandler.CreateShareInvite)
	gatewayGroup.Post("/shares/invites/accept", auth.RequireScopes(auth.ScopeGatewayShare), gatewayHandler.AcceptShareInvite)
	gatewayGroup.Get("/shares/devices/:device_id/grants", auth.RequireScopes(auth.ScopeGatewayShare), gatewayHandler.ListShareGrants)
	gatewayGroup.Post("/shares/grants/:grant_id/revoke", auth.RequireScopes(auth.ScopeGatewayShare), gatewayHandler.RevokeShareGrant)
	gatewayGroup.Post("/shares/grants/:grant_id/leave", auth.RequireScopes(auth.ScopeGatewayShare), gatewayHandler.LeaveShareGrant)

	gatewayGroup.Post("/sessions/:session_id/handshake/client-init", auth.RequireScopes(auth.ScopeGatewaySession), gatewayHandler.PostHandshakeClientInit)
	gatewayGroup.Get("/sessions/:session_id/handshake/:handshake_id", auth.RequireScopes(auth.ScopeGatewaySession), gatewayHandler.GetHandshake)
	gatewayGroup.Post("/sessions/:session_id/handshake/agent-ack", auth.RequireScopes(auth.ScopeDevice), gatewayHandler.PostHandshakeAgentAck)
	gatewayGroup.Post("/sessions/:session_id/messages", auth.RequireScopes(auth.ScopeGatewaySession), gatewayHandler.PostSessionMessage)
	gatewayGroup.Get("/sessions/:session_id/events", auth.RequireScopes(auth.ScopeGatewaySession), gatewayHandler.GetSessionEvents)

	gatewayGroup.Use("/agent/connect", auth.RequireScopes(auth.ScopeDevice), gatewayHandler.RequireAgentWebSocketUpgrade)
	gatewayGroup.Get("/agent/connect", gatewayHandler.AgentConnectWebSocket())

	gatewayGroup.Post("/integrations/routes", auth.RequireScopes(auth.ScopeGatewayShare), gatewayHandler.CreateIntegrationRoute)
	gatewayGroup.Put("/integrations/routes/:route_id", auth.RequireScopes(auth.ScopeGatewayShare), gatewayHandler.UpdateIntegrationRoute)
	gatewayGroup.Delete("/integrations/routes/:route_id", auth.RequireScopes(auth.ScopeGatewayShare), gatewayHandler.DeleteIntegrationRoute)
	gatewayGroup.Get("/integrations/routes", auth.RequireScopes(auth.ScopeGatewayShare), gatewayHandler.ListIntegrationRoutes)
	gatewayGroup.Post("/integrations/routes/:route_id/rotate-token", auth.RequireScopes(auth.ScopeGatewayShare), gatewayHandler.RotateIntegrationRouteToken)

	gatewayGroup.Use("/integrations/tunnel/connect", auth.RequireScopes(auth.ScopeDevice), gatewayHandler.RequireIntegrationTunnelUpgrade)
	gatewayGroup.Get("/integrations/tunnel/connect", gatewayHandler.IntegrationTunnelWebSocket())

	app.All(
		"/integrations/:route_id/:route_token",
		ingressLimiter.GlobalMiddleware(),
		ingressLimiter.IPMiddleware(),
		ingressLimiter.RouteMiddleware(),
		gatewayHandler.HandlePublicIngress,
	)

	log.Printf("gateway startup auth_mode=%s state_backend=%s public_base_url=%s", cfg.AuthMode, cfg.StateBackend, cfg.PublicBaseURL)
	if cfg.AuthMode == config.AuthModeDemo {
		log.Printf("warning: AUTH_MODE=demo is non-production")
	}

	return app, nil
}
