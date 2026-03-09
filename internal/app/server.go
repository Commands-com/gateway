package app

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/gofiber/fiber/v3/middleware/recover"

	"oss-commands-gateway/internal/auth"
	"oss-commands-gateway/internal/config"
	"oss-commands-gateway/internal/console"
	"oss-commands-gateway/internal/gateway"
	"oss-commands-gateway/internal/health"
	"oss-commands-gateway/internal/idtoken"
	"oss-commands-gateway/internal/jwt"
	"oss-commands-gateway/internal/oauth"
)

func New(cfg *config.Config) (*fiber.App, error) {
	return NewWithGatewayOptions(cfg, gateway.HandlerOptions{
		NodeID: cfg.NodeID,
	})
}

func NewWithGatewayOptions(cfg *config.Config, gatewayOpts gateway.HandlerOptions) (*fiber.App, error) {
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
	if strings.TrimSpace(gatewayOpts.NodeID) == "" {
		gatewayOpts.NodeID = cfg.NodeID
	}
	gatewayHandler := gateway.NewHandlerWithOptions(cfg, gatewayOpts)
	healthHandler := health.NewHandler(cfg)
	ingressLimiter := gateway.NewIngressRateLimiter(
		cfg.IngressGlobalLimitPerWindow,
		cfg.IngressIPLimitPerWindow,
		cfg.IngressRouteLimitPerWindow,
		time.Duration(cfg.IngressRateWindowSeconds)*time.Second,
	)

	app := fiber.New(fiber.Config{
		ProxyHeader: cfg.ProxyHeader,
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
				"console":            "/console",
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

	app.Get("/console", console.Handler)

	app.Get("/.well-known/openid-configuration", oauthHandler.WellKnown)
	app.Get("/.well-known/oauth-authorization-server", oauthHandler.WellKnown)
	app.Get("/.well-known/jwks.json", oauthHandler.JWKS)
	app.Post("/register", oauthHandler.Register)

	oauthLimiter := gateway.NewOAuthRateLimiter(
		30,
		time.Duration(cfg.IngressRateWindowSeconds)*time.Second,
	)

	oauthGroup := app.Group("/oauth")
	oauthGroup.Get("/.well-known/openid-configuration", oauthHandler.WellKnown)
	oauthGroup.Get("/.well-known/jwks.json", oauthHandler.JWKS)
	oauthGroup.Get("/authorize", oauthLimiter.Middleware(), oauthHandler.Authorize)
	oauthGroup.Post("/authorize", oauthLimiter.Middleware(), oauthHandler.Authorize)
	oauthGroup.Post("/token", oauthLimiter.Middleware(), oauthHandler.Token)
	oauthGroup.Post("/token/revoke", oauthLimiter.Middleware(), oauthHandler.RevokeToken)

	gatewayGroup := app.Group("/gateway/v1")
	gatewayGroup.Get("/health", auth.OptionalUser(jwtManager), gatewayHandler.Health)
	gatewayGroup.Use(auth.RequireUser(jwtManager))

	// No per-route scope gates — every authenticated user has full access.
	gatewayGroup.Put("/devices/:device_id/identity-key", gatewayHandler.PutDeviceIdentityKey)
	gatewayGroup.Get("/devices", gatewayHandler.ListDevices)
	gatewayGroup.Get("/devices/events", gatewayHandler.GetDeviceEvents)
	gatewayGroup.Get("/devices/:device_id/identity-key", gatewayHandler.GetDeviceIdentityKey)

	gatewayGroup.Post("/shares/invites", gatewayHandler.CreateShareInvite)
	gatewayGroup.Post("/shares/invites/accept", gatewayHandler.AcceptShareInvite)
	gatewayGroup.Get("/shares/devices/:device_id/grants", gatewayHandler.ListShareGrants)
	gatewayGroup.Post("/shares/grants/:grant_id/revoke", gatewayHandler.RevokeShareGrant)
	gatewayGroup.Post("/shares/grants/:grant_id/leave", gatewayHandler.LeaveShareGrant)

	gatewayGroup.Post("/sessions/:session_id/handshake/client-init", gatewayHandler.PostHandshakeClientInit)
	gatewayGroup.Get("/sessions/:session_id/handshake/:handshake_id", gatewayHandler.GetHandshake)
	gatewayGroup.Post("/sessions/:session_id/handshake/agent-ack", gatewayHandler.PostHandshakeAgentAck)
	gatewayGroup.Post("/sessions/:session_id/messages", gatewayHandler.PostSessionMessage)
	gatewayGroup.Get("/sessions/:session_id/events", gatewayHandler.GetSessionEvents)

	gatewayGroup.Use("/agent/connect", gatewayHandler.RequireAgentWebSocketUpgrade)
	gatewayGroup.Get("/agent/connect", gatewayHandler.AgentConnectWebSocket())

	gatewayGroup.Post("/integrations/routes", gatewayHandler.CreateIntegrationRoute)
	gatewayGroup.Put("/integrations/routes/:route_id", gatewayHandler.UpdateIntegrationRoute)
	gatewayGroup.Delete("/integrations/routes/:route_id", gatewayHandler.DeleteIntegrationRoute)
	gatewayGroup.Get("/integrations/routes", gatewayHandler.ListIntegrationRoutes)
	gatewayGroup.Post("/integrations/routes/:route_id/rotate-token", gatewayHandler.RotateIntegrationRouteToken)

	gatewayGroup.Use("/integrations/tunnel/connect", gatewayHandler.RequireIntegrationTunnelUpgrade)
	gatewayGroup.Get("/integrations/tunnel/connect", gatewayHandler.IntegrationTunnelWebSocket())

	app.All(
		"/integrations/:route_id/:route_token",
		ingressLimiter.GlobalMiddleware(),
		ingressLimiter.IPMiddleware(),
		ingressLimiter.RouteMiddleware(),
		gatewayHandler.HandlePublicIngress,
	)

	// Register shutdown hook to stop background sweeper goroutines
	app.Hooks().OnPostShutdown(func(_ error) error {
		gatewayHandler.Close()
		oauthHandler.Close()
		return nil
	})

	slog.Info("gateway startup", "auth_mode", cfg.AuthMode, "state_backend", cfg.StateBackend, "public_base_url", cfg.PublicBaseURL, "node_id", cfg.NodeID)
	if cfg.AuthMode == config.AuthModeDemo {
		slog.Warn("AUTH_MODE=demo is non-production")
	}

	return app, nil
}
