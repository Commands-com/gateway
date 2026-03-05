package gateway

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
)

func TestIngressRateLimiterRouteLimit(t *testing.T) {
	limiter := NewIngressRateLimiter(100, 100, 2, time.Minute)
	app := newIngressLimiterTestApp(limiter)

	mustStatus(t, app, "/integrations/route-a/token-a", fiber.StatusNoContent)
	mustStatus(t, app, "/integrations/route-a/token-a", fiber.StatusNoContent)
	mustStatus(t, app, "/integrations/route-a/token-a", fiber.StatusTooManyRequests)
	mustStatus(t, app, "/integrations/route-b/token-b", fiber.StatusNoContent)
}

func TestIngressRateLimiterIPLimit(t *testing.T) {
	limiter := NewIngressRateLimiter(100, 2, 100, time.Minute)
	app := newIngressLimiterTestApp(limiter)

	mustStatus(t, app, "/integrations/route-a/token-a", fiber.StatusNoContent)
	mustStatus(t, app, "/integrations/route-b/token-b", fiber.StatusNoContent)
	mustStatus(t, app, "/integrations/route-c/token-c", fiber.StatusTooManyRequests)
}

func TestIngressRateLimiterGlobalLimit(t *testing.T) {
	limiter := NewIngressRateLimiter(2, 100, 100, time.Minute)
	app := newIngressLimiterTestApp(limiter)

	mustStatus(t, app, "/integrations/route-a/token-a", fiber.StatusNoContent)
	mustStatus(t, app, "/integrations/route-b/token-b", fiber.StatusNoContent)
	mustStatus(t, app, "/integrations/route-c/token-c", fiber.StatusTooManyRequests)
}

func newIngressLimiterTestApp(limiter *IngressRateLimiter) *fiber.App {
	app := fiber.New()
	app.All(
		"/integrations/:route_id/:route_token",
		limiter.GlobalMiddleware(),
		limiter.IPMiddleware(),
		limiter.RouteMiddleware(),
		func(c fiber.Ctx) error {
			return c.SendStatus(fiber.StatusNoContent)
		},
	)
	return app
}

func mustStatus(t *testing.T, app *fiber.App, path string, expected int) {
	t.Helper()
	req := httptest.NewRequest(fiber.MethodPost, path, nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != expected {
		t.Fatalf("unexpected status for %s: got=%d want=%d", path, resp.StatusCode, expected)
	}
}
