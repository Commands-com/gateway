package gateway

import (
	"context"

	"github.com/gofiber/fiber/v3"

	"oss-commands-gateway/internal/auth"
)

// Health returns a minimal status when unauthenticated, or detailed stats when
// called by an authenticated user.
func (h *Handler) Health(c fiber.Ctx) error {
	principal := auth.PrincipalFromContext(c)
	if principal == nil {
		// Unauthenticated: return minimal response only
		return c.JSON(fiber.Map{
			"status": "ok",
		})
	}

	devices, _ := h.store.CountDevices(context.Background())
	grants, _ := h.store.CountShareGrants(context.Background())
	sessions, _ := h.store.CountSessions(context.Background())
	routes, _ := h.store.CountIntegrationRoutes(context.Background())
	eventBacklogs, _ := h.store.CountSessionEventBacklogs(context.Background())

	h.mu.RLock()
	agents := len(h.agents)
	tunnels := len(h.tunnelConns)
	inflight := len(h.inflightRequests)
	h.mu.RUnlock()

	return c.JSON(fiber.Map{
		"status":         "ok",
		"state_backend":  h.cfg.StateBackend,
		"devices":        devices,
		"grants":         grants,
		"sessions":       sessions,
		"agents":         agents,
		"routes":         routes,
		"tunnels":        tunnels,
		"inflight":       inflight,
		"event_backlogs": eventBacklogs,
	})
}
