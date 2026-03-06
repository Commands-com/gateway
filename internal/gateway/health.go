package gateway

import (
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

	devices, _ := h.store.CountDevices(c.Context())
	grants, _ := h.store.CountShareGrants(c.Context())
	sessions, _ := h.store.CountSessions(c.Context())
	routes, _ := h.store.CountIntegrationRoutes(c.Context())
	eventBacklogs, _ := h.store.CountSessionEventBacklogs(c.Context())

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
