package gateway

import "github.com/gofiber/fiber/v3"

func (h *Handler) Health(c fiber.Ctx) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return c.JSON(fiber.Map{
		"status":         "ok",
		"state_backend":  h.cfg.StateBackend,
		"devices":        len(h.devices),
		"grants":         len(h.grants),
		"sessions":       len(h.sessions),
		"agents":         len(h.agents),
		"routes":         len(h.integrationRoutes),
		"tunnels":        len(h.tunnelConns),
		"inflight":       len(h.inflightRequests),
		"event_backlogs": len(h.events),
	})
}
