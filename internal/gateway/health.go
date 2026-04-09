package gateway

import (
	"github.com/gofiber/fiber/v3"

	"oss-commands-gateway/internal/auth"
)

// Health returns a minimal status when unauthenticated, or detailed stats when
// called by an authenticated user.
//
// The user-scoped counters (devices, grants, sessions, routes) are filtered
// by the caller's UID so the dashboard tiles match the corresponding tab
// listings. The node-local operational counters (agents, tunnels, inflight,
// event_backlogs) remain whole-node metrics — they represent what this
// gateway instance is currently handling and are not meaningful to scope by
// user identity.
func (h *Handler) Health(c fiber.Ctx) error {
	principal := auth.PrincipalFromContext(c)
	if principal == nil {
		// Unauthenticated: return minimal response only
		return c.JSON(fiber.Map{
			"status": "ok",
		})
	}

	ctx := c.Context()
	uid := principal.UID

	devices, _ := h.store.CountDevicesByOwner(ctx, uid)

	ownedRoutes, _ := h.store.ListIntegrationRoutesByOwner(ctx, uid)
	routes := len(ownedRoutes)

	// No owner index exists for grants or sessions, so filter in memory.
	// The in-memory state store's List* methods already clone each record,
	// which is acceptable here — /health is not on any hot path.
	grants := 0
	if allGrants, err := h.store.ListShareGrants(ctx); err == nil {
		for _, grant := range allGrants {
			if grant != nil && grant.OwnerUID == uid {
				grants++
			}
		}
	}
	sessions := 0
	if allSessions, err := h.store.ListSessions(ctx); err == nil {
		for _, sess := range allSessions {
			if sess != nil && sess.OwnerUID == uid {
				sessions++
			}
		}
	}

	eventBacklogs, _ := h.store.CountSessionEventBacklogs(ctx)

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
