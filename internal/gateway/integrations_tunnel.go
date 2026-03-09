package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofiber/contrib/v3/websocket"
	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"oss-commands-gateway/internal/auth"
)

const (
	tunnelPingInterval           = 30 * time.Second
	tunnelPongTimeout            = 10 * time.Second
	wsReadDeadline               = 60 * time.Second
	inflightSweepInterval        = 10 * time.Second
	inflightRequestMaxAge        = 2 * time.Minute
	tunnelBusPublishTimeout      = 250 * time.Millisecond
	routeLeaseTTL                = 15 * time.Second
	routeLeaseRenewEvery         = 5 * time.Second
	maxTunnelConnectionsPerOwner = 50
)

var wsConnIDCounter uint64
var errRouteStatusUpdateSkipped = errors.New("route_status_update_skipped")

// routeBusSub wraps a bus subscription for a single tunnel route so the
// goroutine can identity-check whether its entry is still current in the map.
type routeBusSub struct {
	cancel   func()
	unsub    func()
	stopOnce sync.Once
}

func (rs *routeBusSub) stop() {
	if rs == nil {
		return
	}
	rs.stopOnce.Do(func() {
		rs.cancel()
		if rs.unsub != nil {
			rs.unsub()
		}
	})
}

type tunnelConn struct {
	deviceID        string
	ownerUID        string
	connID          string
	conn            *websocket.Conn
	ctx             context.Context
	cancel          context.CancelFunc
	connectedAt     time.Time
	lastSeenAt      time.Time
	sendMu          sync.Mutex
	activatedRoutes map[string]bool
	routeBusSubs    map[string]*routeBusSub
}

func (tc *tunnelConn) writeJSON(payload map[string]any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	tc.sendMu.Lock()
	defer tc.sendMu.Unlock()
	_ = tc.conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
	return tc.conn.WriteMessage(websocket.TextMessage, raw)
}

func (tc *tunnelConn) closeWithMessage(code int, reason string) {
	tc.sendMu.Lock()
	defer tc.sendMu.Unlock()
	_ = tc.conn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(code, reason),
		time.Now().Add(2*time.Second),
	)
	_ = tc.conn.Close()
}

type inflightRequest struct {
	requestID  string
	routeID    string
	deviceID   string
	responseCh chan *tunnelResponse
	// publishResponseToBus marks requests that originated from MessageBus route
	// subscriptions and must be answered via PublishTunnelResponse.
	publishResponseToBus bool
	createdAt            time.Time
}

type tunnelResponse struct {
	Status     int        `json:"status"`
	Headers    [][]string `json:"headers"`
	BodyBase64 string     `json:"body_base64"`
}

func (h *Handler) RequireIntegrationTunnelUpgrade(c fiber.Ctx) error {
	principal := auth.PrincipalFromContext(c)
	if principal == nil || strings.TrimSpace(principal.UID) == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}

	deviceID, err := validateID(strings.TrimSpace(c.Query("device_id")), "device_id")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "device_id query param is required"})
	}

	device, found, err := h.store.GetDevice(c.Context(), deviceID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal_error"})
	}
	if !found {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "device_not_found"})
	}
	if device.OwnerUID != principal.UID {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
	}

	// Enforce per-owner tunnel connection limit (excluding reconnects for the same device)
	h.mu.RLock()
	ownerTunnelCount := h.tunnelConnCountByOwner[principal.UID]
	if existing, ok := h.tunnelConns[deviceID]; ok && existing.ownerUID == principal.UID && ownerTunnelCount > 0 {
		ownerTunnelCount--
	}
	h.mu.RUnlock()
	if ownerTunnelCount >= maxTunnelConnectionsPerOwner {
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{"error": "too many tunnel connections"})
	}

	if !c.IsWebSocket() {
		return fiber.ErrUpgradeRequired
	}

	c.Locals("gateway_owner_uid", principal.UID)
	c.Locals("gateway_device_id", deviceID)
	return c.Next()
}

func (h *Handler) IntegrationTunnelWebSocket() fiber.Handler {
	return websocket.New(h.handleTunnelConnect, websocket.Config{EnableCompression: true})
}

func (h *Handler) handleTunnelConnect(c *websocket.Conn) {
	deviceID, err := validateID(strings.TrimSpace(c.Query("device_id")), "device_id")
	if err != nil {
		_ = c.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "invalid device_id"),
			time.Now().Add(2*time.Second),
		)
		_ = c.Close()
		return
	}

	ownerUID, _ := c.Locals("gateway_owner_uid").(string)
	ownerUID = strings.TrimSpace(ownerUID)
	if ownerUID == "" {
		ownerUID = "unknown"
	}

	now := time.Now().UTC()
	connID := fmt.Sprintf("tun:%d", atomic.AddUint64(&wsConnIDCounter, 1))
	connCtx, connCancel := context.WithCancel(context.Background())
	state := &tunnelConn{
		deviceID:        deviceID,
		ownerUID:        ownerUID,
		connID:          connID,
		conn:            c,
		ctx:             connCtx,
		cancel:          connCancel,
		connectedAt:     now,
		lastSeenAt:      now,
		activatedRoutes: make(map[string]bool),
		routeBusSubs:    make(map[string]*routeBusSub),
	}

	var replaced *tunnelConn
	h.mu.Lock()
	// Re-check per-owner tunnel connection limit under write lock to prevent
	// concurrent connection attempts from exceeding the limit.
	ownerTunnelCount := h.tunnelConnCountByOwner[ownerUID]
	if existing, ok := h.tunnelConns[deviceID]; ok && existing.ownerUID == ownerUID && ownerTunnelCount > 0 {
		ownerTunnelCount--
	}
	if ownerTunnelCount >= maxTunnelConnectionsPerOwner {
		h.mu.Unlock()
		_ = c.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "too_many_connections"),
			time.Now().Add(2*time.Second),
		)
		_ = c.Close()
		return
	}
	if existing, ok := h.tunnelConns[deviceID]; ok {
		replaced = existing
		h.tunnelConnCountByOwner[existing.ownerUID]--
		if h.tunnelConnCountByOwner[existing.ownerUID] <= 0 {
			delete(h.tunnelConnCountByOwner, existing.ownerUID)
		}
	}
	h.tunnelConns[deviceID] = state
	h.tunnelConnCountByOwner[ownerUID]++
	h.mu.Unlock()

	if replaced != nil && replaced != state {
		h.deactivateAllTunnelRoutes(context.Background(), replaced, "superseded")
		replaced.closeWithMessage(websocket.CloseNormalClosure, "replaced_by_new_connection")
	}

	_ = state.writeJSON(map[string]any{
		"type":      "tunnel.connected",
		"device_id": deviceID,
		"at":        now.Format(time.RFC3339),
	})

	stopPing := make(chan struct{})
	stopLease := make(chan struct{})
	go func() {
		ticker := time.NewTicker(tunnelPingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stopPing:
				return
			case <-ticker.C:
				state.sendMu.Lock()
				err := state.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(tunnelPongTimeout))
				state.sendMu.Unlock()
				if err != nil {
					_ = c.Close()
					return
				}
			}
		}
	}()
	go h.startTunnelLeaseHeartbeat(state, stopLease)

	_ = c.SetReadDeadline(time.Now().Add(wsReadDeadline))
	c.SetPongHandler(func(string) error {
		_ = c.SetReadDeadline(time.Now().Add(wsReadDeadline))
		h.mu.Lock()
		if current, ok := h.tunnelConns[deviceID]; ok && current == state {
			current.lastSeenAt = time.Now().UTC()
		}
		h.mu.Unlock()
		return nil
	})

	for {
		messageType, payload, err := c.ReadMessage()
		if err != nil {
			break
		}

		_ = c.SetReadDeadline(time.Now().Add(wsReadDeadline))
		h.mu.Lock()
		if current, ok := h.tunnelConns[deviceID]; ok && current == state {
			current.lastSeenAt = time.Now().UTC()
		}
		h.mu.Unlock()

		if messageType != websocket.TextMessage && messageType != websocket.BinaryMessage {
			continue
		}
		h.handleTunnelFrame(connCtx, state, payload)
	}

	connCancel()
	close(stopPing)
	close(stopLease)

	wasActive := false
	h.mu.Lock()
	if current, ok := h.tunnelConns[deviceID]; ok && current == state {
		delete(h.tunnelConns, deviceID)
		h.tunnelConnCountByOwner[ownerUID]--
		if h.tunnelConnCountByOwner[ownerUID] <= 0 {
			delete(h.tunnelConnCountByOwner, ownerUID)
		}
		h.removeInflightRequestsForDeviceLocked(deviceID)
		wasActive = true
	}
	h.mu.Unlock()

	if wasActive {
		h.deactivateAllTunnelRoutes(context.Background(), state, "connection_lost")
	}
	h.stopAllRouteBusSubscriptions(state)
	_ = c.Close()
}

func (h *Handler) handleTunnelFrame(ctx context.Context, tc *tunnelConn, payload []byte) {
	var frame map[string]any
	if err := json.Unmarshal(payload, &frame); err != nil {
		_ = tc.writeJSON(map[string]any{"type": "tunnel.error", "error": "invalid_json"})
		return
	}

	switch firstStringMap(frame, "type") {
	case "tunnel.activate":
		h.handleTunnelActivate(ctx, tc, frame)
	case "tunnel.deactivate":
		h.handleTunnelDeactivate(ctx, tc, frame)
	case "tunnel.response":
		h.handleTunnelResponse(ctx, tc, frame)
	case "ping", "heartbeat":
		return
	default:
		_ = tc.writeJSON(map[string]any{"type": "tunnel.error", "error": "unknown_frame_type"})
	}
}

func (h *Handler) startRouteBusSubscription(tc *tunnelConn, routeID string) error {
	routeID = strings.TrimSpace(routeID)
	if routeID == "" {
		return nil
	}

	h.mu.RLock()
	if tc.routeBusSubs != nil {
		if _, exists := tc.routeBusSubs[routeID]; exists {
			h.mu.RUnlock()
			return nil
		}
	}
	h.mu.RUnlock()

	reqCh := make(chan TunnelRequestMessage, 16)
	subCtx, subCancel := context.WithCancel(tc.ctx)
	unsub, err := h.bus.SubscribeTunnelRequests(subCtx, routeID, reqCh)
	if err != nil {
		subCancel()
		return err
	}

	rs := &routeBusSub{cancel: subCancel, unsub: unsub}

	h.mu.Lock()
	current, ok := h.tunnelConns[tc.deviceID]
	if !ok || current != tc || !tc.activatedRoutes[routeID] {
		h.mu.Unlock()
		rs.stop()
		return nil
	}
	if tc.routeBusSubs == nil {
		tc.routeBusSubs = make(map[string]*routeBusSub)
	}
	if _, exists := tc.routeBusSubs[routeID]; exists {
		h.mu.Unlock()
		rs.stop()
		return nil
	}
	tc.routeBusSubs[routeID] = rs
	h.mu.Unlock()

	go func() {
		defer func() {
			rs.stop()
			// Remove our entry (only if it's still ours) so re-subscribe
			// is possible, then restart if the route is still activated.
			h.mu.Lock()
			if tc.routeBusSubs[routeID] == rs {
				delete(tc.routeBusSubs, routeID)
			}
			cur, isCurrent := h.tunnelConns[tc.deviceID]
			stillActive := isCurrent && cur == tc && tc.activatedRoutes[routeID]
			h.mu.Unlock()

			select {
			case <-h.done:
				return
			default:
			}
			select {
			case <-tc.ctx.Done():
				return
			default:
			}
			if stillActive {
				if err := h.startRouteBusSubscription(tc, routeID); err != nil {
					slog.Warn("route bus re-subscribe failed", "route", routeID, "err", err)
				}
			}
		}()
		for {
			select {
			case <-h.done:
				return
			case <-subCtx.Done():
				return
			case req, ok := <-reqCh:
				if !ok {
					return
				}
				if strings.TrimSpace(req.RequestID) == "" || strings.TrimSpace(req.RouteID) != routeID {
					continue
				}
				h.handleBusTunnelRequest(tc, req)
			}
		}
	}()

	return nil
}

func (h *Handler) stopRouteBusSubscription(tc *tunnelConn, routeID string) {
	routeID = strings.TrimSpace(routeID)
	if routeID == "" {
		return
	}

	h.mu.Lock()
	rs := tc.routeBusSubs[routeID]
	delete(tc.routeBusSubs, routeID)
	h.mu.Unlock()

	rs.stop()
}

func (h *Handler) stopAllRouteBusSubscriptions(tc *tunnelConn) {
	if tc == nil {
		return
	}

	h.mu.Lock()
	subs := make([]*routeBusSub, 0, len(tc.routeBusSubs))
	for routeID, rs := range tc.routeBusSubs {
		delete(tc.routeBusSubs, routeID)
		subs = append(subs, rs)
	}
	h.mu.Unlock()

	for _, rs := range subs {
		rs.stop()
	}
}

func (h *Handler) handleBusTunnelRequest(tc *tunnelConn, req TunnelRequestMessage) {
	requestID := strings.TrimSpace(req.RequestID)
	routeID := strings.TrimSpace(req.RouteID)
	if requestID == "" || routeID == "" {
		return
	}

	h.mu.Lock()
	current, ok := h.tunnelConns[tc.deviceID]
	if !ok || current != tc || !tc.activatedRoutes[routeID] {
		h.mu.Unlock()
		return
	}
	if len(h.inflightRequests) >= maxInflightRequests {
		h.mu.Unlock()
		_ = h.bus.PublishTunnelResponse(tc.ctx, requestID, TunnelResponseMessage{
			RequestID: requestID,
			RouteID:   routeID,
			Status:    fiber.StatusServiceUnavailable,
		})
		return
	}
	if _, exists := h.inflightRequests[requestID]; exists {
		h.mu.Unlock()
		return
	}
	h.inflightRequests[requestID] = &inflightRequest{
		requestID:            requestID,
		routeID:              routeID,
		deviceID:             tc.deviceID,
		publishResponseToBus: true,
		createdAt:            time.Now().UTC(),
	}
	h.mu.Unlock()

	receivedAt := req.ReceivedAt
	if receivedAt.IsZero() {
		receivedAt = time.Now().UTC()
	}

	requestFrame := map[string]any{
		"type":              "tunnel.request",
		"request_id":        requestID,
		"route_id":          routeID,
		"method":            req.Method,
		"scheme":            req.Scheme,
		"host":              req.Host,
		"external_url":      req.ExternalURL,
		"raw_target":        req.RawTarget,
		"raw_target_base64": req.RawTargetBase64,
		"path":              req.Path,
		"query":             req.Query,
		"headers":           req.Headers,
		"body_base64":       req.BodyBase64,
		"received_at":       receivedAt.Format(time.RFC3339),
		"deadline_ms":       req.DeadlineMS,
	}

	writeFn := h.tunnelWriteFn
	if writeFn == nil {
		writeFn = func(conn *tunnelConn, payload map[string]any) error {
			return conn.writeJSON(payload)
		}
	}
	if err := writeFn(tc, requestFrame); err != nil {
		h.mu.Lock()
		delete(h.inflightRequests, requestID)
		h.mu.Unlock()
		_ = h.bus.PublishTunnelResponse(tc.ctx, requestID, TunnelResponseMessage{
			RequestID: requestID,
			RouteID:   routeID,
			Status:    fiber.StatusServiceUnavailable,
		})
	}
}

func (h *Handler) handleTunnelActivate(ctx context.Context, tc *tunnelConn, frame map[string]any) {
	requestID := firstStringMap(frame, "request_id")
	if requestID == "" {
		requestID = "act_" + uuid.New().String()[:8]
	}

	routesRaw, ok := frame["routes"].([]any)
	if !ok || len(routesRaw) == 0 {
		_ = tc.writeJSON(map[string]any{"type": "tunnel.activate.result", "request_id": requestID, "results": []any{}})
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	results := make([]map[string]any, 0, len(routesRaw))

	for _, rawRoute := range routesRaw {
		routeID := ""
		switch value := rawRoute.(type) {
		case string:
			routeID = strings.TrimSpace(value)
		case map[string]any:
			routeID = firstStringMap(value, "route_id")
		}
		if routeID == "" {
			continue
		}

		activation := "clean"
		var supersededTunnel *tunnelConn
		result := map[string]any{}

		route, found, err := h.store.GetIntegrationRoute(ctx, routeID)
		switch {
		case err != nil:
			result = map[string]any{
				"route_id": routeID,
				"status":   "rejected",
				"error": map[string]string{
					"code":    "internal_error",
					"message": "Failed to load route state",
				},
			}
		case !found || route == nil:
			result = map[string]any{
				"route_id": routeID,
				"status":   "rejected",
				"error": map[string]string{
					"code":    "route_not_found",
					"message": "Route not found",
				},
			}
		case route.OwnerUID != tc.ownerUID:
			result = map[string]any{
				"route_id": routeID,
				"status":   "rejected",
				"error": map[string]string{
					"code":    "route_not_owned",
					"message": "Route not owned by authenticated user",
				},
			}
		case route.DeviceID != tc.deviceID:
			result = map[string]any{
				"route_id": routeID,
				"status":   "rejected",
				"error": map[string]string{
					"code":    "device_mismatch",
					"message": "Route is bound to a different device",
				},
			}
		case route.Status == "revoked":
			result = map[string]any{
				"route_id": routeID,
				"status":   "rejected",
				"error": map[string]string{
					"code":    "token_revoked",
					"message": "Route has been revoked",
				},
			}
		default:
			lease, claimed, err := h.store.ClaimRouteLease(ctx, routeID, h.nodeID, routeLeaseTTL)
			if err != nil {
				result = map[string]any{
					"route_id": routeID,
					"status":   "rejected",
					"error": map[string]string{
						"code":    "internal_error",
						"message": "Failed to claim route lease",
					},
				}
				break
			}
			if !claimed {
				result = map[string]any{
					"route_id": routeID,
					"status":   "rejected",
					"error": map[string]string{
						"code":    "route_claimed_elsewhere",
						"message": fmt.Sprintf("Route is currently claimed by node %s", lease.NodeID),
					},
				}
				break
			}

			existingDeviceID, active, err := h.store.GetActiveRouteDevice(ctx, routeID)
			if err != nil {
				_ = h.store.ReleaseRouteLease(ctx, routeID, h.nodeID)
				result = map[string]any{
					"route_id": routeID,
					"status":   "rejected",
					"error": map[string]string{
						"code":    "internal_error",
						"message": "Failed to load active route state",
					},
				}
				break
			}
			if active && existingDeviceID != tc.deviceID {
				h.mu.Lock()
				if old, hasOld := h.tunnelConns[existingDeviceID]; hasOld {
					delete(old.activatedRoutes, routeID)
					supersededTunnel = old
				}
				h.mu.Unlock()
				activation = "superseded"
			}
			if err := h.store.SetActiveRouteDevice(ctx, routeID, tc.deviceID); err != nil {
				if !active {
					_ = h.store.ReleaseRouteLease(ctx, routeID, h.nodeID)
				}
				result = map[string]any{
					"route_id": routeID,
					"status":   "rejected",
					"error": map[string]string{
						"code":    "internal_error",
						"message": "Failed to activate route",
					},
				}
				break
			}
			h.mu.Lock()
			tc.activatedRoutes[routeID] = true
			h.mu.Unlock()
			if err := h.startRouteBusSubscription(tc, routeID); err != nil {
				if active {
					_ = h.store.SetActiveRouteDevice(ctx, routeID, existingDeviceID)
					if supersededTunnel != nil {
						h.mu.Lock()
						supersededTunnel.activatedRoutes[routeID] = true
						h.mu.Unlock()
					}
				} else {
					_ = h.store.DeleteActiveRoute(ctx, routeID)
					_ = h.store.ReleaseRouteLease(ctx, routeID, h.nodeID)
				}
				h.mu.Lock()
				delete(tc.activatedRoutes, routeID)
				h.mu.Unlock()
				h.stopRouteBusSubscription(tc, routeID)
				result = map[string]any{
					"route_id": routeID,
					"status":   "rejected",
					"error": map[string]string{
						"code":    "internal_error",
						"message": "Failed to subscribe route bus",
					},
				}
				break
			}
			if err := h.setTunnelRouteStatus(ctx, routeID, tc.deviceID, "active", now, true); err != nil {
				if active {
					_ = h.store.SetActiveRouteDevice(ctx, routeID, existingDeviceID)
					if supersededTunnel != nil {
						h.mu.Lock()
						supersededTunnel.activatedRoutes[routeID] = true
						h.mu.Unlock()
					}
				} else {
					_ = h.store.DeleteActiveRoute(ctx, routeID)
					_ = h.store.ReleaseRouteLease(ctx, routeID, h.nodeID)
				}
				h.mu.Lock()
				delete(tc.activatedRoutes, routeID)
				h.mu.Unlock()
				result = map[string]any{
					"route_id": routeID,
					"status":   "rejected",
					"error": map[string]string{
						"code":    "internal_error",
						"message": "Failed to persist route activation",
					},
				}
				break
			}
			result = map[string]any{
				"route_id":   routeID,
				"status":     "active",
				"activation": activation,
			}
		}

		if supersededTunnel != nil {
			h.stopRouteBusSubscription(supersededTunnel, routeID)
			_ = supersededTunnel.writeJSON(map[string]any{
				"type":     "tunnel.route_deactivated",
				"route_id": routeID,
				"reason":   "superseded",
				"at":       now,
			})
		}
		results = append(results, result)
	}

	_ = tc.writeJSON(map[string]any{
		"type":       "tunnel.activate.result",
		"request_id": requestID,
		"results":    results,
	})
}

func (h *Handler) handleTunnelDeactivate(ctx context.Context, tc *tunnelConn, frame map[string]any) {
	requestID := firstStringMap(frame, "request_id")
	if requestID == "" {
		requestID = "deact_" + uuid.New().String()[:8]
	}

	routesRaw, ok := frame["routes"].([]any)
	if !ok || len(routesRaw) == 0 {
		_ = tc.writeJSON(map[string]any{"type": "tunnel.deactivate.result", "request_id": requestID, "results": []any{}})
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	results := make([]map[string]any, 0, len(routesRaw))
	for _, rawRoute := range routesRaw {
		routeID := ""
		switch value := rawRoute.(type) {
		case string:
			routeID = strings.TrimSpace(value)
		case map[string]any:
			routeID = firstStringMap(value, "route_id")
		}
		if routeID == "" {
			continue
		}

		activeDeviceID, active, err := h.store.GetActiveRouteDevice(ctx, routeID)
		if err != nil {
			results = append(results, map[string]any{
				"route_id": routeID,
				"status":   "rejected",
				"error": map[string]string{
					"code":    "internal_error",
					"message": "Failed to load active route state",
				},
			})
			continue
		}
		if active && activeDeviceID == tc.deviceID {
			if err := h.store.DeleteActiveRoute(ctx, routeID); err != nil {
				results = append(results, map[string]any{
					"route_id": routeID,
					"status":   "rejected",
					"error": map[string]string{
						"code":    "internal_error",
						"message": "Failed to deactivate route",
					},
				})
				continue
			}
			h.mu.Lock()
			delete(tc.activatedRoutes, routeID)
			h.mu.Unlock()
			h.stopRouteBusSubscription(tc, routeID)
			if err := h.store.ReleaseRouteLease(ctx, routeID, h.nodeID); err != nil {
				results = append(results, map[string]any{
					"route_id": routeID,
					"status":   "rejected",
					"error": map[string]string{
						"code":    "internal_error",
						"message": "Failed to release route lease",
					},
				})
				continue
			}
			if err := h.setTunnelRouteStatus(ctx, routeID, tc.deviceID, "inactive", now, false); err != nil {
				results = append(results, map[string]any{
					"route_id": routeID,
					"status":   "rejected",
					"error": map[string]string{
						"code":    "internal_error",
						"message": "Failed to persist route state",
					},
				})
				continue
			}
			results = append(results, map[string]any{"route_id": routeID, "status": "inactive"})
			continue
		}
		results = append(results, map[string]any{
			"route_id": routeID,
			"status":   "rejected",
			"error": map[string]string{
				"code":    "route_not_found",
				"message": "Route not active on this tunnel",
			},
		})
	}

	_ = tc.writeJSON(map[string]any{
		"type":       "tunnel.deactivate.result",
		"request_id": requestID,
		"results":    results,
	})
}

func (h *Handler) handleTunnelResponse(ctx context.Context, tc *tunnelConn, frame map[string]any) {
	requestID := firstStringMap(frame, "request_id")
	if requestID == "" {
		return
	}

	status := 200
	switch rawStatus := frame["status"].(type) {
	case float64:
		status = int(rawStatus)
	case int:
		status = rawStatus
	case int32:
		status = int(rawStatus)
	case int64:
		status = int(rawStatus)
	}

	headers := make([][]string, 0)
	if rawHeaders, ok := frame["headers"].([]any); ok {
		for _, rawHeader := range rawHeaders {
			pair, ok := rawHeader.([]any)
			if !ok || len(pair) != 2 {
				continue
			}
			key, _ := pair[0].(string)
			value, _ := pair[1].(string)
			if strings.TrimSpace(key) == "" {
				continue
			}
			headers = append(headers, []string{key, value})
		}
	}

	resp := &tunnelResponse{
		Status:     status,
		Headers:    headers,
		BodyBase64: firstStringMap(frame, "body_base64"),
	}

	h.mu.Lock()
	inflight, found := h.inflightRequests[requestID]
	if found {
		if inflight.deviceID != tc.deviceID {
			h.mu.Unlock()
			slog.Warn("response ownership mismatch", "request", requestID, "expected_device", inflight.deviceID, "got_device", tc.deviceID)
			_ = tc.writeJSON(map[string]any{
				"type":       "tunnel.error",
				"error":      "response_ownership_mismatch",
				"request_id": requestID,
				"message":    "You do not own this inflight request",
			})
			return
		}
		delete(h.inflightRequests, requestID)
	}
	h.mu.Unlock()

	if !found || inflight == nil {
		return
	}

	if inflight.publishResponseToBus {
		if err := h.bus.PublishTunnelResponse(ctx, requestID, TunnelResponseMessage{
			RequestID:  requestID,
			RouteID:    inflight.routeID,
			Status:     resp.Status,
			Headers:    resp.Headers,
			BodyBase64: resp.BodyBase64,
		}); err != nil {
			slog.Warn("bus publish response failed", "request", requestID, "route", inflight.routeID, "err", err)
		}
		return
	}

	if inflight.responseCh != nil {
		select {
		case inflight.responseCh <- resp:
		default:
		}
	}
}

func (h *Handler) deactivateAllTunnelRoutes(ctx context.Context, tc *tunnelConn, reason string) {
	now := time.Now().UTC().Format(time.RFC3339)

	h.mu.Lock()
	routeIDs := make([]string, 0, len(tc.activatedRoutes))
	for routeID := range tc.activatedRoutes {
		routeIDs = append(routeIDs, routeID)
	}
	tc.activatedRoutes = make(map[string]bool)
	subs := make([]*routeBusSub, 0, len(tc.routeBusSubs))
	for routeID, rs := range tc.routeBusSubs {
		delete(tc.routeBusSubs, routeID)
		subs = append(subs, rs)
	}
	h.mu.Unlock()
	for _, rs := range subs {
		rs.stop()
	}

	routesToDeactivate := make([]string, 0, len(routeIDs))
	for _, routeID := range routeIDs {
		activeDeviceID, active, err := h.store.GetActiveRouteDevice(ctx, routeID)
		if err != nil || !active || activeDeviceID != tc.deviceID {
			continue
		}
		if err := h.store.DeleteActiveRoute(ctx, routeID); err != nil {
			continue
		}
		if err := h.store.ReleaseRouteLease(ctx, routeID, h.nodeID); err != nil {
			slog.Warn("failed to release lease", "route", routeID, "err", err)
		}
		routesToDeactivate = append(routesToDeactivate, routeID)
		if err := h.setTunnelRouteStatus(ctx, routeID, tc.deviceID, "provisioned", now, false); err != nil {
			slog.Warn("failed to persist deactivation", "route", routeID, "err", err)
		}
	}

	if reason != "" {
		slog.Info("deactivated routes", "count", len(routesToDeactivate), "device", tc.deviceID, "reason", reason)
	}
}

func coerceHeaderPairs(raw any) [][]string {
	if raw == nil {
		return nil
	}
	switch typed := raw.(type) {
	case [][]string:
		out := make([][]string, 0, len(typed))
		for _, pair := range typed {
			if len(pair) != 2 {
				continue
			}
			if strings.TrimSpace(pair[0]) == "" {
				continue
			}
			out = append(out, []string{pair[0], pair[1]})
		}
		return out
	case []any:
		out := make([][]string, 0, len(typed))
		for _, item := range typed {
			switch pair := item.(type) {
			case []any:
				if len(pair) != 2 {
					continue
				}
				key, _ := pair[0].(string)
				value, _ := pair[1].(string)
				if strings.TrimSpace(key) == "" {
					continue
				}
				out = append(out, []string{key, value})
			case []string:
				if len(pair) != 2 {
					continue
				}
				if strings.TrimSpace(pair[0]) == "" {
					continue
				}
				out = append(out, []string{pair[0], pair[1]})
			}
		}
		return out
	default:
		return nil
	}
}

func intFromAny(raw any, fallback int) int {
	switch value := raw.(type) {
	case int:
		return value
	case int32:
		return int(value)
	case int64:
		return int(value)
	case float64:
		return int(value)
	case float32:
		return int(value)
	case string:
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return fallback
		}
		parsed, err := strconv.Atoi(trimmed)
		if err != nil {
			return fallback
		}
		return parsed
	default:
		return fallback
	}
}

func (h *Handler) sendTunnelRequest(ctx context.Context, routeID string, requestFrame map[string]any) (*inflightRequest, error) {
	requestID := firstStringMap(requestFrame, "request_id")
	if requestID == "" {
		requestID = "req_" + uuid.New().String()[:12]
		requestFrame["request_id"] = requestID
	}

	deviceID, active, err := h.store.GetActiveRouteDevice(ctx, routeID)
	if err != nil {
		return nil, fmt.Errorf("active_route_lookup_failed: %w", err)
	}
	if !active {
		return nil, fmt.Errorf("tunnel_not_connected")
	}
	_, claimed, err := h.store.GetRouteLease(ctx, routeID)
	if err != nil {
		return nil, fmt.Errorf("route_lease_lookup_failed: %w", err)
	}
	if !claimed {
		_ = h.store.DeleteActiveRoute(ctx, routeID)
		return nil, fmt.Errorf("route_not_claimed")
	}

	deadlineMS := intFromAny(requestFrame["deadline_ms"], 0)
	waitTimeout := inflightRequestMaxAge
	if deadlineMS > 0 {
		waitTimeout = time.Duration(deadlineMS) * time.Millisecond
	}
	if waitTimeout <= 0 {
		waitTimeout = inflightRequestMaxAge
	}

	waiter := &inflightRequest{
		requestID:  requestID,
		routeID:    routeID,
		deviceID:   deviceID,
		responseCh: make(chan *tunnelResponse, 1),
		createdAt:  time.Now().UTC(),
	}

	respCh := make(chan TunnelResponseMessage, 1)
	subCtx, cancel := context.WithTimeout(ctx, waitTimeout)
	unsub, subErr := h.bus.SubscribeTunnelResponses(subCtx, requestID, respCh)
	if subErr != nil {
		cancel()
		return nil, fmt.Errorf("cross_node_subscribe_failed: %w", subErr)
	}
	go func() {
		defer cancel()
		defer unsub()
		select {
		case resp, ok := <-respCh:
			if !ok {
				return
			}
			tr := &tunnelResponse{
				Status:     resp.Status,
				Headers:    resp.Headers,
				BodyBase64: resp.BodyBase64,
			}
			select {
			case waiter.responseCh <- tr:
			default:
			}
		case <-subCtx.Done():
		}
	}()

	busReq := TunnelRequestMessage{
		RequestID:       requestID,
		RouteID:         routeID,
		Method:          asString(requestFrame["method"]),
		Scheme:          asString(requestFrame["scheme"]),
		Host:            asString(requestFrame["host"]),
		ExternalURL:     asString(requestFrame["external_url"]),
		RawTarget:       asString(requestFrame["raw_target"]),
		RawTargetBase64: asString(requestFrame["raw_target_base64"]),
		Path:            asString(requestFrame["path"]),
		Query:           asString(requestFrame["query"]),
		Headers:         coerceHeaderPairs(requestFrame["headers"]),
		BodyBase64:      asString(requestFrame["body_base64"]),
		DeadlineMS:      deadlineMS,
		ReceivedAt:      time.Now().UTC(),
	}

	publishTimeout := tunnelBusPublishTimeout
	if waitTimeout > 0 && waitTimeout < publishTimeout {
		publishTimeout = waitTimeout
	}
	if publishTimeout <= 0 {
		publishTimeout = tunnelBusPublishTimeout
	}
	publishCtx, publishCancel := context.WithTimeout(ctx, publishTimeout)
	defer publishCancel()
	if err := h.bus.PublishTunnelRequest(publishCtx, routeID, busReq); err != nil {
		cancel()
		unsub()
		if errors.Is(err, ErrMessageBusNoSubscribers) || errors.Is(err, ErrMessageBusBackpressure) {
			return nil, fmt.Errorf("tunnel_dispatch_unavailable: %w", err)
		}
		return nil, fmt.Errorf("cross_node_publish_failed: %w", err)
	}

	return waiter, nil
}

func (h *Handler) startTunnelLeaseHeartbeat(tc *tunnelConn, stop <-chan struct{}) {
	ticker := time.NewTicker(routeLeaseRenewEvery)
	defer ticker.Stop()

	for {
		select {
		case <-h.done:
			return
		case <-stop:
			return
		case <-ticker.C:
			h.renewTunnelLeases(tc)
		}
	}
}

func (h *Handler) renewTunnelLeases(tc *tunnelConn) {
	h.mu.RLock()
	current, ok := h.tunnelConns[tc.deviceID]
	if !ok || current != tc {
		h.mu.RUnlock()
		return
	}
	routeIDs := make([]string, 0, len(tc.activatedRoutes))
	for routeID := range tc.activatedRoutes {
		routeIDs = append(routeIDs, routeID)
	}
	h.mu.RUnlock()

	for _, routeID := range routeIDs {
		if _, renewed, err := h.store.RenewRouteLease(tc.ctx, routeID, h.nodeID, routeLeaseTTL); err != nil {
			slog.Warn("lease renew failed", "route", routeID, "err", err)
			continue
		} else if !renewed {
			h.handleLostTunnelLease(tc, routeID)
		}
	}
}

func (h *Handler) handleLostTunnelLease(tc *tunnelConn, routeID string) {
	now := time.Now().UTC().Format(time.RFC3339)

	h.mu.Lock()
	current, ok := h.tunnelConns[tc.deviceID]
	if !ok || current != tc {
		h.mu.Unlock()
		return
	}
	if !tc.activatedRoutes[routeID] {
		h.mu.Unlock()
		return
	}
	delete(tc.activatedRoutes, routeID)
	rs := tc.routeBusSubs[routeID]
	delete(tc.routeBusSubs, routeID)
	h.mu.Unlock()
	rs.stop()

	activeDeviceID, active, err := h.store.GetActiveRouteDevice(tc.ctx, routeID)
	if err == nil && active && activeDeviceID == tc.deviceID {
		_ = h.store.DeleteActiveRoute(tc.ctx, routeID)
	}
	if err := h.setTunnelRouteStatus(tc.ctx, routeID, tc.deviceID, "inactive", now, false); err != nil {
		slog.Warn("failed to persist lost-lease", "route", routeID, "err", err)
	}

	if tc.conn != nil {
		_ = tc.writeJSON(map[string]any{
			"type":     "tunnel.route_deactivated",
			"route_id": routeID,
			"reason":   "lease_lost",
			"at":       now,
		})
	}
}

func (h *Handler) setTunnelRouteStatus(ctx context.Context, routeID, expectedDeviceID, nextStatus, updatedAt string, strict bool) error {
	_, err := h.store.UpdateIntegrationRoute(ctx, routeID, func(route *integrationRoute) error {
		if route == nil {
			return ErrRouteNotFound
		}
		if expectedDeviceID != "" && route.DeviceID != expectedDeviceID {
			return errRouteStatusUpdateSkipped
		}
		if route.Status == "revoked" {
			return errRouteStatusUpdateSkipped
		}
		route.Status = nextStatus
		route.UpdatedAt = updatedAt
		return nil
	})
	if err == nil {
		return nil
	}
	if strict {
		return err
	}
	if errors.Is(err, ErrRouteNotFound) || errors.Is(err, errRouteStatusUpdateSkipped) {
		return nil
	}
	return err
}

func (h *Handler) startInflightSweeper() {
	ticker := time.NewTicker(inflightSweepInterval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-h.done:
				return
			case now := <-ticker.C:
				h.mu.Lock()
				pruned := h.pruneStaleInflightRequestsLocked(now.UTC())
				h.mu.Unlock()
				if pruned > 0 {
					slog.Info("pruned stale inflight", "count", pruned)
				}
			}
		}
	}()
}

func (h *Handler) removeInflightRequestsForDeviceLocked(deviceID string) {
	for requestID, inflight := range h.inflightRequests {
		if inflight != nil && inflight.deviceID == deviceID {
			h.dropInflightRequestLocked(requestID, inflight)
		}
	}
}

func (h *Handler) pruneStaleInflightRequestsLocked(now time.Time) int {
	cutoff := now.Add(-inflightRequestMaxAge)
	pruned := 0
	for requestID, inflight := range h.inflightRequests {
		if inflight == nil {
			h.dropInflightRequestLocked(requestID, inflight)
			pruned++
			continue
		}
		if inflight.createdAt.Before(cutoff) {
			h.dropInflightRequestLocked(requestID, inflight)
			pruned++
		}
	}
	return pruned
}

func (h *Handler) dropInflightRequestLocked(requestID string, inflight *inflightRequest) {
	delete(h.inflightRequests, requestID)
	if inflight == nil {
		return
	}
	select {
	case inflight.responseCh <- nil:
	default:
	}
}
