package gateway

import (
	"encoding/json"
	"fmt"
	"log"
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
	tunnelPingInterval    = 30 * time.Second
	tunnelPongTimeout     = 10 * time.Second
	inflightSweepInterval = 10 * time.Second
	inflightRequestMaxAge = 2 * time.Minute
)

var wsConnIDCounter uint64

type tunnelConn struct {
	deviceID        string
	ownerUID        string
	connID          string
	conn            *websocket.Conn
	connectedAt     time.Time
	lastSeenAt      time.Time
	sendMu          sync.Mutex
	activatedRoutes map[string]bool
}

func (tc *tunnelConn) writeJSON(payload map[string]any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	tc.sendMu.Lock()
	defer tc.sendMu.Unlock()
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
	createdAt  time.Time
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

	h.mu.RLock()
	device, found := h.devices[deviceID]
	h.mu.RUnlock()
	if !found {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "device_not_found"})
	}
	if device.OwnerUID != principal.UID {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
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
	state := &tunnelConn{
		deviceID:        deviceID,
		ownerUID:        ownerUID,
		connID:          connID,
		conn:            c,
		connectedAt:     now,
		lastSeenAt:      now,
		activatedRoutes: make(map[string]bool),
	}

	var replaced *tunnelConn
	h.mu.Lock()
	if existing, ok := h.tunnelConns[deviceID]; ok {
		replaced = existing
	}
	h.tunnelConns[deviceID] = state
	h.mu.Unlock()

	if replaced != nil && replaced != state {
		h.deactivateAllTunnelRoutes(replaced, "superseded")
		replaced.closeWithMessage(websocket.CloseNormalClosure, "replaced_by_new_connection")
	}

	_ = state.writeJSON(map[string]any{
		"type":      "tunnel.connected",
		"device_id": deviceID,
		"at":        now.Format(time.RFC3339),
	})

	stopPing := make(chan struct{})
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
					return
				}
			}
		}
	}()

	c.SetPongHandler(func(string) error {
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

		h.mu.Lock()
		if current, ok := h.tunnelConns[deviceID]; ok && current == state {
			current.lastSeenAt = time.Now().UTC()
		}
		h.mu.Unlock()

		if messageType != websocket.TextMessage && messageType != websocket.BinaryMessage {
			continue
		}
		h.handleTunnelFrame(state, payload)
	}

	close(stopPing)

	wasActive := false
	h.mu.Lock()
	if current, ok := h.tunnelConns[deviceID]; ok && current == state {
		delete(h.tunnelConns, deviceID)
		h.removeInflightRequestsForDeviceLocked(deviceID)
		wasActive = true
	}
	h.mu.Unlock()

	if wasActive {
		h.deactivateAllTunnelRoutes(state, "connection_lost")
	}
	_ = c.Close()
}

func (h *Handler) handleTunnelFrame(tc *tunnelConn, payload []byte) {
	var frame map[string]any
	if err := json.Unmarshal(payload, &frame); err != nil {
		_ = tc.writeJSON(map[string]any{"type": "tunnel.error", "error": "invalid_json"})
		return
	}

	switch firstStringMap(frame, "type") {
	case "tunnel.activate":
		h.handleTunnelActivate(tc, frame)
	case "tunnel.deactivate":
		h.handleTunnelDeactivate(tc, frame)
	case "tunnel.response":
		h.handleTunnelResponse(tc, frame)
	case "ping", "heartbeat":
		return
	default:
		_ = tc.writeJSON(map[string]any{"type": "tunnel.error", "error": "unknown_frame_type"})
	}
}

func (h *Handler) handleTunnelActivate(tc *tunnelConn, frame map[string]any) {
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

		h.mu.Lock()
		route, found := h.integrationRoutes[routeID]
		switch {
		case !found:
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
			if existingDeviceID, active := h.activeRoutes[routeID]; active && existingDeviceID != tc.deviceID {
				if old, hasOld := h.tunnelConns[existingDeviceID]; hasOld {
					delete(old.activatedRoutes, routeID)
					supersededTunnel = old
				}
				activation = "superseded"
			}
			h.activeRoutes[routeID] = tc.deviceID
			tc.activatedRoutes[routeID] = true
			route.Status = "active"
			route.UpdatedAt = now
			result = map[string]any{
				"route_id":   routeID,
				"status":     "active",
				"activation": activation,
			}
		}
		h.mu.Unlock()

		if supersededTunnel != nil {
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

func (h *Handler) handleTunnelDeactivate(tc *tunnelConn, frame map[string]any) {
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

		h.mu.Lock()
		if activeDeviceID, active := h.activeRoutes[routeID]; active && activeDeviceID == tc.deviceID {
			delete(h.activeRoutes, routeID)
			delete(tc.activatedRoutes, routeID)
			if route, found := h.integrationRoutes[routeID]; found {
				route.Status = "inactive"
				route.UpdatedAt = now
			}
			h.mu.Unlock()
			results = append(results, map[string]any{"route_id": routeID, "status": "inactive"})
			continue
		}
		h.mu.Unlock()
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

func (h *Handler) handleTunnelResponse(tc *tunnelConn, frame map[string]any) {
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
			log.Printf("[tunnel] response ownership mismatch: request=%s expected_device=%s got_device=%s", requestID, inflight.deviceID, tc.deviceID)
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

	if found && inflight != nil {
		select {
		case inflight.responseCh <- resp:
		default:
		}
	}
}

func (h *Handler) deactivateAllTunnelRoutes(tc *tunnelConn, reason string) {
	now := time.Now().UTC().Format(time.RFC3339)

	h.mu.Lock()
	routesToDeactivate := make([]string, 0, len(tc.activatedRoutes))
	for routeID := range tc.activatedRoutes {
		if activeDeviceID, active := h.activeRoutes[routeID]; active && activeDeviceID == tc.deviceID {
			delete(h.activeRoutes, routeID)
			routesToDeactivate = append(routesToDeactivate, routeID)
		}
	}
	tc.activatedRoutes = make(map[string]bool)
	for _, routeID := range routesToDeactivate {
		if route, found := h.integrationRoutes[routeID]; found && route.Status != "revoked" {
			route.Status = "provisioned"
			route.UpdatedAt = now
		}
	}
	h.mu.Unlock()

	if reason != "" {
		log.Printf("[tunnel] deactivated %d routes for device=%s reason=%s", len(routesToDeactivate), tc.deviceID, reason)
	}
}

func (h *Handler) sendTunnelRequest(routeID string, requestFrame map[string]any) (*inflightRequest, error) {
	requestID := firstStringMap(requestFrame, "request_id")
	if requestID == "" {
		requestID = "req_" + uuid.New().String()[:12]
		requestFrame["request_id"] = requestID
	}

	h.mu.Lock()
	_ = h.pruneStaleInflightRequestsLocked(time.Now().UTC())
	deviceID, active := h.activeRoutes[routeID]
	if !active {
		h.mu.Unlock()
		return nil, fmt.Errorf("tunnel_not_connected")
	}
	tunnel, ok := h.tunnelConns[deviceID]
	if !ok || tunnel == nil {
		delete(h.activeRoutes, routeID)
		h.mu.Unlock()
		return nil, fmt.Errorf("tunnel_not_connected")
	}
	if len(h.inflightRequests) >= maxInflightRequests {
		h.mu.Unlock()
		return nil, fmt.Errorf("too_many_inflight_requests")
	}

	inflight := &inflightRequest{
		requestID:  requestID,
		routeID:    routeID,
		deviceID:   deviceID,
		responseCh: make(chan *tunnelResponse, 1),
		createdAt:  time.Now().UTC(),
	}
	h.inflightRequests[requestID] = inflight
	h.mu.Unlock()

	writeFn := h.tunnelWriteFn
	if writeFn == nil {
		writeFn = func(tc *tunnelConn, payload map[string]any) error {
			return tc.writeJSON(payload)
		}
	}
	if err := writeFn(tunnel, requestFrame); err != nil {
		h.mu.Lock()
		delete(h.inflightRequests, requestID)
		h.mu.Unlock()
		return nil, fmt.Errorf("tunnel_write_failed: %w", err)
	}

	return inflight, nil
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
					log.Printf("[tunnel] pruned_stale_inflight count=%d", pruned)
				}
			}
		}
	}()
}

func (h *Handler) removeInflightRequestsForDeviceLocked(deviceID string) {
	for requestID, inflight := range h.inflightRequests {
		if inflight == nil {
			h.dropInflightRequestLocked(requestID, inflight)
			continue
		}
		if inflight.deviceID == deviceID {
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
