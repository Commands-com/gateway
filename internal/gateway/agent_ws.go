package gateway

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofiber/contrib/v3/websocket"
	"github.com/gofiber/fiber/v3"

	"oss-commands-gateway/internal/auth"
)

const maxAgentConnectionsPerOwner = 50

type agentConn struct {
	deviceID         string
	ownerUID         string
	connID           string
	conn             *websocket.Conn
	connectedAt      time.Time
	lastSeenAt       time.Time
	lastTransportSeq int
	sendMu           sync.Mutex
}

func (ac *agentConn) writeJSON(payload map[string]any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ac.sendMu.Lock()
	defer ac.sendMu.Unlock()
	return ac.conn.WriteMessage(websocket.TextMessage, raw)
}

func (ac *agentConn) closeWithMessage(code int, reason string) {
	ac.sendMu.Lock()
	defer ac.sendMu.Unlock()
	_ = ac.conn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(code, reason),
		time.Now().Add(2*time.Second),
	)
	_ = ac.conn.Close()
}

func (h *Handler) RequireAgentWebSocketUpgrade(c fiber.Ctx) error {
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
	ownerConnCount := 0
	for _, conn := range h.agents {
		if conn.ownerUID == principal.UID {
			ownerConnCount++
		}
	}
	h.mu.RUnlock()
	if !found {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "device_not_found"})
	}
	if device.OwnerUID != principal.UID {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
	}

	headerDeviceID := strings.TrimSpace(c.Get("X-Device-Id"))
	if headerDeviceID != "" {
		normalizedHeaderDeviceID, err := validateID(headerDeviceID, "X-Device-Id")
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid X-Device-Id header"})
		}
		if normalizedHeaderDeviceID != deviceID {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "X-Device-Id header does not match device_id query param"})
		}
	}

	if ownerConnCount >= maxAgentConnectionsPerOwner {
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{"error": "too many agent connections"})
	}
	if !c.IsWebSocket() {
		return fiber.ErrUpgradeRequired
	}

	c.Locals("gateway_owner_uid", principal.UID)
	c.Locals("gateway_device_id", deviceID)
	return c.Next()
}

func (h *Handler) AgentConnectWebSocket() fiber.Handler {
	return websocket.New(h.handleAgentConnect, websocket.Config{EnableCompression: true})
}

func (h *Handler) handleAgentConnect(c *websocket.Conn) {
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
	connID := fmt.Sprintf("agt:%d", atomic.AddUint64(&wsConnIDCounter, 1))
	state := &agentConn{
		deviceID:         deviceID,
		ownerUID:         ownerUID,
		connID:           connID,
		conn:             c,
		connectedAt:      now,
		lastSeenAt:       now,
		lastTransportSeq: 0,
	}

	var replaced *agentConn
	h.mu.Lock()
	ownerConnCount := 0
	for _, existing := range h.agents {
		if existing.ownerUID == ownerUID {
			ownerConnCount++
		}
	}
	if ownerConnCount >= maxAgentConnectionsPerOwner {
		h.mu.Unlock()
		_ = c.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "too_many_connections"),
			time.Now().Add(2*time.Second),
		)
		_ = c.Close()
		return
	}
	if existing, ok := h.agents[deviceID]; ok {
		replaced = existing
	}
	h.agents[deviceID] = state
	h.mu.Unlock()

	if replaced != nil && replaced != state {
		replaced.closeWithMessage(websocket.CloseNormalClosure, "replaced_by_new_connection")
	}

	_ = state.writeJSON(map[string]any{
		"type":      "gateway.connected",
		"device_id": deviceID,
		"at":        now.Format(time.RFC3339),
	})

	for {
		messageType, payload, err := c.ReadMessage()
		if err != nil {
			break
		}

		h.mu.Lock()
		if current, ok := h.agents[deviceID]; ok && current == state {
			current.lastSeenAt = time.Now().UTC()
		}
		h.mu.Unlock()

		if messageType != websocket.TextMessage && messageType != websocket.BinaryMessage {
			continue
		}
		h.handleAgentFrame(deviceID, payload, state)
	}

	h.mu.Lock()
	if current, ok := h.agents[deviceID]; ok && current == state {
		delete(h.agents, deviceID)
	}
	h.mu.Unlock()
	_ = c.Close()
}

func (h *Handler) handleAgentFrame(deviceID string, payload []byte, connState *agentConn) {
	var frame map[string]any
	if err := json.Unmarshal(payload, &frame); err != nil {
		_ = connState.writeJSON(map[string]any{"type": "agent.error", "error": "invalid_json"})
		return
	}

	frameType := firstStringMap(frame, "type", "event")
	switch frameType {
	case "heartbeat":
		return
	case "ping":
		_ = connState.writeJSON(map[string]any{
			"type":      "heartbeat",
			"device_id": deviceID,
			"at":        time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	sessionID := strings.TrimSpace(firstStringMap(frame, "session_id", "sessionId"))
	handshakeID := strings.TrimSpace(firstStringMap(frame, "handshake_id", "handshakeId"))
	if sessionID == "" {
		return
	}
	if !h.isSessionBoundToDevice(sessionID, handshakeID, deviceID) {
		_ = connState.writeJSON(map[string]any{
			"type":         "agent.error",
			"error":        "unauthorized_session_frame",
			"session_id":   sessionID,
			"handshake_id": handshakeID,
		})
		return
	}

	if frameType == "session.handshake.ack" {
		now := time.Now().UTC().Unix()
		h.mu.RLock()
		state, ok := h.sessions[sessionID]
		h.mu.RUnlock()
		if ok {
			state.mu.Lock()
			if state.DeviceID == deviceID && (handshakeID == "" || state.HandshakeID == handshakeID) {
				if strings.TrimSpace(firstStringMap(frame, "status")) == "error" {
					state.Status = "agent_error"
				} else {
					state.Status = "agent_acknowledged"
				}
				state.UpdatedAt = now
			}
			state.mu.Unlock()
		}
	}

	h.appendSessionEvent(sessionID, payload)
}

func (h *Handler) isSessionBoundToDevice(sessionID, handshakeID, deviceID string) bool {
	h.mu.RLock()
	state, ok := h.sessions[sessionID]
	h.mu.RUnlock()
	if !ok {
		return false
	}
	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.DeviceID != deviceID {
		return false
	}
	if handshakeID != "" && state.HandshakeID != handshakeID {
		return false
	}
	return true
}

func (h *Handler) sendToAgentForSession(sessionID string, payload map[string]any) {
	h.mu.RLock()
	state, found := h.sessions[sessionID]
	h.mu.RUnlock()
	if !found {
		return
	}
	state.mu.RLock()
	deviceID := state.DeviceID
	state.mu.RUnlock()

	h.mu.RLock()
	conn := h.agents[deviceID]
	h.mu.RUnlock()
	if conn == nil {
		return
	}

	writeFn := h.agentWriteFn
	if writeFn == nil {
		writeFn = func(ac *agentConn, frame map[string]any) error {
			return ac.writeJSON(frame)
		}
	}
	_ = writeFn(conn, payload)
}
