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

	"oss-commands-gateway/internal/auth"
	"oss-commands-gateway/internal/gatewaycrypto"
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
	if h.transportTokenIssuer != nil {
		transportToken := h.transportTokenIssuer.IssueToken(deviceID, connID, h.transportTokenTTL)
		if err := state.writeJSON(map[string]any{
			"type":            "transport.init",
			"device_id":       deviceID,
			"connection_id":   connID,
			"transport_token": transportToken,
			"expires_in":      int(h.transportTokenTTL / time.Second),
			"at":              now.Format(time.RFC3339),
		}); err != nil {
			// Clean up agent state on init write failure to avoid memory leak
			h.mu.Lock()
			if current, ok := h.agents[deviceID]; ok && current == state {
				delete(h.agents, deviceID)
			}
			h.mu.Unlock()
			_ = c.Close()
			return
		}
	}
	h.flushPendingHandshakes(deviceID)

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

	if violation := h.validateAndAdvanceTransportFrame(deviceID, connState, frame); violation != "" {
		log.Printf("[gateway] transport_rejected device=%s conn=%s violation=%s", deviceID, connState.connID, violation)
		return
	}
	delete(frame, "transport_token")
	delete(frame, "t_seq")
	delete(frame, "connection_id")

	sessionID := strings.TrimSpace(firstStringMap(frame, "session_id", "sessionId"))
	handshakeID := strings.TrimSpace(firstStringMap(frame, "handshake_id", "handshakeId"))
	if sessionID == "" {
		return
	}

	if frameType != "session.handshake.ack" && !h.hasCompletedHandshakeBinding(sessionID, deviceID, handshakeID) {
		_ = connState.writeJSON(map[string]any{
			"type":         "agent.error",
			"error":        "unauthorized_session_frame",
			"session_id":   sessionID,
			"handshake_id": handshakeID,
		})
		return
	}

	if frameType == "session.handshake.ack" {
		if !h.processAgentHandshakeAckFrame(deviceID, sessionID, handshakeID, frame) {
			return
		}
	}

	if encryptedSessionFrameTypes[frameType] {
		h.mu.RLock()
		state, ok := h.sessions[sessionID]
		h.mu.RUnlock()
		if !ok {
			return
		}

		nowUnix := time.Now().UTC().Unix()
		state.mu.Lock()
		if state.DeviceID != deviceID || state.Status != "agent_acknowledged" {
			state.mu.Unlock()
			return
		}
		if handshakeID != "" && state.HandshakeID != handshakeID {
			state.mu.Unlock()
			return
		}
		if state.ConversationID != "" {
			frame["conversation_id"] = state.ConversationID
		}
		if violation := validateEncryptedEnvelope(frame); violation != "" {
			state.UpdatedAt = nowUnix
			state.mu.Unlock()
			log.Printf("[gateway] encryption_violation dir=agent_to_client device=%s session=%s frame=%s violation=%s", deviceID, sessionID, frameType, violation)
			if h.cfg.RequireEncryptedFrames {
				return
			}
		} else {
			seq, _ := extractPositiveInt(frame, "seq")
			if seq <= state.SeqAgentToClient {
				state.mu.Unlock()
				log.Printf("[gateway] replay_rejected dir=agent_to_client device=%s session=%s frame=%s seq=%d", deviceID, sessionID, frameType, seq)
				return
			}
			state.SeqAgentToClient = seq
			state.UpdatedAt = nowUnix
			state.mu.Unlock()
		}
	}

	if strings.TrimSpace(firstStringMap(frame, "conversation_id", "conversationId")) == "" {
		h.mu.RLock()
		state, ok := h.sessions[sessionID]
		h.mu.RUnlock()
		if ok {
			state.mu.RLock()
			if state.ConversationID != "" {
				frame["conversation_id"] = state.ConversationID
			}
			state.mu.RUnlock()
		}
	}

	raw, err := json.Marshal(frame)
	if err != nil {
		return
	}
	h.appendSessionEvent(sessionID, raw)
}

func (h *Handler) processAgentHandshakeAckFrame(deviceID, sessionID, handshakeID string, frame map[string]any) bool {
	h.mu.RLock()
	state, found := h.sessions[sessionID]
	device, hasDevice := h.devices[deviceID]
	h.mu.RUnlock()
	if !found {
		return false
	}

	nowUnix := time.Now().UTC().Unix()
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.DeviceID != deviceID {
		return false
	}
	if handshakeID != "" && state.HandshakeID != handshakeID {
		return false
	}
	if state.HandshakeID != "" {
		frame["handshake_id"] = state.HandshakeID
	}
	if state.ConversationID != "" {
		frame["conversation_id"] = state.ConversationID
	}
	frame["session_id"] = state.SessionID
	frame["device_id"] = state.DeviceID

	if strings.TrimSpace(firstStringMap(frame, "status")) == "error" {
		lastErr := strings.TrimSpace(firstStringMap(frame, "error", "details", "message"))
		if lastErr == "" {
			lastErr = "agent handshake error"
		}
		state.Status = "agent_error"
		state.LastError = lastErr
		state.UpdatedAt = nowUnix
		frame["status"] = "agent_error"
		frame["error"] = lastErr
		return true
	}

	agentEphemeral := strings.TrimSpace(firstStringMap(frame, "agent_ephemeral_public_key", "agentEphemeralPublicKey"))
	agentSignature := strings.TrimSpace(firstStringMap(frame, "agent_identity_signature", "agentIdentitySignature"))
	transcriptHash := strings.TrimSpace(firstStringMap(frame, "transcript_hash", "transcriptHash"))

	lastErr := ""
	switch {
	case agentEphemeral == "" || agentSignature == "" || transcriptHash == "":
		lastErr = "missing handshake ack fields from agent websocket frame"
	case state.ClientEphemeralPublicKey == "" || state.ClientSessionNonce == "":
		lastErr = "client handshake fields missing on gateway state"
	case !hasDevice || strings.TrimSpace(device.IdentityKey) == "":
		lastErr = "device identity not found"
	default:
		if err := gatewaycrypto.ValidateX25519PublicKey(agentEphemeral); err != nil {
			lastErr = err.Error()
		} else {
			expectedTranscript := gatewaycrypto.BuildTranscriptHash(
				state.SessionID,
				state.HandshakeID,
				state.ClientEphemeralPublicKey,
				state.ClientSessionNonce,
				agentEphemeral,
			)
			if !gatewaycrypto.ConstantTimeEqualBase64(expectedTranscript, transcriptHash) {
				lastErr = "transcript hash mismatch"
			} else if err := gatewaycrypto.VerifyAgentSignature(device.IdentityKey, transcriptHash, agentSignature); err != nil {
				lastErr = fmt.Sprintf("signature verification failed: %v", err)
			}
		}
	}

	if lastErr != "" {
		state.Status = "agent_error"
		state.LastError = lastErr
		state.UpdatedAt = nowUnix
		frame["status"] = "agent_error"
		frame["error"] = lastErr
		return true
	}

	state.AgentEphemeralPublicKey = agentEphemeral
	state.AgentIdentitySignature = agentSignature
	state.TranscriptHash = transcriptHash
	state.Status = "agent_acknowledged"
	state.LastError = ""
	state.UpdatedAt = nowUnix

	frame["status"] = "agent_acknowledged"
	frame["agent_ephemeral_public_key"] = agentEphemeral
	frame["agent_identity_signature"] = agentSignature
	frame["transcript_hash"] = transcriptHash
	return true
}

func (h *Handler) hasCompletedHandshakeBinding(sessionID, deviceID, handshakeID string) bool {
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
	return state.Status == "agent_acknowledged"
}

func (h *Handler) flushPendingHandshakes(deviceID string) {
	type pendingHandshake struct {
		sessionID string
	}
	pending := make([]pendingHandshake, 0)

	h.mu.RLock()
	for sessionID, state := range h.sessions {
		if state == nil {
			continue
		}
		state.mu.RLock()
		match := state.DeviceID == deviceID && (state.Status == "pending_agent_ack" || state.Status == "pending_agent_connection")
		state.mu.RUnlock()
		if match {
			pending = append(pending, pendingHandshake{sessionID: sessionID})
		}
	}
	h.mu.RUnlock()

	for _, p := range pending {
		h.mu.RLock()
		state, ok := h.sessions[p.sessionID]
		h.mu.RUnlock()
		if !ok || state == nil {
			continue
		}
		state.mu.RLock()
		frame := h.buildHandshakeRequestFrame(state)
		state.mu.RUnlock()
		if frame == nil {
			continue
		}

		newStatus := "pending_agent_ack"
		newError := ""
		if err := h.sendToAgentForSession(p.sessionID, frame); err != nil {
			newStatus = "pending_agent_connection"
			newError = err.Error()
		}

		state.mu.Lock()
		state.Status = newStatus
		state.LastError = newError
		state.UpdatedAt = time.Now().UTC().Unix()
		state.mu.Unlock()
	}
}

func (h *Handler) sendToAgentForSession(sessionID string, payload map[string]any) error {
	h.mu.RLock()
	state, found := h.sessions[sessionID]
	h.mu.RUnlock()
	if !found {
		return fmt.Errorf("session_not_found")
	}
	state.mu.RLock()
	deviceID := state.DeviceID
	state.mu.RUnlock()

	h.mu.RLock()
	conn := h.agents[deviceID]
	h.mu.RUnlock()
	if conn == nil {
		return fmt.Errorf("agent_not_connected")
	}

	writeFn := h.agentWriteFn
	if writeFn == nil {
		writeFn = func(ac *agentConn, frame map[string]any) error {
			return ac.writeJSON(frame)
		}
	}
	if err := writeFn(conn, payload); err != nil {
		h.mu.Lock()
		if current, ok := h.agents[deviceID]; ok && current == conn {
			delete(h.agents, deviceID)
		}
		h.mu.Unlock()
		return fmt.Errorf("agent_unavailable")
	}
	return nil
}
