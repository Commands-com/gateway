package gateway

import (
	"bufio"
	"encoding/json"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"oss-commands-gateway/internal/auth"
	"oss-commands-gateway/internal/gatewaycrypto"
)

const handshakeRetryInterval = 5 * time.Second

func (h *Handler) PostHandshakeClientInit(c fiber.Ctx) error {
	principal := auth.PrincipalFromContext(c)
	if principal == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}

	sessionID, err := validateID(c.Params("session_id"), "session_id")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	var body map[string]any
	if err := c.Bind().Body(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}
	if body == nil {
		body = make(map[string]any)
	}

	deviceID, err := validateID(firstStringMap(body, "device_id", "deviceId"), "device_id")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	clientEphemeral := strings.TrimSpace(firstStringMap(body, "client_ephemeral_public_key", "clientEphemeralPublicKey"))
	clientNonce := strings.TrimSpace(firstStringMap(body, "client_session_nonce", "clientSessionNonce"))
	if clientNonce == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "device_id, handshake_id, and client_session_nonce are required"})
	}
	handshakeID, err := validateID(firstStringMap(body, "handshake_id", "handshakeId"), "handshake_id")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	conversationID := strings.TrimSpace(firstStringMap(body, "conversation_id", "conversationId"))
	if conversationID == "" {
		conversationID = "conv_" + sessionID
	} else {
		conversationID, err = validateID(conversationID, "conversation_id")
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
	}

	if err := gatewaycrypto.ValidateX25519PublicKey(clientEphemeral); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid ephemeral public key"})
	}

	now := time.Now().UTC()
	nowUnix := now.Unix()

	h.mu.Lock()
	device, exists := h.devices[deviceID]
	if !exists {
		h.mu.Unlock()
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "device not found"})
	}
	if !h.canAccessDeviceLocked(principal.UID, deviceID) {
		h.mu.Unlock()
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
	}

	state, found := h.sessions[sessionID]
	if !found {
		state = &sessionState{
			SessionID:                sessionID,
			HandshakeID:              handshakeID,
			DeviceID:                 deviceID,
			OwnerUID:                 device.OwnerUID,
			ConversationID:           conversationID,
			ClientEphemeralPublicKey: clientEphemeral,
			ClientSessionNonce:       clientNonce,
			Status:                   "pending_agent_ack",
			CreatedAt:                nowUnix,
			UpdatedAt:                nowUnix,
		}
		h.sessions[sessionID] = state
	} else {
		state.mu.Lock()
		if state.DeviceID != deviceID || state.HandshakeID != handshakeID || state.ClientEphemeralPublicKey != clientEphemeral || state.ClientSessionNonce != clientNonce {
			state.mu.Unlock()
			h.mu.Unlock()
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "handshake_id already exists with different payload"})
		}
		if state.ConversationID != "" && state.ConversationID != conversationID {
			state.mu.Unlock()
			h.mu.Unlock()
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "handshake_id already exists with different conversation_id"})
		}
		if state.ConversationID == "" {
			state.ConversationID = conversationID
		}
		state.UpdatedAt = nowUnix
		state.mu.Unlock()
	}
	h.mu.Unlock()

	relayStatus := "already_acknowledged"
	relayError := ""

	state.mu.RLock()
	status := state.Status
	state.mu.RUnlock()

	if status != "agent_acknowledged" {
		state.mu.RLock()
		frame := h.buildHandshakeRequestFrame(state)
		state.mu.RUnlock()
		if err := h.sendToAgentForSession(sessionID, frame); err != nil {
			relayStatus = "pending_agent_connection"
			relayError = err.Error()
			state.mu.Lock()
			state.Status = "pending_agent_connection"
			state.LastError = relayError
			state.UpdatedAt = time.Now().UTC().Unix()
			state.mu.Unlock()
		} else {
			relayStatus = "forwarded_to_agent"
			state.mu.Lock()
			if state.Status == "pending_agent_connection" {
				state.Status = "pending_agent_ack"
			}
			state.LastError = ""
			state.UpdatedAt = time.Now().UTC().Unix()
			state.mu.Unlock()
		}
	}

	state.mu.RLock()
	resp := fiber.Map{
		"status":                      state.Status,
		"session_id":                  state.SessionID,
		"sessionId":                   state.SessionID,
		"handshake_id":                state.HandshakeID,
		"handshakeId":                 state.HandshakeID,
		"conversation_id":             state.ConversationID,
		"conversationId":              state.ConversationID,
		"relay_status":                relayStatus,
		"device_id":                   state.DeviceID,
		"deviceId":                    state.DeviceID,
		"client_ephemeral_public_key": state.ClientEphemeralPublicKey,
		"client_session_nonce":        state.ClientSessionNonce,
	}
	if relayError != "" {
		resp["relay_error"] = relayError
	}
	if state.LastError != "" {
		resp["last_error"] = state.LastError
	}
	state.mu.RUnlock()

	return c.Status(fiber.StatusAccepted).JSON(resp)
}

func (h *Handler) GetHandshake(c fiber.Ctx) error {
	principal := auth.PrincipalFromContext(c)
	if principal == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	sessionID, err := validateID(c.Params("session_id"), "session_id")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	handshakeID, err := validateID(c.Params("handshake_id"), "handshake_id")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	h.mu.RLock()
	state, found := h.sessions[sessionID]
	h.mu.RUnlock()
	if !found {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "session not found"})
	}

	if !h.isSessionMemberDynamic(principal.UID, state) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
	}

	state.mu.RLock()
	matchesHandshake := state.HandshakeID == handshakeID
	status := state.Status
	lastUpdatedAt := state.UpdatedAt
	frame := h.buildHandshakeRequestFrame(state)
	state.mu.RUnlock()

	if !matchesHandshake {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "handshake not found"})
	}

	if (status == "pending_agent_ack" || status == "pending_agent_connection") && time.Since(time.Unix(lastUpdatedAt, 0)) >= handshakeRetryInterval {
		newStatus := "pending_agent_ack"
		newError := ""
		if err := h.sendToAgentForSession(sessionID, frame); err != nil {
			newStatus = "pending_agent_connection"
			newError = err.Error()
		}
		state.mu.Lock()
		state.Status = newStatus
		state.LastError = newError
		state.UpdatedAt = time.Now().UTC().Unix()
		state.mu.Unlock()
	}

	state.mu.RLock()
	resp := fiber.Map{
		"session_id":                  state.SessionID,
		"sessionId":                   state.SessionID,
		"handshake_id":                state.HandshakeID,
		"handshakeId":                 state.HandshakeID,
		"conversation_id":             state.ConversationID,
		"conversationId":              state.ConversationID,
		"device_id":                   state.DeviceID,
		"deviceId":                    state.DeviceID,
		"status":                      state.Status,
		"last_error":                  state.LastError,
		"client_ephemeral_public_key": state.ClientEphemeralPublicKey,
		"agent_ephemeral_public_key":  state.AgentEphemeralPublicKey,
		"agent_identity_signature":    state.AgentIdentitySignature,
		"transcript_hash":             state.TranscriptHash,
		"created_at":                  time.Unix(state.CreatedAt, 0).UTC().Format(time.RFC3339),
		"updated_at":                  time.Unix(state.UpdatedAt, 0).UTC().Format(time.RFC3339),
	}
	state.mu.RUnlock()
	return c.JSON(resp)
}

func (h *Handler) PostHandshakeAgentAck(c fiber.Ctx) error {
	principal := auth.PrincipalFromContext(c)
	if principal == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	sessionID, err := validateID(c.Params("session_id"), "session_id")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	var body map[string]any
	if err := c.Bind().Body(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}
	if body == nil {
		body = make(map[string]any)
	}

	deviceID, err := validateID(firstStringMap(body, "device_id", "deviceId"), "device_id")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	handshakeID, err := validateID(firstStringMap(body, "handshake_id", "handshakeId"), "handshake_id")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	agentEphemeral := strings.TrimSpace(firstStringMap(body, "agent_ephemeral_public_key", "agentEphemeralPublicKey"))
	agentSignature := strings.TrimSpace(firstStringMap(body, "agent_identity_signature", "agentIdentitySignature"))
	transcriptHash := strings.TrimSpace(firstStringMap(body, "transcript_hash", "transcriptHash"))

	if err := gatewaycrypto.ValidateX25519PublicKey(agentEphemeral); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid ephemeral public key"})
	}

	h.mu.RLock()
	state, found := h.sessions[sessionID]
	device, hasDevice := h.devices[deviceID]
	h.mu.RUnlock()
	if !found {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "handshake not found"})
	}
	if !hasDevice || strings.TrimSpace(device.IdentityKey) == "" {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "device identity not found"})
	}
	if device.OwnerUID != principal.UID {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "device identity not found"})
	}

	statusCode := fiber.StatusAccepted
	var errResp fiber.Map
	var event map[string]any
	var resp fiber.Map

	func() {
		state.mu.Lock()
		defer state.mu.Unlock()

		if state.HandshakeID != handshakeID {
			statusCode = fiber.StatusNotFound
			errResp = fiber.Map{"error": "handshake not found"}
			return
		}
		if state.DeviceID != deviceID {
			statusCode = fiber.StatusBadRequest
			errResp = fiber.Map{"error": "device_id mismatch for handshake"}
			return
		}
		if state.ConversationID == "" {
			state.ConversationID = "conv_" + sessionID
		}

		expectedTranscript := gatewaycrypto.BuildTranscriptHash(sessionID, handshakeID, state.ClientEphemeralPublicKey, state.ClientSessionNonce, agentEphemeral)
		if !gatewaycrypto.ConstantTimeEqualBase64(expectedTranscript, transcriptHash) {
			statusCode = fiber.StatusBadRequest
			errResp = fiber.Map{"error": "transcript hash mismatch"}
			return
		}
		if err := gatewaycrypto.VerifyAgentSignature(device.IdentityKey, transcriptHash, agentSignature); err != nil {
			statusCode = fiber.StatusUnauthorized
			errResp = fiber.Map{"error": "signature verification failed"}
			return
		}

		state.AgentEphemeralPublicKey = agentEphemeral
		state.AgentIdentitySignature = agentSignature
		state.TranscriptHash = transcriptHash
		state.Status = "agent_acknowledged"
		state.LastError = ""
		state.UpdatedAt = time.Now().UTC().Unix()

		event = map[string]any{
			"type":                       "session.handshake.ack",
			"status":                     state.Status,
			"session_id":                 state.SessionID,
			"handshake_id":               state.HandshakeID,
			"conversation_id":            state.ConversationID,
			"device_id":                  state.DeviceID,
			"agent_ephemeral_public_key": state.AgentEphemeralPublicKey,
			"agent_identity_signature":   state.AgentIdentitySignature,
			"transcript_hash":            state.TranscriptHash,
			"updated_at":                 time.Unix(state.UpdatedAt, 0).UTC().Format(time.RFC3339),
		}
		resp = fiber.Map{
			"status":          state.Status,
			"session_id":      state.SessionID,
			"sessionId":       state.SessionID,
			"handshake_id":    state.HandshakeID,
			"handshakeId":     state.HandshakeID,
			"conversation_id": state.ConversationID,
			"conversationId":  state.ConversationID,
		}
	}()

	if errResp != nil {
		return c.Status(statusCode).JSON(errResp)
	}

	// appendSessionEvent acquires h.mu, so we must not hold state.mu here
	raw, _ := json.Marshal(event)
	h.appendSessionEvent(sessionID, raw)

	return c.Status(fiber.StatusAccepted).JSON(resp)
}

func (h *Handler) PostSessionMessage(c fiber.Ctx) error {
	principal := auth.PrincipalFromContext(c)
	if principal == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	sessionID, err := validateID(c.Params("session_id"), "session_id")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	idempotencyKey := strings.TrimSpace(c.Get("X-Idempotency-Key"))
	if idempotencyKey == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing X-Idempotency-Key header"})
	}

	var payload map[string]any
	if err := c.Bind().Body(&payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}
	if payload == nil {
		payload = make(map[string]any)
	}

	h.mu.RLock()
	state, found := h.sessions[sessionID]
	h.mu.RUnlock()
	if !found {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "session not found"})
	}

	if !h.isSessionMemberDynamic(principal.UID, state) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
	}

	state.mu.RLock()
	handshakeStatus := state.Status
	handshakeID := state.HandshakeID
	conversationID := state.ConversationID
	lastSeq := state.SeqClientToAgent
	state.mu.RUnlock()

	if handshakeStatus != "agent_acknowledged" {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error":           "handshake_not_ready",
			"status":          handshakeStatus,
			"session_id":      sessionID,
			"handshake_id":    handshakeID,
			"conversation_id": conversationID,
		})
	}

	clientConversationID := strings.TrimSpace(firstStringMap(payload, "conversation_id", "conversationId"))
	if clientConversationID != "" && conversationID != "" && clientConversationID != conversationID {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error":           "conversation_mismatch",
			"session_id":      sessionID,
			"handshake_id":    handshakeID,
			"conversation_id": conversationID,
		})
	}

	seq := 0
	if violation := validateEncryptedEnvelope(payload); violation != "" {
		if h.cfg.RequireEncryptedFrames {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":           "encryption_required",
				"violation":       violation,
				"session_id":      sessionID,
				"conversation_id": conversationID,
			})
		}
	} else {
		parsedSeq, _ := extractPositiveInt(payload, "seq")
		seq = parsedSeq
		if seq <= lastSeq {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error":           "replay_detected",
				"violation":       "replay_detected",
				"session_id":      sessionID,
				"conversation_id": conversationID,
			})
		}
	}

	now := time.Now().UTC()
	if !h.checkAndReserveIdempotencyKey(sessionID, principal.UID, idempotencyKey, now) {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error":      "duplicate_request",
			"session_id": sessionID,
		})
	}

	messageID := strings.TrimSpace(firstStringMap(payload, "message_id", "messageId"))
	if messageID == "" {
		messageID = newSessionMessageID()
	}

	payload["type"] = "session.message"
	payload["message_id"] = messageID
	payload["requester_uid"] = principal.UID
	if strings.TrimSpace(principal.Email) == "" {
		payload["requester_email"] = nil
	} else {
		payload["requester_email"] = principal.Email
	}
	if strings.TrimSpace(principal.DisplayName) == "" {
		payload["requester_display_name"] = nil
	} else {
		payload["requester_display_name"] = principal.DisplayName
	}
	payload["requester"] = map[string]any{
		"uid":          principal.UID,
		"email":        payload["requester_email"],
		"display_name": payload["requester_display_name"],
	}
	payload["received_at"] = now.Format(time.RFC3339)
	payload["session_id"] = sessionID
	payload["handshake_id"] = handshakeID
	if conversationID != "" {
		payload["conversation_id"] = conversationID
	}

	reservedSeq := 0
	previousSeq := 0
	if seq > 0 {
		state.mu.Lock()
		if seq <= state.SeqClientToAgent {
			state.mu.Unlock()
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error":           "replay_detected",
				"violation":       "replay_detected",
				"session_id":      sessionID,
				"conversation_id": conversationID,
			})
		}
		previousSeq = state.SeqClientToAgent
		state.SeqClientToAgent = seq
		state.UpdatedAt = now.Unix()
		reservedSeq = seq
		state.mu.Unlock()
	}

	if err := h.sendToAgentForSession(sessionID, payload); err != nil {
		if reservedSeq > 0 {
			state.mu.Lock()
			if state.SeqClientToAgent == reservedSeq {
				state.SeqClientToAgent = previousSeq
			}
			state.mu.Unlock()
		}
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error":           "agent_unavailable",
			"session_id":      sessionID,
			"conversation_id": conversationID,
		})
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to encode event"})
	}
	eventID := h.appendSessionEvent(sessionID, raw)

	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
		"status":          "forwarded_to_agent",
		"session_id":      sessionID,
		"sessionId":       sessionID,
		"handshake_id":    handshakeID,
		"handshakeId":     handshakeID,
		"conversation_id": conversationID,
		"conversationId":  conversationID,
		"message_id":      messageID,
		"messageId":       messageID,
		"event_id":        eventID,
		"eventId":         eventID,
	})
}

func (h *Handler) GetSessionEvents(c fiber.Ctx) error {
	principal := auth.PrincipalFromContext(c)
	if principal == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	sessionID, err := validateID(c.Params("session_id"), "session_id")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	lastEventID := strings.TrimSpace(c.Get("Last-Event-ID"))

	h.mu.RLock()
	state, found := h.sessions[sessionID]
	h.mu.RUnlock()
	if !found {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "session not found"})
	}
	if !h.isSessionMemberDynamic(principal.UID, state) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
	}

	// Subscribe before replay to avoid missing events in the gap
	sub := h.subscribe(sessionID, principal.UID)
	replay := h.replayEvents(sessionID, lastEventID)

	c.Set(fiber.HeaderContentType, "text/event-stream")
	c.Set(fiber.HeaderCacheControl, "no-cache")
	c.Set(fiber.HeaderConnection, "keep-alive")
	c.Set("X-Accel-Buffering", "no")

	if err := c.SendStreamWriter(func(w *bufio.Writer) {
		defer h.unsubscribe(sessionID, sub)
		if err := writeSSEComment(w, "connected"); err != nil {
			return
		}
		// isEvicted is a helper that checks whether the subscriber has been
		// evicted without blocking.
		isEvicted := func() bool {
			select {
			case <-sub.evicted:
				return true
			default:
				return false
			}
		}

		// Track the last sent event ID for deduplication (subscribe before replay
		// may cause overlap)
		lastSentID := lastEventID
		for _, evt := range replay {
			if isEvicted() {
				return
			}
			if err := writeSSEEvent(w, evt); err != nil {
				return
			}
			lastSentID = evt.ID
		}
		heartbeat := time.NewTicker(15 * time.Second)
		defer heartbeat.Stop()
		for {
			// Prioritize eviction check so revoked clients disconnect
			// immediately even if sub.ch has buffered events.
			if isEvicted() {
				return
			}
			select {
			case <-sub.evicted:
				// Subscriber evicted (slow client or auth revoked)
				return
			case evt := <-sub.ch:
				// Deduplicate events that were already sent via replay
				if lastSentID != "" && !eventIDGreaterThan(evt.ID, lastSentID) {
					continue
				}
				if isEvicted() {
					return
				}
				if err := writeSSEEvent(w, evt); err != nil {
					return
				}
				lastSentID = evt.ID
			case <-heartbeat.C:
				// Re-check authorization on each heartbeat
				if !h.isSessionMemberDynamic(principal.UID, state) {
					_ = writeSSEComment(w, "authorization_revoked")
					return
				}
				if err := writeSSEComment(w, "heartbeat"); err != nil {
					return
				}
			}
		}
	}); err != nil {
		return err
	}
	return nil
}

func (h *Handler) buildHandshakeRequestFrame(state *sessionState) map[string]any {
	if state == nil {
		return nil
	}
	return map[string]any{
		"type":                        "session.handshake.request",
		"session_id":                  state.SessionID,
		"handshake_id":                state.HandshakeID,
		"conversation_id":             state.ConversationID,
		"device_id":                   state.DeviceID,
		"client_ephemeral_public_key": state.ClientEphemeralPublicKey,
		"client_session_nonce":        state.ClientSessionNonce,
	}
}

func newSessionMessageID() string {
	return "msg_" + strings.ReplaceAll(uuid.NewString(), "-", "")
}

// isSessionMemberDynamic checks whether the given UID currently has access to the session
// by evaluating device ownership and current grant state dynamically.
// Must be called without holding h.mu or state.mu.
func (h *Handler) isSessionMemberDynamic(uid string, state *sessionState) bool {
	if state == nil {
		return false
	}

	state.mu.RLock()
	deviceID := state.DeviceID
	ownerUID := state.OwnerUID
	state.mu.RUnlock()

	// Owner always has access
	if uid == ownerUID {
		return true
	}

	now := time.Now().UTC().Unix()
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.hasActiveGrantLocked(deviceID, uid, now)
}
