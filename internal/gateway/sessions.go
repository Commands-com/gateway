package gateway

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"oss-commands-gateway/internal/auth"
)

func (h *Handler) PostHandshakeClientInit(c fiber.Ctx) error {
	principal := auth.PrincipalFromContext(c)
	if principal == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	sessionID, err := validateID(c.Params("session_id"), "session_id")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	var req postHandshakeClientInitRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid json body"})
	}
	deviceID, err := validateID(req.DeviceID, "deviceId")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	now := time.Now().UTC().Unix()

	h.mu.Lock()
	defer h.mu.Unlock()

	device, exists := h.devices[deviceID]
	if !exists {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "device not found"})
	}
	if !h.canAccessDeviceLocked(principal.UID, deviceID) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
	}

	members := map[string]struct{}{
		device.OwnerUID: {},
		principal.UID:   {},
	}
	for _, grant := range h.grants {
		if grant.DeviceID == deviceID && effectiveGrantStatus(grant, now) == "active" && grant.GranteeUID != "" {
			members[grant.GranteeUID] = struct{}{}
		}
	}

	handshakeID := "hs_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	conversationID := "conv_" + sessionID
	state := &sessionState{
		SessionID:      sessionID,
		HandshakeID:    handshakeID,
		DeviceID:       deviceID,
		OwnerUID:       device.OwnerUID,
		ConversationID: conversationID,
		Status:         "agent_acknowledged",
		Members:        members,
		UpdatedAt:      now,
	}
	h.sessions[sessionID] = state

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"sessionId":      sessionID,
		"handshakeId":    handshakeID,
		"status":         state.Status,
		"deviceId":       deviceID,
		"conversationId": conversationID,
	})
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
	state.mu.RLock()
	defer state.mu.RUnlock()
	if _, ok := state.Members[principal.UID]; !ok {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
	}
	if state.HandshakeID != handshakeID {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "handshake not found"})
	}
	resp := fiber.Map{
		"sessionId":      state.SessionID,
		"handshakeId":    state.HandshakeID,
		"status":         state.Status,
		"deviceId":       state.DeviceID,
		"conversationId": state.ConversationID,
	}
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

	h.mu.RLock()
	state, found := h.sessions[sessionID]
	h.mu.RUnlock()
	if !found {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "session not found"})
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if _, ok := state.Members[principal.UID]; !ok {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
	}
	state.Status = "agent_acknowledged"
	state.UpdatedAt = time.Now().UTC().Unix()
	return c.JSON(fiber.Map{
		"sessionId":   sessionID,
		"handshakeId": state.HandshakeID,
		"status":      state.Status,
	})
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
	state.mu.RLock()
	if _, ok := state.Members[principal.UID]; !ok {
		state.mu.RUnlock()
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
	}
	if state.Status != "agent_acknowledged" {
		state.mu.RUnlock()
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error":           "handshake_not_ready",
			"status":          state.Status,
			"session_id":      sessionID,
			"handshake_id":    state.HandshakeID,
			"conversation_id": state.ConversationID,
		})
	}
	handshakeID := state.HandshakeID
	conversationID := state.ConversationID
	state.mu.RUnlock()

	messageID := strings.TrimSpace(asString(payload["message_id"]))
	if messageID == "" {
		messageID = fmt.Sprintf("msg_%d", time.Now().UTC().UnixNano())
	}
	eventPayload := map[string]any{
		"type":                   "session.message",
		"session_id":             sessionID,
		"handshake_id":           handshakeID,
		"conversation_id":        conversationID,
		"message_id":             messageID,
		"requester_uid":          principal.UID,
		"requester_email":        principal.Email,
		"requester_display_name": principal.DisplayName,
		"received_at":            time.Now().UTC().Format(time.RFC3339),
		"payload":                payload,
	}
	raw, err := json.Marshal(eventPayload)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to encode event"})
	}

	eventID := h.appendSessionEvent(sessionID, raw)
	h.sendToAgentForSession(sessionID, eventPayload)

	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
		"status":          "forwarded_to_agent",
		"session_id":      sessionID,
		"handshake_id":    handshakeID,
		"conversation_id": conversationID,
		"message_id":      messageID,
		"event_id":        eventID,
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
	state.mu.RLock()
	if _, ok := state.Members[principal.UID]; !ok {
		state.mu.RUnlock()
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
	}
	state.mu.RUnlock()

	replay := h.replayEvents(sessionID, lastEventID)
	sub := h.subscribe(sessionID)

	c.Set(fiber.HeaderContentType, "text/event-stream")
	c.Set(fiber.HeaderCacheControl, "no-cache")
	c.Set(fiber.HeaderConnection, "keep-alive")
	c.Set("X-Accel-Buffering", "no")

	if err := c.SendStreamWriter(func(w *bufio.Writer) {
		defer h.unsubscribe(sessionID, sub)
		if err := writeSSEComment(w, "connected"); err != nil {
			return
		}
		for _, evt := range replay {
			if err := writeSSEEvent(w, evt); err != nil {
				return
			}
		}
		heartbeat := time.NewTicker(15 * time.Second)
		defer heartbeat.Stop()
		for {
			select {
			case evt := <-sub:
				if err := writeSSEEvent(w, evt); err != nil {
					return
				}
			case <-heartbeat.C:
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
