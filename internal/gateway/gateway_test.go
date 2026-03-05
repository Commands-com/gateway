package gateway

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"

	"oss-commands-gateway/internal/auth"
	"oss-commands-gateway/internal/config"
)

func TestShareInviteAcceptAndList(t *testing.T) {
	h := NewHandler(&config.Config{
		FrontendURL:   "https://frontend.example",
		StateBackend:  config.StateBackendMemory,
		PublicBaseURL: "http://localhost:8080",
	})
	app := newGatewayTestApp(h)

	mustDoJSON(t, app, "PUT", "/gateway/v1/devices/devowner1/identity-key", map[string]any{"identityKey": "owner-key"}, "owner1", "owner@example.com", fiber.StatusOK)

	inviteResp := mustDoJSON(t, app, "POST", "/gateway/v1/shares/invites", map[string]any{
		"deviceId": "devowner1",
		"email":    "collab@example.com",
	}, "owner1", "owner@example.com", fiber.StatusCreated)

	inviteURL, _ := inviteResp["inviteUrl"].(string)
	if inviteURL == "" {
		t.Fatalf("expected inviteUrl in create invite response")
	}
	parts := strings.Split(inviteURL, "/")
	token := parts[len(parts)-1]
	if token == "" {
		t.Fatalf("expected invite token in inviteUrl")
	}

	mustDoJSON(t, app, "PUT", "/gateway/v1/devices/devcollab1/identity-key", map[string]any{"identityKey": "collab-key"}, "collab1", "collab@example.com", fiber.StatusOK)

	acceptResp := mustDoJSON(t, app, "POST", "/gateway/v1/shares/invites/accept", map[string]any{
		"token":    token,
		"deviceId": "devcollab1",
	}, "collab1", "collab@example.com", fiber.StatusOK)

	if acceptResp["status"] != "active" {
		t.Fatalf("expected accepted grant status active, got %v", acceptResp["status"])
	}

	listResp := mustDoJSON(t, app, "GET", "/gateway/v1/shares/devices/devowner1/grants", nil, "owner1", "owner@example.com", fiber.StatusOK)
	grants, ok := listResp["grants"].([]any)
	if !ok {
		t.Fatalf("expected grants array in response")
	}
	if len(grants) != 1 {
		t.Fatalf("expected 1 grant, got %d", len(grants))
	}
	grant, ok := grants[0].(map[string]any)
	if !ok {
		t.Fatalf("expected grant object")
	}
	if grant["status"] != "active" {
		t.Fatalf("expected listed grant status active, got %v", grant["status"])
	}
	if grant["granteeUid"] != "collab1" {
		t.Fatalf("expected granteeUid collab1, got %v", grant["granteeUid"])
	}
}

func TestSessionMessageCreatesEventAndEnforcesMembership(t *testing.T) {
	h := NewHandler(&config.Config{
		FrontendURL:   "https://frontend.example",
		StateBackend:  config.StateBackendMemory,
		PublicBaseURL: "http://localhost:8080",
	})
	app := newGatewayTestApp(h)

	mustDoJSON(t, app, "PUT", "/gateway/v1/devices/devowner1/identity-key", map[string]any{"identityKey": "owner-key"}, "owner1", "owner@example.com", fiber.StatusOK)

	inviteResp := mustDoJSON(t, app, "POST", "/gateway/v1/shares/invites", map[string]any{
		"deviceId": "devowner1",
		"email":    "collab@example.com",
	}, "owner1", "owner@example.com", fiber.StatusCreated)
	inviteURL, _ := inviteResp["inviteUrl"].(string)
	token := inviteURL[strings.LastIndex(inviteURL, "/")+1:]

	mustDoJSON(t, app, "PUT", "/gateway/v1/devices/devcollab1/identity-key", map[string]any{"identityKey": "collab-key"}, "collab1", "collab@example.com", fiber.StatusOK)
	mustDoJSON(t, app, "POST", "/gateway/v1/shares/invites/accept", map[string]any{
		"token":    token,
		"deviceId": "devcollab1",
	}, "collab1", "collab@example.com", fiber.StatusOK)

	handshake := mustDoJSON(t, app, "POST", "/gateway/v1/sessions/sessabc1/handshake/client-init", map[string]any{"deviceId": "devowner1"}, "collab1", "collab@example.com", fiber.StatusCreated)
	if handshake["status"] != "agent_acknowledged" {
		t.Fatalf("expected handshake status agent_acknowledged, got %v", handshake["status"])
	}

	mustDoJSON(t, app, "POST", "/gateway/v1/sessions/sessabc1/messages", map[string]any{"message_id": "msg-1", "content": "hello"}, "collab1", "collab@example.com", fiber.StatusAccepted)

	events := h.replayEvents("sessabc1", "")
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if !strings.Contains(string(events[0].Data), "msg-1") {
		t.Fatalf("expected event payload to contain message_id msg-1")
	}

	mustDoJSON(t, app, "POST", "/gateway/v1/sessions/sessabc1/messages", map[string]any{"message_id": "msg-2", "content": "nope"}, "stranger1", "stranger@example.com", fiber.StatusForbidden)
}

func newGatewayTestApp(h *Handler) *fiber.App {
	app := fiber.New()
	app.Use(func(c fiber.Ctx) error {
		uid := strings.Clone(strings.TrimSpace(c.Get("X-Test-UID")))
		if uid != "" {
			c.Locals("principal", &auth.Principal{
				UID:         uid,
				Email:       strings.Clone(strings.TrimSpace(c.Get("X-Test-Email"))),
				DisplayName: strings.Clone(strings.TrimSpace(c.Get("X-Test-Name"))),
			})
		}
		return c.Next()
	})

	group := app.Group("/gateway/v1")
	group.Put("/devices/:device_id/identity-key", h.PutDeviceIdentityKey)
	group.Get("/devices/:device_id/identity-key", h.GetDeviceIdentityKey)
	group.Post("/shares/invites", h.CreateShareInvite)
	group.Post("/shares/invites/accept", h.AcceptShareInvite)
	group.Get("/shares/devices/:device_id/grants", h.ListShareGrants)
	group.Post("/shares/grants/:grant_id/revoke", h.RevokeShareGrant)
	group.Post("/shares/grants/:grant_id/leave", h.LeaveShareGrant)
	group.Post("/sessions/:session_id/handshake/client-init", h.PostHandshakeClientInit)
	group.Get("/sessions/:session_id/handshake/:handshake_id", h.GetHandshake)
	group.Post("/sessions/:session_id/handshake/agent-ack", h.PostHandshakeAgentAck)
	group.Post("/sessions/:session_id/messages", h.PostSessionMessage)
	group.Get("/sessions/:session_id/events", h.GetSessionEvents)

	return app
}

func mustDoJSON(
	t *testing.T,
	app *fiber.App,
	method string,
	path string,
	payload map[string]any,
	uid string,
	email string,
	expectedStatus int,
) map[string]any {
	t.Helper()

	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
	}

	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if uid != "" {
		req.Header.Set("X-Test-UID", uid)
	}
	if email != "" {
		req.Header.Set("X-Test-Email", email)
	}

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test request failed: %v", err)
	}
	defer resp.Body.Close()

	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != expectedStatus {
		t.Fatalf("unexpected status for %s %s: got %d want %d body=%v", method, path, resp.StatusCode, expectedStatus, out)
	}
	if out == nil {
		return map[string]any{}
	}
	return out
}
