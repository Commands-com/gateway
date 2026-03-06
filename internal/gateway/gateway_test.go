package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"

	"oss-commands-gateway/internal/auth"
	"oss-commands-gateway/internal/config"
)

func identityPayload(publicKey string) map[string]any {
	return map[string]any{
		"algorithm":  "ed25519",
		"public_key": publicKey,
	}
}

func TestPutDeviceIdentityKeyAcceptsLegacyPayloadAliases(t *testing.T) {
	h := NewHandler(&config.Config{
		FrontendURL:   "https://frontend.example",
		StateBackend:  config.StateBackendMemory,
		PublicBaseURL: "http://localhost:8080",
	})
	app := newGatewayTestApp(h)

	identityKey, _ := testEd25519Identity("owner-legacy")
	mustDoJSON(t, app, "PUT", "/gateway/v1/devices/devlegacy1/identity-key", map[string]any{
		"identityKey": identityKey,
	}, "owner1", "owner@example.com", fiber.StatusNoContent)

	got := mustDoJSON(t, app, "GET", "/gateway/v1/devices/devlegacy1/identity-key", nil, "owner1", "owner@example.com", fiber.StatusOK)
	if got["public_key"] != identityKey {
		t.Fatalf("expected legacy identityKey to persist as public_key, got %v", got["public_key"])
	}

	mustDoJSON(t, app, "PUT", "/gateway/v1/devices/devlegacy1/identity-key", map[string]any{
		"identity_key": identityKey,
	}, "owner1", "owner@example.com", fiber.StatusNoContent)
}

func TestListDevicesAllowsOwnerByEmailFallback(t *testing.T) {
	h := NewHandler(&config.Config{
		FrontendURL:   "https://frontend.example",
		StateBackend:  config.StateBackendMemory,
		PublicBaseURL: "http://localhost:8080",
		AuthMode:      config.AuthModeDemo,
	})
	app := newGatewayTestApp(h)

	identityKey, _ := testEd25519Identity("owner-email")
	mustDoJSON(t, app, "PUT", "/gateway/v1/devices/devmail1/identity-key", identityPayload(identityKey), "owner-uid-a", "dtannen@example.com", fiber.StatusNoContent)

	// Different UID, same canonical email should still be treated as owner.
	if !h.canAccessDeviceForPrincipal(context.Background(), "owner-uid-b", "dtannen@example.com", "devmail1") {
		t.Fatalf("expected email fallback owner access to device")
	}
}

func TestOwnerEmailFallbackDisabledOutsideDemo(t *testing.T) {
	h := NewHandler(&config.Config{
		FrontendURL:   "https://frontend.example",
		StateBackend:  config.StateBackendMemory,
		PublicBaseURL: "http://localhost:8080",
		AuthMode:      config.AuthModeOIDC,
	})
	app := newGatewayTestApp(h)

	identityKey, _ := testEd25519Identity("owner-nondemo")
	mustDoJSON(t, app, "PUT", "/gateway/v1/devices/devnondemo1/identity-key", identityPayload(identityKey), "owner-uid-a", "same@example.com", fiber.StatusNoContent)

	if h.canAccessDeviceForPrincipal(context.Background(), "owner-uid-b", "same@example.com", "devnondemo1") {
		t.Fatalf("expected email fallback to be disabled in non-demo auth mode")
	}
}

func TestListDevicesReturnsStoredDisplayName(t *testing.T) {
	h := NewHandler(&config.Config{
		FrontendURL:   "https://frontend.example",
		StateBackend:  config.StateBackendMemory,
		PublicBaseURL: "http://localhost:8080",
	})
	app := newGatewayTestApp(h)

	identityKey, _ := testEd25519Identity("owner-display")
	mustDoJSON(t, app, "PUT", "/gateway/v1/devices/devdisplay1/identity-key", map[string]any{
		"algorithm":    "ed25519",
		"public_key":   identityKey,
		"display_name": "Office Mac",
	}, "owner1", "owner@example.com", fiber.StatusNoContent)

	resp := mustDoJSON(t, app, "GET", "/gateway/v1/devices", nil, "owner1", "owner@example.com", fiber.StatusOK)
	devices, ok := resp["devices"].([]any)
	if !ok || len(devices) != 1 {
		t.Fatalf("expected one device in list response, got %v", resp["devices"])
	}
	dev, ok := devices[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first device to be object")
	}
	if dev["display_name"] != "Office Mac" {
		t.Fatalf("expected display_name Office Mac, got %v", dev["display_name"])
	}
	if dev["name"] != "Office Mac" {
		t.Fatalf("expected name Office Mac, got %v", dev["name"])
	}
}

func TestShareInviteAcceptAndList(t *testing.T) {
	h := NewHandler(&config.Config{
		FrontendURL:   "https://frontend.example",
		StateBackend:  config.StateBackendMemory,
		PublicBaseURL: "http://localhost:8080",
	})
	app := newGatewayTestApp(h)

	ownerIdentityKey, _ := testEd25519Identity("owner1")
	collabIdentityKey, _ := testEd25519Identity("collab1")
	mustDoJSON(t, app, "PUT", "/gateway/v1/devices/devowner1/identity-key", identityPayload(ownerIdentityKey), "owner1", "owner@example.com", fiber.StatusNoContent)

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

	mustDoJSON(t, app, "PUT", "/gateway/v1/devices/devcollab1/identity-key", identityPayload(collabIdentityKey), "collab1", "collab@example.com", fiber.StatusNoContent)

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

func TestShareGrantIndexMaintainedOnRevoke(t *testing.T) {
	h := NewHandler(&config.Config{
		FrontendURL:   "https://frontend.example",
		StateBackend:  config.StateBackendMemory,
		PublicBaseURL: "http://localhost:8080",
	})
	app := newGatewayTestApp(h)

	ownerIdentityKey, _ := testEd25519Identity("owner1")
	collabIdentityKey, _ := testEd25519Identity("collab1")
	mustDoJSON(t, app, "PUT", "/gateway/v1/devices/devowner1/identity-key", identityPayload(ownerIdentityKey), "owner1", "owner@example.com", fiber.StatusNoContent)

	inviteResp := mustDoJSON(t, app, "POST", "/gateway/v1/shares/invites", map[string]any{
		"deviceId": "devowner1",
		"email":    "collab@example.com",
	}, "owner1", "owner@example.com", fiber.StatusCreated)

	grantID, _ := inviteResp["grantId"].(string)
	if grantID == "" {
		t.Fatalf("expected grantId in create invite response")
	}
	inviteURL, _ := inviteResp["inviteUrl"].(string)
	token := inviteURL[strings.LastIndex(inviteURL, "/")+1:]
	if token == "" {
		t.Fatalf("expected invite token in inviteUrl")
	}

	mustDoJSON(t, app, "PUT", "/gateway/v1/devices/devcollab1/identity-key", identityPayload(collabIdentityKey), "collab1", "collab@example.com", fiber.StatusNoContent)
	mustDoJSON(t, app, "POST", "/gateway/v1/shares/invites/accept", map[string]any{
		"token":    token,
		"deviceId": "devcollab1",
	}, "collab1", "collab@example.com", fiber.StatusOK)

	grantsBefore, err := h.store.ListShareGrantsByDevice(context.Background(), "devowner1")
	if err != nil {
		t.Fatalf("list grants by device before revoke failed: %v", err)
	}
	indexed := len(grantsBefore)
	hasAccessBeforeRevoke := h.canAccessDevice(context.Background(), "collab1", "devowner1")
	if indexed != 1 {
		t.Fatalf("expected 1 indexed grant for device, got %d", indexed)
	}
	if !hasAccessBeforeRevoke {
		t.Fatalf("expected collaborator to have access before revoke")
	}

	mustDoJSON(t, app, "POST", "/gateway/v1/shares/grants/"+grantID+"/revoke", nil, "owner1", "owner@example.com", fiber.StatusOK)

	grantsAfter, err := h.store.ListShareGrantsByDevice(context.Background(), "devowner1")
	if err != nil {
		t.Fatalf("list grants by device after revoke failed: %v", err)
	}
	indexed = len(grantsAfter)
	hasAccessAfterRevoke := h.canAccessDevice(context.Background(), "collab1", "devowner1")
	if indexed != 0 {
		t.Fatalf("expected 0 indexed grants after revoke, got %d", indexed)
	}
	if hasAccessAfterRevoke {
		t.Fatalf("expected collaborator access to be removed after revoke")
	}

	listResp := mustDoJSON(t, app, "GET", "/gateway/v1/shares/devices/devowner1/grants", nil, "owner1", "owner@example.com", fiber.StatusOK)
	grants, ok := listResp["grants"].([]any)
	if !ok {
		t.Fatalf("expected grants array in response")
	}
	if len(grants) != 1 {
		t.Fatalf("expected 1 grant in historical listing, got %d", len(grants))
	}
	grant, ok := grants[0].(map[string]any)
	if !ok {
		t.Fatalf("expected grant object")
	}
	if grant["status"] != "revoked" {
		t.Fatalf("expected listed grant status revoked, got %v", grant["status"])
	}
}

func TestSessionMessageCreatesEventAndEnforcesMembership(t *testing.T) {
	h := NewHandler(&config.Config{
		FrontendURL:   "https://frontend.example",
		StateBackend:  config.StateBackendMemory,
		PublicBaseURL: "http://localhost:8080",
	})
	app := newGatewayTestApp(h)

	ownerIdentityKey, ownerIdentityPriv := testEd25519Identity("owner1")
	collabIdentityKey, _ := testEd25519Identity("collab1")
	mustDoJSON(t, app, "PUT", "/gateway/v1/devices/devowner1/identity-key", identityPayload(ownerIdentityKey), "owner1", "owner@example.com", fiber.StatusNoContent)

	inviteResp := mustDoJSON(t, app, "POST", "/gateway/v1/shares/invites", map[string]any{
		"deviceId": "devowner1",
		"email":    "collab@example.com",
	}, "owner1", "owner@example.com", fiber.StatusCreated)
	inviteURL, _ := inviteResp["inviteUrl"].(string)
	token := inviteURL[strings.LastIndex(inviteURL, "/")+1:]

	mustDoJSON(t, app, "PUT", "/gateway/v1/devices/devcollab1/identity-key", identityPayload(collabIdentityKey), "collab1", "collab@example.com", fiber.StatusNoContent)
	mustDoJSON(t, app, "POST", "/gateway/v1/shares/invites/accept", map[string]any{
		"token":    token,
		"deviceId": "devcollab1",
	}, "collab1", "collab@example.com", fiber.StatusOK)

	clientEphemeral := testX25519Public("client-ephemeral")
	clientNonce := testNonce("client-nonce")
	handshakeID := "hs_secure_abc1"
	handshake := mustDoJSON(t, app, "POST", "/gateway/v1/sessions/sessabc1/handshake/client-init", map[string]any{
		"device_id":                   "devowner1",
		"client_ephemeral_public_key": clientEphemeral,
		"client_session_nonce":        clientNonce,
		"handshake_id":                handshakeID,
	}, "collab1", "collab@example.com", fiber.StatusAccepted)
	if handshake["status"] != "pending_agent_connection" {
		t.Fatalf("expected handshake status pending_agent_connection, got %v", handshake["status"])
	}

	ackPayload := testSignedHandshakeAck(t, "sessabc1", handshakeID, clientEphemeral, clientNonce, ownerIdentityPriv)
	ackPayload["device_id"] = "devowner1"
	ackPayload["handshake_id"] = handshakeID
	mustDoJSON(t, app, "POST", "/gateway/v1/sessions/sessabc1/handshake/agent-ack", ackPayload, "owner1", "owner@example.com", fiber.StatusAccepted)

	var forwarded map[string]any
	h.mu.Lock()
	h.agents["devowner1"] = &agentConn{deviceID: "devowner1", ownerUID: "owner1"}
	h.mu.Unlock()
	h.agentWriteFn = func(_ *agentConn, payload map[string]any) error {
		forwarded = payload
		return nil
	}

	mustDoJSONWithHeaders(t, app, "POST", "/gateway/v1/sessions/sessabc1/messages", map[string]any{
		"message_id": "msg-1",
		"encrypted":  true,
		"ciphertext": "abc",
		"nonce":      "def",
		"tag":        "ghi",
		"seq":        1,
	}, "collab1", "collab@example.com", fiber.StatusAccepted, map[string]string{"X-Idempotency-Key": "idem-1"})
	if forwarded == nil || firstStringMap(forwarded, "message_id") != "msg-1" {
		t.Fatalf("expected forwarded agent payload with message_id msg-1")
	}

	events := h.replayEvents(context.Background(), "sessabc1", "")
	if len(events) != 1 {
		t.Fatalf("expected 1 event (handshake ack), got %d", len(events))
	}

	mustDoJSONWithHeaders(t, app, "POST", "/gateway/v1/sessions/sessabc1/messages", map[string]any{
		"message_id": "msg-2",
		"encrypted":  true,
		"ciphertext": "abc",
		"nonce":      "def",
		"tag":        "ghi",
		"seq":        2,
	}, "stranger1", "stranger@example.com", fiber.StatusForbidden, map[string]string{"X-Idempotency-Key": "idem-2"})
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
	group.Get("/devices", h.ListDevices)
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
	return mustDoJSONWithHeaders(t, app, method, path, payload, uid, email, expectedStatus, nil)
}

func mustDoJSONWithHeaders(
	t *testing.T,
	app *fiber.App,
	method string,
	path string,
	payload map[string]any,
	uid string,
	email string,
	expectedStatus int,
	extraHeaders map[string]string,
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
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
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
