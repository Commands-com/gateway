package gateway

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"oss-commands-gateway/internal/auth"
	"oss-commands-gateway/internal/config"
)

func TestIngressRelaysThroughActiveTunnel(t *testing.T) {
	h := NewHandler(&config.Config{
		FrontendURL:   "https://frontend.example",
		StateBackend:  config.StateBackendMemory,
		PublicBaseURL: "http://localhost:8080",
	})
	app := newGatewayIntegrationTestApp(h)

	ownerIdentityKey, _ := testEd25519Identity("owner1")
	mustDoJSON(t, app, "PUT", "/gateway/v1/devices/devowner1/identity-key", identityPayload(ownerIdentityKey), "owner1", "owner@example.com", fiber.StatusNoContent)
	createResp := mustDoJSON(t, app, "POST", "/gateway/v1/integrations/routes", map[string]any{
		"device_id":       "devowner1",
		"interface_type":  "slack_events",
		"token_auth_mode": "path",
	}, "owner1", "owner@example.com", fiber.StatusCreated)

	routeObj, ok := createResp["route"].(map[string]any)
	if !ok {
		t.Fatalf("expected route object in create response")
	}
	routeID, _ := routeObj["route_id"].(string)
	routeToken, _ := createResp["route_token"].(string)
	if routeID == "" || routeToken == "" {
		t.Fatalf("expected route_id and route_token in create response")
	}

	tc := &tunnelConn{
		deviceID:        "devowner1",
		ownerUID:        "owner1",
		activatedRoutes: map[string]bool{routeID: true},
	}
	route, found, err := h.store.GetIntegrationRoute(context.Background(), routeID)
	if err != nil || !found || route == nil {
		t.Fatalf("expected route to exist, found=%v err=%v", found, err)
	}
	route.Status = "active"
	route.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := h.store.SaveIntegrationRoute(context.Background(), route); err != nil {
		t.Fatalf("save route failed: %v", err)
	}
	if err := h.store.SetActiveRouteDevice(context.Background(), routeID, tc.deviceID); err != nil {
		t.Fatalf("set active route failed: %v", err)
	}
	h.mu.Lock()
	h.tunnelConns[tc.deviceID] = tc
	h.mu.Unlock()
	if _, ok, err := h.store.ClaimRouteLease(context.Background(), routeID, h.nodeID, routeLeaseTTL); err != nil || !ok {
		t.Fatalf("expected route lease claim to succeed, err=%v", err)
	}
	if err := h.startRouteBusSubscription(tc, routeID); err != nil {
		t.Fatalf("start route bus subscription failed: %v", err)
	}

	h.tunnelWriteFn = func(conn *tunnelConn, frame map[string]any) error {
		requestID := firstStringMap(frame, "request_id")
		h.handleTunnelResponse(conn, map[string]any{
			"type":       "tunnel.response",
			"request_id": requestID,
			"status":     201,
			"headers": []any{
				[]any{"Content-Type", "text/plain"},
				[]any{"X-Relay", "ok"},
			},
			"body_base64": base64.StdEncoding.EncodeToString([]byte("relayed")),
		})
		return nil
	}

	req := httptest.NewRequest("POST", "/integrations/"+routeID+"/"+routeToken+"?source=test", strings.NewReader(`{"hello":"world"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("ingress request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != fiber.StatusCreated {
		t.Fatalf("expected status 201, got %d body=%s", resp.StatusCode, string(body))
	}
	if string(body) != "relayed" {
		t.Fatalf("expected relayed body, got %q", string(body))
	}
	if resp.Header.Get("X-Relay") != "ok" {
		t.Fatalf("expected X-Relay header from tunnel response")
	}
}

func TestIngressRejectsTokenMismatch(t *testing.T) {
	h := NewHandler(&config.Config{
		FrontendURL:   "https://frontend.example",
		StateBackend:  config.StateBackendMemory,
		PublicBaseURL: "http://localhost:8080",
	})
	app := newGatewayIntegrationTestApp(h)

	ownerIdentityKey, _ := testEd25519Identity("owner1")
	mustDoJSON(t, app, "PUT", "/gateway/v1/devices/devowner1/identity-key", identityPayload(ownerIdentityKey), "owner1", "owner@example.com", fiber.StatusNoContent)
	createResp := mustDoJSON(t, app, "POST", "/gateway/v1/integrations/routes", map[string]any{
		"device_id":       "devowner1",
		"interface_type":  "slack_events",
		"token_auth_mode": "path",
	}, "owner1", "owner@example.com", fiber.StatusCreated)

	routeObj, ok := createResp["route"].(map[string]any)
	if !ok {
		t.Fatalf("expected route object in create response")
	}
	routeID, _ := routeObj["route_id"].(string)

	calls := 0
	h.tunnelWriteFn = func(_ *tunnelConn, _ map[string]any) error {
		calls++
		return nil
	}

	req := httptest.NewRequest("POST", "/integrations/"+routeID+"/invalid-token", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("ingress mismatch request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != fiber.StatusNotFound {
		t.Fatalf("expected 404 for token mismatch, got %d", resp.StatusCode)
	}
	if calls != 0 {
		t.Fatalf("expected tunnel not to be called on token mismatch")
	}
}

func TestIngressRejectsWhenLeaseOwnedByRemoteNode(t *testing.T) {
	h := NewHandlerWithOptions(
		&config.Config{
			FrontendURL:   "https://frontend.example",
			StateBackend:  config.StateBackendMemory,
			PublicBaseURL: "http://localhost:8080",
		},
		HandlerOptions{NodeID: "node-local-a"},
	)
	app := newGatewayIntegrationTestApp(h)

	ownerIdentityKey, _ := testEd25519Identity("owner1")
	mustDoJSON(t, app, "PUT", "/gateway/v1/devices/devowner1/identity-key", identityPayload(ownerIdentityKey), "owner1", "owner@example.com", fiber.StatusNoContent)
	createResp := mustDoJSON(t, app, "POST", "/gateway/v1/integrations/routes", map[string]any{
		"device_id":       "devowner1",
		"interface_type":  "slack_events",
		"token_auth_mode": "path",
	}, "owner1", "owner@example.com", fiber.StatusCreated)

	routeObj, ok := createResp["route"].(map[string]any)
	if !ok {
		t.Fatalf("expected route object in create response")
	}
	routeID, _ := routeObj["route_id"].(string)
	routeToken, _ := createResp["route_token"].(string)
	if routeID == "" || routeToken == "" {
		t.Fatalf("expected route_id and route_token in create response")
	}

	tc := &tunnelConn{
		deviceID:        "devowner1",
		ownerUID:        "owner1",
		activatedRoutes: map[string]bool{routeID: true},
	}
	route, found, err := h.store.GetIntegrationRoute(context.Background(), routeID)
	if err != nil || !found || route == nil {
		t.Fatalf("expected route to exist, found=%v err=%v", found, err)
	}
	route.Status = "active"
	route.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := h.store.SaveIntegrationRoute(context.Background(), route); err != nil {
		t.Fatalf("save route failed: %v", err)
	}
	if err := h.store.SetActiveRouteDevice(context.Background(), routeID, tc.deviceID); err != nil {
		t.Fatalf("set active route failed: %v", err)
	}
	h.mu.Lock()
	h.tunnelConns[tc.deviceID] = tc
	h.mu.Unlock()
	if _, ok, err := h.store.ClaimRouteLease(context.Background(), routeID, "node-remote", routeLeaseTTL); err != nil || !ok {
		t.Fatalf("expected remote lease claim to succeed, err=%v", err)
	}

	calls := 0
	h.tunnelWriteFn = func(_ *tunnelConn, _ map[string]any) error {
		calls++
		return nil
	}

	req := httptest.NewRequest("POST", "/integrations/"+routeID+"/"+routeToken, nil)
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 5 * time.Second}) // allow time for deadline timeout
	if err != nil {
		t.Fatalf("ingress request failed: %v", err)
	}
	defer resp.Body.Close()
	// When the lease is owned by a remote node, the request is forwarded via
	// the MessageBus rather than rejected immediately. With no remote node
	// subscribed, the request will timeout at the route deadline.
	if resp.StatusCode != fiber.StatusGatewayTimeout {
		t.Fatalf("expected 504 (gateway timeout via cross-node routing) when lease is owned by remote node, got %d", resp.StatusCode)
	}
	if calls != 0 {
		t.Fatalf("expected local tunnel dispatch not to run when lease owner is remote")
	}
}

func TestTunnelLeaseRenewalDropsLostRoute(t *testing.T) {
	h := NewHandlerWithOptions(
		&config.Config{
			FrontendURL:   "https://frontend.example",
			StateBackend:  config.StateBackendMemory,
			PublicBaseURL: "http://localhost:8080",
		},
		HandlerOptions{NodeID: "node-local-a"},
	)
	app := newGatewayIntegrationTestApp(h)

	ownerIdentityKey, _ := testEd25519Identity("owner1")
	mustDoJSON(t, app, "PUT", "/gateway/v1/devices/devowner1/identity-key", identityPayload(ownerIdentityKey), "owner1", "owner@example.com", fiber.StatusNoContent)
	createResp := mustDoJSON(t, app, "POST", "/gateway/v1/integrations/routes", map[string]any{
		"device_id":       "devowner1",
		"interface_type":  "slack_events",
		"token_auth_mode": "path",
	}, "owner1", "owner@example.com", fiber.StatusCreated)

	routeObj, ok := createResp["route"].(map[string]any)
	if !ok {
		t.Fatalf("expected route object in create response")
	}
	routeID, _ := routeObj["route_id"].(string)
	if routeID == "" {
		t.Fatalf("expected route_id in create response")
	}

	tc := &tunnelConn{
		deviceID:        "devowner1",
		ownerUID:        "owner1",
		activatedRoutes: map[string]bool{routeID: true},
	}
	route, found, err := h.store.GetIntegrationRoute(context.Background(), routeID)
	if err != nil || !found || route == nil {
		t.Fatalf("expected route to exist, found=%v err=%v", found, err)
	}
	route.Status = "active"
	route.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := h.store.SaveIntegrationRoute(context.Background(), route); err != nil {
		t.Fatalf("save route failed: %v", err)
	}
	if err := h.store.SetActiveRouteDevice(context.Background(), routeID, tc.deviceID); err != nil {
		t.Fatalf("set active route failed: %v", err)
	}
	h.mu.Lock()
	h.tunnelConns[tc.deviceID] = tc
	h.mu.Unlock()
	if _, ok, err := h.store.ClaimRouteLease(context.Background(), routeID, h.nodeID, routeLeaseTTL); err != nil || !ok {
		t.Fatalf("expected local lease claim to succeed, err=%v", err)
	}
	if err := h.store.ReleaseRouteLease(context.Background(), routeID, h.nodeID); err != nil {
		t.Fatalf("release lease failed: %v", err)
	}

	h.renewTunnelLeases(tc)

	h.mu.RLock()
	_, stillActive := tc.activatedRoutes[routeID]
	h.mu.RUnlock()
	if stillActive {
		t.Fatalf("expected lost lease route to be removed from tunnel activated routes")
	}
	if _, active, err := h.store.GetActiveRouteDevice(context.Background(), routeID); err != nil || active {
		t.Fatalf("expected active route binding to be cleared, active=%v err=%v", active, err)
	}
	updatedRoute, found, err := h.store.GetIntegrationRoute(context.Background(), routeID)
	if err != nil || !found || updatedRoute == nil {
		t.Fatalf("expected route to exist after lease loss, found=%v err=%v", found, err)
	}
	if updatedRoute.Status != "inactive" {
		t.Fatalf("expected route status inactive after lease loss, got %s", updatedRoute.Status)
	}
}

func TestSetTunnelRouteStatusGuardsTerminalAndDeviceMismatch(t *testing.T) {
	h := NewHandler(&config.Config{
		FrontendURL:   "https://frontend.example",
		StateBackend:  config.StateBackendMemory,
		PublicBaseURL: "http://localhost:8080",
	})

	now := time.Now().UTC().Format(time.RFC3339)
	routeID := "rt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	route := &integrationRoute{
		RouteID:          routeID,
		OwnerUID:         "owner1",
		DeviceID:         "devowner1",
		InterfaceType:    "http",
		TokenAuthMode:    "path",
		Status:           "active",
		DeadlineMs:       2500,
		MaxBodyBytes:     1024,
		TokenMaxAgeDays:  90,
		TokenExpiresAt:   now,
		TokenCurrentHash: "hash",
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := h.store.SaveIntegrationRoute(context.Background(), route); err != nil {
		t.Fatalf("save route failed: %v", err)
	}

	if err := h.setTunnelRouteStatus(routeID, "different-device", "inactive", now, false); err != nil {
		t.Fatalf("unexpected error for mismatched-device transition: %v", err)
	}
	stored, found, err := h.store.GetIntegrationRoute(context.Background(), routeID)
	if err != nil || !found || stored == nil {
		t.Fatalf("expected stored route, found=%v err=%v", found, err)
	}
	if stored.Status != "active" {
		t.Fatalf("expected mismatched-device transition to be ignored, got status=%s", stored.Status)
	}

	stored.Status = "revoked"
	stored.UpdatedAt = now
	if err := h.store.SaveIntegrationRoute(context.Background(), stored); err != nil {
		t.Fatalf("save revoked route failed: %v", err)
	}

	if err := h.setTunnelRouteStatus(routeID, "devowner1", "provisioned", now, false); err != nil {
		t.Fatalf("unexpected error for revoked transition: %v", err)
	}
	stored, found, err = h.store.GetIntegrationRoute(context.Background(), routeID)
	if err != nil || !found || stored == nil {
		t.Fatalf("expected stored route after revoked transition, found=%v err=%v", found, err)
	}
	if stored.Status != "revoked" {
		t.Fatalf("expected revoked status to be preserved, got %s", stored.Status)
	}

	err = h.setTunnelRouteStatus(routeID, "devowner1", "active", now, true)
	if !errors.Is(err, errRouteStatusUpdateSkipped) {
		t.Fatalf("expected strict transition to fail for revoked route, got %v", err)
	}
}

func TestWebSocketUpgradeMiddlewareForAgentAndTunnel(t *testing.T) {
	h := NewHandler(&config.Config{
		FrontendURL:   "https://frontend.example",
		StateBackend:  config.StateBackendMemory,
		PublicBaseURL: "http://localhost:8080",
	})
	app := newGatewayIntegrationTestApp(h)

	ownerIdentityKey, _ := testEd25519Identity("owner1")
	mustDoJSON(t, app, "PUT", "/gateway/v1/devices/devowner1/identity-key", identityPayload(ownerIdentityKey), "owner1", "owner@example.com", fiber.StatusNoContent)

	reqForbidden := httptest.NewRequest("GET", "/gateway/v1/agent/connect?device_id=devowner1", nil)
	reqForbidden.Header.Set("X-Test-UID", "other-user")
	reqForbidden.Header.Set("X-Test-Email", "other@example.com")
	reqForbidden.Header.Set("Connection", "Upgrade")
	reqForbidden.Header.Set("Upgrade", "websocket")
	respForbidden, err := app.Test(reqForbidden)
	if err != nil {
		t.Fatalf("agent forbidden request failed: %v", err)
	}
	defer respForbidden.Body.Close()
	if respForbidden.StatusCode != fiber.StatusForbidden {
		t.Fatalf("expected 403 for non-owner agent upgrade, got %d", respForbidden.StatusCode)
	}

	reqUpgradeRequired := httptest.NewRequest("GET", "/gateway/v1/agent/connect?device_id=devowner1", nil)
	reqUpgradeRequired.Header.Set("X-Test-UID", "owner1")
	reqUpgradeRequired.Header.Set("X-Test-Email", "owner@example.com")
	respUpgradeRequired, err := app.Test(reqUpgradeRequired)
	if err != nil {
		t.Fatalf("agent upgrade-required request failed: %v", err)
	}
	defer respUpgradeRequired.Body.Close()
	if respUpgradeRequired.StatusCode != fiber.StatusUpgradeRequired {
		t.Fatalf("expected 426 for non-websocket agent request, got %d", respUpgradeRequired.StatusCode)
	}

	reqTunnelAllowed := httptest.NewRequest("GET", "/gateway/v1/integrations/tunnel/connect?device_id=devowner1", nil)
	reqTunnelAllowed.Header.Set("X-Test-UID", "owner1")
	reqTunnelAllowed.Header.Set("X-Test-Email", "owner@example.com")
	reqTunnelAllowed.Header.Set("Connection", "Upgrade")
	reqTunnelAllowed.Header.Set("Upgrade", "websocket")
	respTunnelAllowed, err := app.Test(reqTunnelAllowed)
	if err != nil {
		t.Fatalf("tunnel websocket-marked request failed: %v", err)
	}
	defer respTunnelAllowed.Body.Close()
	if respTunnelAllowed.StatusCode != fiber.StatusNoContent {
		t.Fatalf("expected 204 for tunnel websocket-marked middleware path, got %d", respTunnelAllowed.StatusCode)
	}
}

func newGatewayIntegrationTestApp(h *Handler) *fiber.App {
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
	group.Post("/integrations/routes", h.CreateIntegrationRoute)
	group.Put("/integrations/routes/:route_id", h.UpdateIntegrationRoute)
	group.Delete("/integrations/routes/:route_id", h.DeleteIntegrationRoute)
	group.Get("/integrations/routes", h.ListIntegrationRoutes)
	group.Post("/integrations/routes/:route_id/rotate-token", h.RotateIntegrationRouteToken)

	group.Use("/agent/connect", h.RequireAgentWebSocketUpgrade)
	group.Get("/agent/connect", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusNoContent)
	})

	group.Use("/integrations/tunnel/connect", h.RequireIntegrationTunnelUpgrade)
	group.Get("/integrations/tunnel/connect", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusNoContent)
	})

	app.All("/integrations/:route_id/:route_token", h.HandlePublicIngress)
	return app
}
