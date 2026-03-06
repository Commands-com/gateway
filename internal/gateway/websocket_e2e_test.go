package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	fastws "github.com/fasthttp/websocket"
	"github.com/gofiber/fiber/v3"

	"oss-commands-gateway/internal/auth"
	"oss-commands-gateway/internal/config"
)

func TestAgentWebSocketReconnectE2E(t *testing.T) {
	ownerIdentityKey, ownerIdentityPriv := testEd25519Identity("owner1")
	sessionID := "sessws1"
	handshakeID := "hsws1"
	clientEphemeral := testX25519Public("client-e2e")
	clientNonce := testNonce("nonce-e2e")

	h := NewHandler(&config.Config{
		StateBackend:           config.StateBackendMemory,
		PublicBaseURL:          "http://localhost:8080",
		FrontendURL:            "https://example.com",
		RequireEncryptedFrames: true,
		IdempotencyTTLSeconds:  300,
		TransportTokenSecret:   "transport-secret-for-tests",
		TransportTokenTTL:      time.Hour,
	})
	httpBase, wsBase, cleanup := startGatewayWSHarness(t, h)
	defer cleanup()

	client := &http.Client{Timeout: 3 * time.Second}

	mustHTTPJSON(t, client, fiber.MethodPut, httpBase+"/gateway/v1/devices/devowner1/identity-key", identityPayload(ownerIdentityKey), "owner1", "owner@example.com", fiber.StatusNoContent)
	mustHTTPJSON(t, client, fiber.MethodPost, httpBase+"/gateway/v1/sessions/"+sessionID+"/handshake/client-init", map[string]any{
		"device_id":                   "devowner1",
		"client_ephemeral_public_key": clientEphemeral,
		"client_session_nonce":        clientNonce,
		"handshake_id":                handshakeID,
	}, "owner1", "owner@example.com", fiber.StatusAccepted)

	agentURL := wsBase + "/gateway/v1/agent/connect?device_id=devowner1"
	conn1 := mustDialWS(t, agentURL, "owner1", "owner@example.com")
	defer conn1.Close()
	connected1 := mustReadWSJSONByType(t, conn1, 2*time.Second, "gateway.connected")
	if connected1["type"] != "gateway.connected" {
		t.Fatalf("expected gateway.connected on first connection, got %v", connected1)
	}
	transportInit1 := mustReadWSJSONByType(t, conn1, 2*time.Second, "transport.init")
	if strings.TrimSpace(asString(transportInit1["transport_token"])) == "" {
		t.Fatalf("expected transport token on first connection")
	}
	handshakeRequest1 := mustReadWSJSONByType(t, conn1, 2*time.Second, "session.handshake.request")
	if handshakeRequest1["handshake_id"] != handshakeID {
		t.Fatalf("expected handshake request %s on first connection, got %v", handshakeID, handshakeRequest1)
	}

	conn2 := mustDialWS(t, agentURL, "owner1", "owner@example.com")
	defer conn2.Close()
	connected2 := mustReadWSJSONByType(t, conn2, 2*time.Second, "gateway.connected")
	if connected2["type"] != "gateway.connected" {
		t.Fatalf("expected gateway.connected on second connection, got %v", connected2)
	}
	transportInit2 := mustReadWSJSONByType(t, conn2, 2*time.Second, "transport.init")
	transportToken2 := strings.TrimSpace(asString(transportInit2["transport_token"]))
	if transportToken2 == "" {
		t.Fatalf("expected transport token on second connection")
	}
	handshakeRequest2 := mustReadWSJSONByType(t, conn2, 2*time.Second, "session.handshake.request")
	if handshakeRequest2["handshake_id"] != handshakeID {
		t.Fatalf("expected handshake request %s on second connection, got %v", handshakeID, handshakeRequest2)
	}

	conn1.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := conn1.ReadMessage(); err == nil {
		t.Fatalf("expected first websocket to be closed after reconnect")
	}

	ackPayload := testSignedHandshakeAck(t, sessionID, handshakeID, clientEphemeral, clientNonce, ownerIdentityPriv)
	ackPayload["type"] = "session.handshake.ack"
	ackPayload["session_id"] = sessionID
	ackPayload["handshake_id"] = handshakeID
	ackPayload["transport_token"] = transportToken2
	ackPayload["t_seq"] = 1
	mustWriteWSJSON(t, conn2, ackPayload)

	var handshakeState map[string]any
	for i := 0; i < 10; i++ {
		handshakeState = mustHTTPJSON(t, client, fiber.MethodGet, httpBase+"/gateway/v1/sessions/"+sessionID+"/handshake/"+handshakeID, nil, "owner1", "owner@example.com", fiber.StatusOK)
		if handshakeState["status"] == "agent_acknowledged" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if handshakeState["status"] != "agent_acknowledged" {
		t.Fatalf("expected handshake to be acknowledged, got %v", handshakeState)
	}

	mustHTTPJSONWithHeaders(t, client, fiber.MethodPost, httpBase+"/gateway/v1/sessions/"+sessionID+"/messages", map[string]any{
		"type":         "session.message",
		"message_id":   "m-reconnect",
		"handshake_id": handshakeID,
		"encrypted":    true,
		"ciphertext":   "cipher",
		"nonce":        "nonce",
		"tag":          "tag",
		"seq":          1,
	}, "owner1", "owner@example.com", fiber.StatusAccepted, map[string]string{"X-Idempotency-Key": "ws-idem-1"})

	frame := mustReadWSJSONByType(t, conn2, 2*time.Second, "session.message")
	if frame["type"] != "session.message" {
		t.Fatalf("expected session.message frame after reconnect, got %v", frame)
	}
	if frame["message_id"] != "m-reconnect" {
		t.Fatalf("expected message_id m-reconnect, got %v", frame["message_id"])
	}
}

func TestTunnelIngressReconnectE2E(t *testing.T) {
	h := NewHandler(&config.Config{StateBackend: config.StateBackendMemory, PublicBaseURL: "http://localhost:8080", FrontendURL: "https://example.com"})
	httpBase, wsBase, cleanup := startGatewayWSHarness(t, h)
	defer cleanup()

	client := &http.Client{Timeout: 5 * time.Second}

	ownerIdentityKey, _ := testEd25519Identity("owner1")
	mustHTTPJSON(t, client, fiber.MethodPut, httpBase+"/gateway/v1/devices/devowner1/identity-key", identityPayload(ownerIdentityKey), "owner1", "owner@example.com", fiber.StatusNoContent)
	createResp := mustHTTPJSON(t, client, fiber.MethodPost, httpBase+"/gateway/v1/integrations/routes", map[string]any{
		"device_id":       "devowner1",
		"interface_type":  "slack_events",
		"token_auth_mode": "path",
	}, "owner1", "owner@example.com", fiber.StatusCreated)

	routeObj, ok := createResp["route"].(map[string]any)
	if !ok {
		t.Fatalf("expected route object in create response: %v", createResp)
	}
	routeID, _ := routeObj["route_id"].(string)
	routeToken, _ := createResp["route_token"].(string)
	if routeID == "" || routeToken == "" {
		t.Fatalf("expected route id/token in response: %v", createResp)
	}

	tunnelURL := wsBase + "/gateway/v1/integrations/tunnel/connect?device_id=devowner1"
	conn1 := mustDialWS(t, tunnelURL, "owner1", "owner@example.com")
	defer conn1.Close()
	frame1 := mustReadWSJSON(t, conn1, 2*time.Second)
	if frame1["type"] != "tunnel.connected" {
		t.Fatalf("expected tunnel.connected on first connection, got %v", frame1)
	}

	conn2 := mustDialWS(t, tunnelURL, "owner1", "owner@example.com")
	defer conn2.Close()
	frame2 := mustReadWSJSON(t, conn2, 2*time.Second)
	if frame2["type"] != "tunnel.connected" {
		t.Fatalf("expected tunnel.connected on second connection, got %v", frame2)
	}

	conn1.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := conn1.ReadMessage(); err == nil {
		t.Fatalf("expected first tunnel websocket to be closed after reconnect")
	}

	mustWriteWSJSON(t, conn2, map[string]any{
		"type":       "tunnel.activate",
		"request_id": "act-1",
		"routes":     []any{routeID},
	})
	activate := mustReadWSJSON(t, conn2, 2*time.Second)
	if activate["type"] != "tunnel.activate.result" {
		t.Fatalf("expected tunnel.activate.result, got %v", activate)
	}

	requestBody := []byte(`{"hello":"world"}`)
	ingressReq, err := http.NewRequest(fiber.MethodPost, httpBase+"/integrations/"+routeID+"/"+routeToken, bytes.NewReader(requestBody))
	if err != nil {
		t.Fatalf("build ingress request failed: %v", err)
	}
	ingressReq.Header.Set("Content-Type", "application/json")
	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := client.Do(ingressReq)
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()

	requestFrame := mustReadWSJSON(t, conn2, 3*time.Second)
	if requestFrame["type"] != "tunnel.request" {
		t.Fatalf("expected tunnel.request, got %v", requestFrame)
	}
	requestID, _ := requestFrame["request_id"].(string)
	if requestID == "" {
		t.Fatalf("expected request_id in tunnel.request frame: %v", requestFrame)
	}

	mustWriteWSJSON(t, conn2, map[string]any{
		"type":       "tunnel.response",
		"request_id": requestID,
		"status":     207,
		"headers": []any{
			[]any{"Content-Type", "text/plain"},
			[]any{"X-Tunnel", "ok"},
		},
		"body_base64": base64.StdEncoding.EncodeToString([]byte("relay-ok")),
	})

	select {
	case err := <-errCh:
		t.Fatalf("ingress request failed: %v", err)
	case resp := <-respCh:
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 207 {
			t.Fatalf("expected ingress status 207, got %d body=%s", resp.StatusCode, string(body))
		}
		if string(body) != "relay-ok" {
			t.Fatalf("expected relay-ok body, got %q", string(body))
		}
		if resp.Header.Get("X-Tunnel") != "ok" {
			t.Fatalf("expected X-Tunnel header from tunnel response")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for ingress response")
	}
}

func startGatewayWSHarness(t *testing.T, h *Handler) (string, string, func()) {
	t.Helper()
	app := fiber.New()
	app.Use(func(c fiber.Ctx) error {
		uid := strings.TrimSpace(c.Get("X-Test-UID"))
		if uid != "" {
			c.Locals("principal", &auth.Principal{
				UID:         uid,
				Email:       strings.TrimSpace(c.Get("X-Test-Email")),
				DisplayName: strings.TrimSpace(c.Get("X-Test-Name")),
			})
		}
		return c.Next()
	})

	group := app.Group("/gateway/v1")
	group.Put("/devices/:device_id/identity-key", h.PutDeviceIdentityKey)
	group.Post("/sessions/:session_id/handshake/client-init", h.PostHandshakeClientInit)
	group.Get("/sessions/:session_id/handshake/:handshake_id", h.GetHandshake)
	group.Post("/sessions/:session_id/messages", h.PostSessionMessage)
	group.Post("/integrations/routes", h.CreateIntegrationRoute)
	group.Use("/agent/connect", h.RequireAgentWebSocketUpgrade)
	group.Get("/agent/connect", h.AgentConnectWebSocket())
	group.Use("/integrations/tunnel/connect", h.RequireIntegrationTunnelUpgrade)
	group.Get("/integrations/tunnel/connect", h.IntegrationTunnelWebSocket())

	app.All("/integrations/:route_id/:route_token", h.HandlePublicIngress)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	serveDone := make(chan struct{})
	go func() {
		_ = app.Listener(listener)
		close(serveDone)
	}()

	cleanup := func() {
		_ = app.Shutdown()
		_ = listener.Close()
		select {
		case <-serveDone:
		case <-time.After(2 * time.Second):
		}
	}

	host := listener.Addr().String()
	return fmt.Sprintf("http://%s", host), fmt.Sprintf("ws://%s", host), cleanup
}

func mustDialWS(t *testing.T, url, uid, email string) *fastws.Conn {
	t.Helper()
	headers := http.Header{}
	if uid != "" {
		headers.Set("X-Test-UID", uid)
	}
	if email != "" {
		headers.Set("X-Test-Email", email)
	}
	conn, resp, err := fastws.DefaultDialer.Dial(url, headers)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("websocket dial failed url=%s status=%d err=%v", url, status, err)
	}
	return conn
}

func mustReadWSJSON(t *testing.T, conn *fastws.Conn, timeout time.Duration) map[string]any {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	_, payload, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("websocket read failed: %v", err)
	}
	var frame map[string]any
	if err := json.Unmarshal(payload, &frame); err != nil {
		t.Fatalf("decode websocket payload failed: %v payload=%s", err, string(payload))
	}
	return frame
}

func mustReadWSJSONByType(t *testing.T, conn *fastws.Conn, timeout time.Duration, frameType string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatalf("timed out waiting for websocket frame type %q", frameType)
		}
		frame := mustReadWSJSON(t, conn, remaining)
		if strings.TrimSpace(asString(frame["type"])) == frameType {
			return frame
		}
	}
}

func mustWriteWSJSON(t *testing.T, conn *fastws.Conn, payload map[string]any) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal websocket payload failed: %v", err)
	}
	if err := conn.WriteMessage(fastws.TextMessage, raw); err != nil {
		t.Fatalf("websocket write failed: %v", err)
	}
}

func mustHTTPJSON(
	t *testing.T,
	client *http.Client,
	method string,
	url string,
	payload map[string]any,
	uid string,
	email string,
	expectedStatus int,
) map[string]any {
	return mustHTTPJSONWithHeaders(t, client, method, url, payload, uid, email, expectedStatus, nil)
}

func mustHTTPJSONWithHeaders(
	t *testing.T,
	client *http.Client,
	method string,
	url string,
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
			t.Fatalf("marshal payload failed: %v", err)
		}
	}

	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request failed: %v", err)
	}
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

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("http request failed: %v", err)
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(rawBody, &out)
	if out == nil {
		out = map[string]any{}
	}
	if resp.StatusCode != expectedStatus {
		t.Fatalf("unexpected status for %s %s: got=%d want=%d body=%s", method, url, resp.StatusCode, expectedStatus, string(rawBody))
	}
	return out
}
