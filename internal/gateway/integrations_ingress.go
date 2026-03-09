package gateway

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
)

func (h *Handler) HandlePublicIngress(c fiber.Ctx) error {
	routeID := strings.TrimSpace(c.Params("route_id"))
	routeToken := strings.TrimSpace(c.Params("route_token"))
	if routeID == "" || routeToken == "" {
		return c.SendStatus(fiber.StatusNotFound)
	}

	now := time.Now().UTC()
	route, found, err := h.store.GetIntegrationRoute(c.Context(), routeID)
	if err != nil {
		return c.SendStatus(fiber.StatusServiceUnavailable)
	}
	var routeCopy integrationRoute
	if found && route != nil {
		routeCopy = *route
	}
	if !found {
		return c.SendStatus(fiber.StatusNotFound)
	}

	if !constantTimeRouteTokenMatch(&routeCopy, routeToken, now) {
		return c.SendStatus(fiber.StatusNotFound)
	}
	if routeCopy.TokenExpiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339, routeCopy.TokenExpiresAt)
		if err == nil && now.After(expiresAt) {
			return c.SendStatus(fiber.StatusNotFound)
		}
	}
	if routeCopy.Status != "active" {
		return c.SendStatus(fiber.StatusServiceUnavailable)
	}
	_, leaseFound, err := h.store.GetRouteLease(c.Context(), routeID)
	if err != nil {
		return c.SendStatus(fiber.StatusServiceUnavailable)
	}
	if !leaseFound {
		return c.SendStatus(fiber.StatusServiceUnavailable)
	}
	// If the lease is held by a different node, still proceed — sendTunnelRequest
	// will forward via the MessageBus for cross-node routing.

	// Enforce body size limit BEFORE reading the body into memory to prevent
	// large requests from being fully buffered before rejection. Check
	// Content-Length header first (cheap), then verify actual body length.
	maxBody := routeCopy.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = defaultIntegrationMaxBodyBytes
	}
	if contentLen := c.Request().Header.ContentLength(); contentLen > maxBody {
		return c.SendStatus(fiber.StatusRequestEntityTooLarge)
	}
	bodyBytes := c.Body()
	if len(bodyBytes) > maxBody {
		return c.SendStatus(fiber.StatusRequestEntityTooLarge)
	}

	if err := h.store.TouchIntegrationRouteLastUsed(c.Context(), routeID, now.Format(time.RFC3339)); err != nil {
		slog.Warn("route touch failed", "route", routeID, "err", err)
	}

	headers := make([][]string, 0)
	c.Request().Header.VisitAll(func(key, value []byte) {
		head := string(key)
		headLower := strings.ToLower(head)
		if headLower == "host" || headLower == "connection" || headLower == "transfer-encoding" {
			return
		}
		headers = append(headers, []string{head, string(value)})
	})

	requestID := "req_" + uuid.New().String()[:12]
	rawTarget := c.OriginalURL()
	bodyBase64 := ""
	if len(bodyBytes) > 0 {
		bodyBase64 = base64.StdEncoding.EncodeToString(bodyBytes)
	}

	scheme := "https"
	if strings.EqualFold(c.Protocol(), "http") {
		scheme = "http"
	}
	host := c.Hostname()
	if host == "" {
		host = "localhost"
	}

	requestFrame := map[string]any{
		"type":              "tunnel.request",
		"request_id":        requestID,
		"route_id":          routeID,
		"method":            c.Method(),
		"scheme":            scheme,
		"host":              host,
		"external_url":      fmt.Sprintf("%s://%s%s", scheme, host, rawTarget),
		"raw_target":        rawTarget,
		"raw_target_base64": base64.StdEncoding.EncodeToString([]byte(rawTarget)),
		"path":              c.Path(),
		"query":             string(c.Request().URI().QueryString()),
		"headers":           headers,
		"body_base64":       bodyBase64,
		"received_at":       now.Format(time.RFC3339),
		"deadline_ms":       routeCopy.DeadlineMs,
	}

	deadline := time.Duration(routeCopy.DeadlineMs) * time.Millisecond
	if deadline <= 0 {
		deadline = time.Duration(defaultIntegrationDeadlineMS) * time.Millisecond
	}

	// Use a detached context for sendTunnelRequest because it spawns
	// background goroutines that outlive the Fiber handler. Fiber recycles
	// the underlying fasthttp.RequestCtx after the handler returns, so
	// passing c.Context() would cause data races or panics.
	tunnelCtx, tunnelCancel := context.WithTimeout(context.Background(), deadline)
	defer tunnelCancel()
	inflight, err := h.sendTunnelRequest(tunnelCtx, routeID, requestFrame)
	if err != nil {
		slog.Warn("tunnel send failed", "route", routeID, "err", err)
		return c.SendStatus(fiber.StatusServiceUnavailable)
	}

	timer := time.NewTimer(deadline)
	defer timer.Stop()

	select {
	case resp := <-inflight.responseCh:
		if resp == nil {
			return c.SendStatus(fiber.StatusBadGateway)
		}
		for _, pair := range resp.Headers {
			if len(pair) != 2 {
				continue
			}
			headerKey := pair[0]
			headerVal := pair[1]
			// Reject headers containing CRLF characters to prevent HTTP
			// response splitting attacks. Even though fasthttp typically
			// sanitizes these, we enforce it explicitly for defense in depth.
			if containsCRLF(headerKey) || containsCRLF(headerVal) {
				slog.Warn("dropping tunnel response header with CRLF",
					"route", routeID, "header", headerKey)
				continue
			}
			headLower := strings.ToLower(headerKey)
			// Filter out security-sensitive and hop-by-hop headers that a
			// malicious agent could abuse for session fixation, response
			// splitting, or HTTP desync.
			if isBlockedTunnelResponseHeader(headLower) {
				continue
			}
			c.Set(headerKey, headerVal)
		}
		if resp.BodyBase64 != "" {
			body, err := base64.StdEncoding.DecodeString(resp.BodyBase64)
			if err != nil {
				slog.Warn("body decode failed", "route", routeID, "request", requestID, "err", err)
				return c.SendStatus(fiber.StatusBadGateway)
			}
			return c.Status(resp.Status).Send(body)
		}
		if resp.Status <= 0 {
			return c.SendStatus(fiber.StatusBadGateway)
		}
		return c.Status(resp.Status).Send(nil)
	case <-timer.C:
		slog.Warn("deadline exceeded", "route", routeID, "request", requestID, "deadline_ms", routeCopy.DeadlineMs)
		return c.SendStatus(fiber.StatusGatewayTimeout)
	}
}

// blockedTunnelResponseHeaders is the set of HTTP headers that must not be
// passed through from the agent's tunnel response to the public HTTP client.
// These include hop-by-hop headers, headers that could cause HTTP desync, and
// security-sensitive headers that could enable session fixation or CORS bypass.
var blockedTunnelResponseHeaders = map[string]struct{}{
	"host":                             {},
	"connection":                       {},
	"transfer-encoding":                {},
	"content-length":                   {},
	"set-cookie":                       {},
	"set-cookie2":                      {},
	"proxy-authenticate":               {},
	"proxy-authorization":              {},
	"te":                               {},
	"trailer":                          {},
	"upgrade":                          {},
	"keep-alive":                       {},
	"access-control-allow-origin":      {},
	"access-control-allow-credentials": {},
	"access-control-allow-headers":     {},
	"access-control-allow-methods":     {},
	"access-control-expose-headers":    {},
	"access-control-max-age":           {},
}

func isBlockedTunnelResponseHeader(headerLower string) bool {
	_, blocked := blockedTunnelResponseHeaders[headerLower]
	return blocked
}

// containsCRLF returns true if s contains any carriage return or line feed
// characters that could be used for HTTP response splitting.
func containsCRLF(s string) bool {
	return strings.ContainsAny(s, "\r\n")
}
