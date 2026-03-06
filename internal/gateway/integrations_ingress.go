package gateway

import (
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

	bodyBytes := c.Body()
	if routeCopy.MaxBodyBytes > 0 && len(bodyBytes) > routeCopy.MaxBodyBytes {
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

	inflight, err := h.sendTunnelRequest(c.Context(), routeID, requestFrame)
	if err != nil {
		slog.Warn("tunnel send failed", "route", routeID, "err", err)
		return c.SendStatus(fiber.StatusServiceUnavailable)
	}

	deadline := time.Duration(routeCopy.DeadlineMs) * time.Millisecond
	if deadline <= 0 {
		deadline = time.Duration(defaultIntegrationDeadlineMS) * time.Millisecond
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
			headLower := strings.ToLower(pair[0])
			if headLower == "transfer-encoding" || headLower == "connection" {
				continue
			}
			c.Set(pair[0], pair[1])
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
		return c.SendStatus(resp.Status)
	case <-timer.C:
		slog.Warn("deadline exceeded", "route", routeID, "request", requestID, "deadline_ms", routeCopy.DeadlineMs)
		return c.SendStatus(fiber.StatusGatewayTimeout)
	}
}
