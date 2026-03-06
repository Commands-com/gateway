package gateway

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"

	"oss-commands-gateway/internal/auth"
)

var routeIDPattern = regexp.MustCompile(`^rt_[a-f0-9]{32}$`)
var routeTokenCharset = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
var interfaceTypePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

const (
	defaultIntegrationDeadlineMS      = 2500
	minIntegrationDeadlineMS          = 500
	maxIntegrationDeadlineMS          = 10000
	defaultIntegrationMaxBodyBytes    = 10 * 1024 * 1024
	minIntegrationMaxBodyBytes        = 1024
	maxIntegrationMaxBodyBytes        = 10 * 1024 * 1024
	defaultIntegrationTokenMaxAgeDays = 90
	minIntegrationTokenMaxAgeDays     = 1
	maxIntegrationTokenMaxAgeDays     = 365
	minIntegrationRouteTokenLength    = 43
)

type integrationRoute struct {
	RouteID                string `json:"route_id"`
	OwnerUID               string `json:"owner_uid"`
	DeviceID               string `json:"device_id"`
	InterfaceID            string `json:"interface_id,omitempty"`
	InterfaceType          string `json:"interface_type"`
	TokenAuthMode          string `json:"token_auth_mode"`
	Status                 string `json:"status"`
	DeadlineMs             int    `json:"deadline_ms"`
	MaxBodyBytes           int    `json:"max_body_bytes"`
	TokenMaxAgeDays        int    `json:"token_max_age_days"`
	TokenExpiresAt         string `json:"token_expires_at"`
	TokenLastUsedAt        string `json:"token_last_used_at,omitempty"`
	CreatedAt              string `json:"created_at"`
	UpdatedAt              string `json:"updated_at"`
	Version                int64  `json:"-"`
	TokenCurrentHash       string
	TokenPreviousHash      string
	TokenPreviousExpiresAt string
}

func integrationErrorResponse(code, message string, details map[string]string) fiber.Map {
	errMap := fiber.Map{
		"code":    code,
		"message": message,
	}
	if len(details) > 0 {
		errMap["details"] = details
	}
	return fiber.Map{"error": errMap}
}

func integrationPublicURL(baseURL, routeID, token string) string {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" {
		base = "http://localhost:8080"
	}
	return fmt.Sprintf("%s/integrations/%s/%s", base, routeID, token)
}

func integrationRouteResponse(route integrationRoute) fiber.Map {
	return fiber.Map{
		"route_id":           route.RouteID,
		"interface_id":       route.InterfaceID,
		"interface_type":     route.InterfaceType,
		"token_auth_mode":    route.TokenAuthMode,
		"status":             route.Status,
		"deadline_ms":        route.DeadlineMs,
		"max_body_bytes":     route.MaxBodyBytes,
		"token_max_age_days": route.TokenMaxAgeDays,
		"token_expires_at":   route.TokenExpiresAt,
		"token_last_used_at": route.TokenLastUsedAt,
		"created_at":         route.CreatedAt,
		"updated_at":         route.UpdatedAt,
	}
}

func constantTimeRouteTokenMatch(route *integrationRoute, candidateToken string, now time.Time) bool {
	if route == nil || strings.TrimSpace(candidateToken) == "" {
		return false
	}
	candidateHash := hashRouteToken(candidateToken)
	if route.TokenCurrentHash != "" && subtle.ConstantTimeCompare([]byte(candidateHash), []byte(route.TokenCurrentHash)) == 1 {
		return true
	}
	if route.TokenPreviousHash != "" && route.TokenPreviousExpiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339, route.TokenPreviousExpiresAt)
		if err == nil && now.Before(expiresAt) {
			if subtle.ConstantTimeCompare([]byte(candidateHash), []byte(route.TokenPreviousHash)) == 1 {
				return true
			}
		}
	}
	return false
}

func (h *Handler) CreateIntegrationRoute(c fiber.Ctx) error {
	principal := auth.PrincipalFromContext(c)
	if principal == nil || strings.TrimSpace(principal.UID) == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(integrationErrorResponse("unauthorized", "Authentication required", nil))
	}

	var req struct {
		InterfaceType   string `json:"interface_type"`
		TokenAuthMode   string `json:"token_auth_mode"`
		RouteToken      string `json:"route_token"`
		DeadlineMs      *int   `json:"deadline_ms"`
		MaxBodyBytes    *int   `json:"max_body_bytes"`
		TokenMaxAgeDays *int   `json:"token_max_age_days"`
		InterfaceID     string `json:"interface_id"`
		DeviceID        string `json:"device_id"`
	}
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(integrationErrorResponse("invalid_request", "Invalid request body", nil))
	}

	deviceID := strings.TrimSpace(req.DeviceID)
	if deviceID == "" {
		deviceID = strings.TrimSpace(c.Get("X-Device-Id"))
	}
	if deviceID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(integrationErrorResponse("invalid_request", "device_id is required", nil))
	}
	var err error
	deviceID, err = validateID(deviceID, "device_id")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(integrationErrorResponse("invalid_request", "Invalid device_id format", nil))
	}

	device, found, err := h.store.GetDevice(context.Background(), deviceID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(integrationErrorResponse("internal_error", "Failed to load device", nil))
	}
	if !found {
		return c.Status(fiber.StatusBadRequest).JSON(integrationErrorResponse("invalid_request", "Device not found; register the device before creating a route", nil))
	}
	if device.OwnerUID != principal.UID {
		return c.Status(fiber.StatusForbidden).JSON(integrationErrorResponse("forbidden", "You do not own this device", nil))
	}

	req.InterfaceType = strings.TrimSpace(req.InterfaceType)
	if !interfaceTypePattern.MatchString(req.InterfaceType) {
		return c.Status(fiber.StatusBadRequest).JSON(integrationErrorResponse("invalid_request", "interface_type must match ^[a-z][a-z0-9_]{0,31}$", nil))
	}

	req.TokenAuthMode = strings.TrimSpace(req.TokenAuthMode)
	if req.TokenAuthMode == "" {
		req.TokenAuthMode = "path"
	}
	if req.TokenAuthMode != "path" {
		return c.Status(fiber.StatusBadRequest).JSON(integrationErrorResponse("invalid_request", "token_auth_mode must be 'path'", nil))
	}

	deadlineMS := defaultIntegrationDeadlineMS
	if req.DeadlineMs != nil {
		deadlineMS = *req.DeadlineMs
		if deadlineMS < minIntegrationDeadlineMS || deadlineMS > maxIntegrationDeadlineMS {
			return c.Status(fiber.StatusBadRequest).JSON(integrationErrorResponse("invalid_request", fmt.Sprintf("deadline_ms must be between %d and %d", minIntegrationDeadlineMS, maxIntegrationDeadlineMS), nil))
		}
	}

	maxBodyBytes := defaultIntegrationMaxBodyBytes
	if req.MaxBodyBytes != nil {
		maxBodyBytes = *req.MaxBodyBytes
		if maxBodyBytes < minIntegrationMaxBodyBytes || maxBodyBytes > maxIntegrationMaxBodyBytes {
			return c.Status(fiber.StatusBadRequest).JSON(integrationErrorResponse("invalid_request", fmt.Sprintf("max_body_bytes must be between %d and %d", minIntegrationMaxBodyBytes, maxIntegrationMaxBodyBytes), nil))
		}
	}

	tokenMaxAgeDays := defaultIntegrationTokenMaxAgeDays
	if req.TokenMaxAgeDays != nil {
		tokenMaxAgeDays = *req.TokenMaxAgeDays
		if tokenMaxAgeDays < minIntegrationTokenMaxAgeDays || tokenMaxAgeDays > maxIntegrationTokenMaxAgeDays {
			return c.Status(fiber.StatusBadRequest).JSON(integrationErrorResponse("invalid_request", fmt.Sprintf("token_max_age_days must be between %d and %d", minIntegrationTokenMaxAgeDays, maxIntegrationTokenMaxAgeDays), nil))
		}
	}

	plainToken := strings.TrimSpace(req.RouteToken)
	if plainToken != "" {
		if len(plainToken) < minIntegrationRouteTokenLength {
			return c.Status(fiber.StatusUnprocessableEntity).JSON(integrationErrorResponse("token_validation_failed", fmt.Sprintf("route_token must be at least %d characters", minIntegrationRouteTokenLength), nil))
		}
		if !routeTokenCharset.MatchString(plainToken) {
			return c.Status(fiber.StatusUnprocessableEntity).JSON(integrationErrorResponse("token_validation_failed", "route_token must contain only [A-Za-z0-9_-]", nil))
		}
	} else {
		plainToken, err = generateRouteToken()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(integrationErrorResponse("internal_error", "Failed to generate token", nil))
		}
	}

	routeID, err := generateRouteID()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(integrationErrorResponse("internal_error", "Failed to generate route ID", nil))
	}

	now := time.Now().UTC()
	route := &integrationRoute{
		RouteID:          routeID,
		OwnerUID:         principal.UID,
		DeviceID:         deviceID,
		InterfaceID:      strings.TrimSpace(req.InterfaceID),
		InterfaceType:    req.InterfaceType,
		TokenAuthMode:    req.TokenAuthMode,
		Status:           "provisioned",
		DeadlineMs:       deadlineMS,
		MaxBodyBytes:     maxBodyBytes,
		TokenMaxAgeDays:  tokenMaxAgeDays,
		TokenExpiresAt:   now.AddDate(0, 0, tokenMaxAgeDays).Format(time.RFC3339),
		CreatedAt:        now.Format(time.RFC3339),
		UpdatedAt:        now.Format(time.RFC3339),
		TokenCurrentHash: hashRouteToken(plainToken),
	}

	if err := h.store.SaveIntegrationRoute(context.Background(), route); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(integrationErrorResponse("internal_error", "Failed to save route", nil))
	}

	publicURL := integrationPublicURL(h.cfg.PublicBaseURL, routeID, plainToken)
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"route":       integrationRouteResponse(*route),
		"public_url":  publicURL,
		"route_token": plainToken,
	})
}

func (h *Handler) UpdateIntegrationRoute(c fiber.Ctx) error {
	principal := auth.PrincipalFromContext(c)
	if principal == nil || strings.TrimSpace(principal.UID) == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(integrationErrorResponse("unauthorized", "Authentication required", nil))
	}

	routeID := strings.TrimSpace(c.Params("route_id"))
	if routeID == "" || !routeIDPattern.MatchString(routeID) {
		return c.Status(fiber.StatusBadRequest).JSON(integrationErrorResponse("invalid_request", "route_id is required", nil))
	}

	var req struct {
		DeadlineMs    *int   `json:"deadline_ms"`
		MaxBodyBytes  *int   `json:"max_body_bytes"`
		TokenAuthMode string `json:"token_auth_mode"`
		Status        string `json:"status"`
		DeviceID      string `json:"device_id"`
	}
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(integrationErrorResponse("invalid_request", "Invalid request body", nil))
	}

	validatedDeviceID := ""
	if strings.TrimSpace(req.DeviceID) != "" {
		deviceID, err := validateID(strings.TrimSpace(req.DeviceID), "device_id")
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(integrationErrorResponse("invalid_request", "Invalid device_id format", nil))
		}
		device, found, err := h.store.GetDevice(context.Background(), deviceID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(integrationErrorResponse("internal_error", "Failed to load device", nil))
		}
		if !found {
			return c.Status(fiber.StatusBadRequest).JSON(integrationErrorResponse("invalid_request", "Device not found; register the device before binding it to a route", nil))
		}
		if device.OwnerUID != principal.UID {
			return c.Status(fiber.StatusForbidden).JSON(integrationErrorResponse("forbidden", "You do not own this device", nil))
		}
		validatedDeviceID = deviceID
	}

	// Pre-flight: read the route to validate ownership and request fields before
	// the atomic update. This avoids performing side-effects (tunnel deactivation)
	// inside the mutator.
	route, found, err := h.store.GetIntegrationRoute(context.Background(), routeID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(integrationErrorResponse("internal_error", "Failed to load route", nil))
	}
	if !found {
		return c.Status(fiber.StatusNotFound).JSON(integrationErrorResponse("route_not_found", "Route not found", nil))
	}
	if route.OwnerUID != principal.UID {
		return c.Status(fiber.StatusForbidden).JSON(integrationErrorResponse("forbidden", "You do not own this route", nil))
	}

	// Validate request fields before mutating
	if req.DeadlineMs != nil {
		if *req.DeadlineMs < minIntegrationDeadlineMS || *req.DeadlineMs > maxIntegrationDeadlineMS {
			return c.Status(fiber.StatusBadRequest).JSON(integrationErrorResponse("invalid_request", fmt.Sprintf("deadline_ms must be between %d and %d", minIntegrationDeadlineMS, maxIntegrationDeadlineMS), nil))
		}
	}
	if req.MaxBodyBytes != nil {
		if *req.MaxBodyBytes < minIntegrationMaxBodyBytes || *req.MaxBodyBytes > maxIntegrationMaxBodyBytes {
			return c.Status(fiber.StatusBadRequest).JSON(integrationErrorResponse("invalid_request", fmt.Sprintf("max_body_bytes must be between %d and %d", minIntegrationMaxBodyBytes, maxIntegrationMaxBodyBytes), nil))
		}
	}
	if strings.TrimSpace(req.TokenAuthMode) != "" {
		if strings.TrimSpace(req.TokenAuthMode) != "path" {
			return c.Status(fiber.StatusBadRequest).JSON(integrationErrorResponse("invalid_request", "token_auth_mode must be 'path'", nil))
		}
	}
	if strings.TrimSpace(req.Status) != "" {
		status := strings.TrimSpace(req.Status)
		switch status {
		case "provisioned", "inactive":
			// valid
		case "active":
			return c.Status(fiber.StatusBadRequest).JSON(integrationErrorResponse("invalid_route_update", "'active' status is set via tunnel activation, not REST API", nil))
		default:
			return c.Status(fiber.StatusBadRequest).JSON(integrationErrorResponse("invalid_route_update", "status must be 'provisioned' or 'inactive'", nil))
		}
	}
	requestedStatus := strings.TrimSpace(req.Status)
	needsDeactivation := (requestedStatus == "provisioned" || requestedStatus == "inactive") || (validatedDeviceID != "" && validatedDeviceID != route.DeviceID)

	now := time.Now().UTC().Format(time.RFC3339)

	// Atomic update with version check
	updated, err := h.store.UpdateIntegrationRoute(context.Background(), routeID, func(r *integrationRoute) error {
		if r.OwnerUID != principal.UID {
			return fmt.Errorf("forbidden")
		}
		if req.DeadlineMs != nil {
			r.DeadlineMs = *req.DeadlineMs
		}
		if req.MaxBodyBytes != nil {
			r.MaxBodyBytes = *req.MaxBodyBytes
		}
		if strings.TrimSpace(req.TokenAuthMode) != "" {
			r.TokenAuthMode = "path"
		}
		if requestedStatus != "" {
			r.Status = requestedStatus
		}
		if validatedDeviceID != "" && validatedDeviceID != r.DeviceID {
			if r.Status == "active" {
				r.Status = "provisioned"
			}
			r.DeviceID = validatedDeviceID
		} else if validatedDeviceID != "" {
			r.DeviceID = validatedDeviceID
		}
		r.UpdatedAt = now
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrRouteNotFound):
			return c.Status(fiber.StatusNotFound).JSON(integrationErrorResponse("route_not_found", "Route not found", nil))
		case errors.Is(err, ErrRouteVersionConflict):
			return c.Status(fiber.StatusConflict).JSON(integrationErrorResponse("version_conflict", "Route was modified concurrently; please retry", nil))
		case err.Error() == "forbidden":
			return c.Status(fiber.StatusForbidden).JSON(integrationErrorResponse("forbidden", "You do not own this route", nil))
		default:
			return c.Status(fiber.StatusInternalServerError).JSON(integrationErrorResponse("internal_error", "Failed to save route", nil))
		}
	}

	var deactivatedTunnel *tunnelConn
	if needsDeactivation {
		if activeDeviceID, active, _ := h.store.GetActiveRouteDevice(context.Background(), routeID); active {
			_ = h.store.DeleteActiveRoute(context.Background(), routeID)
			_ = h.store.ReleaseRouteLease(context.Background(), routeID, h.nodeID)
			h.mu.Lock()
			if tc, ok := h.tunnelConns[activeDeviceID]; ok {
				delete(tc.activatedRoutes, routeID)
				deactivatedTunnel = tc
			}
			h.mu.Unlock()
			if deactivatedTunnel != nil {
				h.stopRouteBusSubscription(deactivatedTunnel, routeID)
			}
		}
	}

	if deactivatedTunnel != nil {
		_ = deactivatedTunnel.writeJSON(map[string]any{
			"type":     "tunnel.route_deactivated",
			"route_id": routeID,
			"reason":   "route_updated",
			"at":       now,
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"route": integrationRouteResponse(*updated)})
}

func (h *Handler) DeleteIntegrationRoute(c fiber.Ctx) error {
	principal := auth.PrincipalFromContext(c)
	if principal == nil || strings.TrimSpace(principal.UID) == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(integrationErrorResponse("unauthorized", "Authentication required", nil))
	}

	routeID := strings.TrimSpace(c.Params("route_id"))
	if routeID == "" || !routeIDPattern.MatchString(routeID) {
		return c.Status(fiber.StatusBadRequest).JSON(integrationErrorResponse("invalid_request", "route_id is required", nil))
	}

	now := time.Now().UTC().Format(time.RFC3339)
	var deactivatedTunnel *tunnelConn
	route, found, err := h.store.GetIntegrationRoute(context.Background(), routeID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(integrationErrorResponse("internal_error", "Failed to load route", nil))
	}
	if !found {
		return c.Status(fiber.StatusNotFound).JSON(integrationErrorResponse("route_not_found", "Route not found", nil))
	}
	if route.OwnerUID != principal.UID {
		return c.Status(fiber.StatusForbidden).JSON(integrationErrorResponse("forbidden", "You do not own this route", nil))
	}

	if activeDeviceID, active, _ := h.store.GetActiveRouteDevice(context.Background(), routeID); active {
		_ = h.store.DeleteActiveRoute(context.Background(), routeID)
		_ = h.store.ReleaseRouteLease(context.Background(), routeID, h.nodeID)
		h.mu.Lock()
		if tc, ok := h.tunnelConns[activeDeviceID]; ok {
			delete(tc.activatedRoutes, routeID)
			deactivatedTunnel = tc
		}
		h.mu.Unlock()
		if deactivatedTunnel != nil {
			h.stopRouteBusSubscription(deactivatedTunnel, routeID)
		}
	}
	if err := h.store.DeleteIntegrationRoute(context.Background(), routeID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(integrationErrorResponse("internal_error", "Failed to delete route", nil))
	}

	if deactivatedTunnel != nil {
		_ = deactivatedTunnel.writeJSON(map[string]any{
			"type":     "tunnel.route_deactivated",
			"route_id": routeID,
			"reason":   "revoked",
			"at":       now,
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"ok":         true,
		"route_id":   routeID,
		"revoked_at": now,
	})
}

func (h *Handler) ListIntegrationRoutes(c fiber.Ctx) error {
	principal := auth.PrincipalFromContext(c)
	if principal == nil || strings.TrimSpace(principal.UID) == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(integrationErrorResponse("unauthorized", "Authentication required", nil))
	}

	interfaceType := strings.TrimSpace(c.Query("interface_type"))
	status := strings.TrimSpace(c.Query("status"))

	ownerRoutes, err := h.store.ListIntegrationRoutesByOwner(context.Background(), principal.UID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(integrationErrorResponse("internal_error", "Failed to list routes", nil))
	}
	routes := make([]integrationRoute, 0, len(ownerRoutes))
	for _, route := range ownerRoutes {
		if route == nil {
			continue
		}
		routes = append(routes, *route)
	}

	sort.Slice(routes, func(i, j int) bool {
		return routes[i].CreatedAt > routes[j].CreatedAt
	})

	out := make([]fiber.Map, 0, len(routes))
	for _, route := range routes {
		if interfaceType != "" && route.InterfaceType != interfaceType {
			continue
		}
		if status != "" && route.Status != status {
			continue
		}
		out = append(out, integrationRouteResponse(route))
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"routes": out})
}

func (h *Handler) RotateIntegrationRouteToken(c fiber.Ctx) error {
	principal := auth.PrincipalFromContext(c)
	if principal == nil || strings.TrimSpace(principal.UID) == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(integrationErrorResponse("unauthorized", "Authentication required", nil))
	}

	routeID := strings.TrimSpace(c.Params("route_id"))
	if routeID == "" || !routeIDPattern.MatchString(routeID) {
		return c.Status(fiber.StatusBadRequest).JSON(integrationErrorResponse("invalid_request", "route_id is required", nil))
	}

	var req struct {
		GraceSeconds *int `json:"grace_seconds"`
	}
	_ = c.Bind().Body(&req)

	graceSeconds := 300
	if req.GraceSeconds != nil {
		graceSeconds = *req.GraceSeconds
		if graceSeconds < 0 || graceSeconds > 1800 {
			return c.Status(fiber.StatusBadRequest).JSON(integrationErrorResponse("invalid_request", "grace_seconds must be between 0 and 1800", nil))
		}
	}

	newPlainToken, err := generateRouteToken()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(integrationErrorResponse("internal_error", "Failed to generate token", nil))
	}
	newHash := hashRouteToken(newPlainToken)

	// Pre-flight ownership check
	route, found, err := h.store.GetIntegrationRoute(context.Background(), routeID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(integrationErrorResponse("internal_error", "Failed to load route", nil))
	}
	if !found {
		return c.Status(fiber.StatusNotFound).JSON(integrationErrorResponse("route_not_found", "Route not found", nil))
	}
	if route.OwnerUID != principal.UID {
		return c.Status(fiber.StatusForbidden).JSON(integrationErrorResponse("forbidden", "You do not own this route", nil))
	}

	now := time.Now().UTC()
	updated, err := h.store.UpdateIntegrationRoute(context.Background(), routeID, func(r *integrationRoute) error {
		if r.OwnerUID != principal.UID {
			return fmt.Errorf("forbidden")
		}
		if r.TokenCurrentHash != "" && graceSeconds > 0 {
			r.TokenPreviousHash = r.TokenCurrentHash
			r.TokenPreviousExpiresAt = now.Add(time.Duration(graceSeconds) * time.Second).Format(time.RFC3339)
		} else {
			r.TokenPreviousHash = ""
			r.TokenPreviousExpiresAt = ""
		}
		r.TokenCurrentHash = newHash
		r.TokenExpiresAt = now.AddDate(0, 0, r.TokenMaxAgeDays).Format(time.RFC3339)
		r.UpdatedAt = now.Format(time.RFC3339)
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrRouteNotFound):
			return c.Status(fiber.StatusNotFound).JSON(integrationErrorResponse("route_not_found", "Route not found", nil))
		case errors.Is(err, ErrRouteVersionConflict):
			return c.Status(fiber.StatusConflict).JSON(integrationErrorResponse("version_conflict", "Route was modified concurrently; please retry", nil))
		case err.Error() == "forbidden":
			return c.Status(fiber.StatusForbidden).JSON(integrationErrorResponse("forbidden", "You do not own this route", nil))
		default:
			return c.Status(fiber.StatusInternalServerError).JSON(integrationErrorResponse("internal_error", "Failed to save route", nil))
		}
	}

	resp := fiber.Map{
		"route_id":         routeID,
		"public_url":       integrationPublicURL(h.cfg.PublicBaseURL, routeID, newPlainToken),
		"route_token":      newPlainToken,
		"token_expires_at": updated.TokenExpiresAt,
	}
	if updated.TokenPreviousExpiresAt != "" {
		resp["previous_token_expires_at"] = updated.TokenPreviousExpiresAt
	}
	return c.Status(fiber.StatusOK).JSON(resp)
}
