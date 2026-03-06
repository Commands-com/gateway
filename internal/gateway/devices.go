package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"

	"oss-commands-gateway/internal/auth"
	"oss-commands-gateway/internal/config"
	"oss-commands-gateway/internal/gatewaycrypto"
)

const maxDevicesPerOwner = 200

type listedDeviceSummary struct {
	DeviceID    string `json:"device_id"`
	DisplayName string `json:"display_name,omitempty"`
	Name        string `json:"name,omitempty"`
	OwnerUID    string `json:"owner_uid,omitempty"`
	OwnerEmail  string `json:"owner_email,omitempty"`
	Algorithm   string `json:"algorithm"`
	Status      string `json:"status"`
	Connected   bool   `json:"connected"`
	UpdatedAt   string `json:"updated_at"`
	ConnectedAt string `json:"connected_at,omitempty"`
	LastSeenAt  string `json:"last_seen_at,omitempty"`
	DeviceClass string `json:"device_class,omitempty"`
	Role        string `json:"role,omitempty"`
}

func (h *Handler) PutDeviceIdentityKey(c fiber.Ctx) error {
	principal := auth.PrincipalFromContext(c)
	if principal == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	deviceID, err := validateID(c.Params("device_id"), "device_id")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	var req putDeviceIdentityKeyRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}

	if strings.TrimSpace(req.Algorithm) == "" {
		req.Algorithm = "ed25519"
	}
	if req.Algorithm != "ed25519" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "unsupported algorithm"})
	}

	publicKey := strings.TrimSpace(req.PublicKey)
	if publicKey == "" {
		publicKey = strings.TrimSpace(req.LegacyPublicKey)
	}
	if publicKey == "" {
		publicKey = strings.TrimSpace(req.SnakePublicKey)
	}
	if err := gatewaycrypto.ValidateEd25519PublicKey(publicKey); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid public key"})
	}
	now := time.Now().UTC().Unix()
	rec, exists, err := h.store.GetDevice(c.Context(), deviceID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to read device"})
	}
	if exists && !h.ownerMatchesPrincipal(rec.OwnerUID, rec.OwnerEmail, principal.UID, principal.Email) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "you do not own this device"})
	}
	// Enforce per-owner device registration limit for new devices
	if !exists {
		ownerDeviceCount, countErr := h.store.CountDevicesByOwner(c.Context(), principal.UID)
		if countErr != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to count devices"})
		}
		if ownerDeviceCount >= maxDevicesPerOwner {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{"error": "too many registered devices"})
		}
	}
	rec.DeviceID = deviceID
	rec.OwnerUID = principal.UID
	rec.OwnerEmail = canonicalEmail(principal.Email)
	if displayName := strings.TrimSpace(req.DisplayName); displayName != "" {
		rec.DisplayName = displayName
	}
	rec.IdentityKey = publicKey
	rec.UpdatedAt = now
	if err := h.store.SaveDevice(c.Context(), rec); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to save device"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *Handler) ListDevices(c fiber.Ctx) error {
	principal := auth.PrincipalFromContext(c)
	if principal == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}

	devices, err := h.listVisibleDeviceSummaries(c.Context(), principal.UID, principal.Email)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list devices"})
	}
	return c.JSON(fiber.Map{"devices": devices})
}

func (h *Handler) GetDeviceEvents(c fiber.Ctx) error {
	principal := auth.PrincipalFromContext(c)
	if principal == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}

	c.Set(fiber.HeaderContentType, "text/event-stream")
	c.Set(fiber.HeaderCacheControl, "no-cache")
	c.Set(fiber.HeaderConnection, "keep-alive")
	c.Set("X-Accel-Buffering", "no")

	ctx := c.Context()
	return c.SendStreamWriter(func(w *bufio.Writer) {
		if err := writeSSEComment(w, "connected"); err != nil {
			return
		}

		// Subscribe to bus device events for cross-node wakeups.
		busCh := make(chan struct{}, 1)
		busCtx, busCancel := context.WithCancel(context.Background())
		defer busCancel()
		unsubBus, err := h.bus.SubscribeDeviceEvents(busCtx, busCh)
		if err != nil {
			slog.Warn("device-events: failed to subscribe to bus", "err", err)
		} else {
			defer unsubBus()
		}

		last := make(map[string]string)
		sendSnapshot := func(items []listedDeviceSummary) error {
			seen := make(map[string]struct{}, len(items))
			for _, item := range items {
				seen[item.DeviceID] = struct{}{}
				next := item.Status
				if prev, ok := last[item.DeviceID]; ok && prev == next {
					continue
				}
				if err := writeDeviceStatusEvent(w, item.DeviceID, next, item.LastSeenAt); err != nil {
					return err
				}
				last[item.DeviceID] = next
			}
			for deviceID := range last {
				if _, ok := seen[deviceID]; ok {
					continue
				}
				if err := writeDeviceStatusEvent(w, deviceID, "offline", time.Now().UTC().Format(time.RFC3339)); err != nil {
					return err
				}
				delete(last, deviceID)
			}
			return nil
		}

		initial, listErr := h.listVisibleDeviceSummaries(ctx, principal.UID, principal.Email)
		if listErr != nil {
			return
		}
		if err := sendSnapshot(initial); err != nil {
			return
		}

		heartbeat := time.NewTicker(30 * time.Second)
		defer heartbeat.Stop()

		for {
			// Grab the current notification channel under read lock.
			h.mu.RLock()
			notify := h.deviceStateNotify
			h.mu.RUnlock()

			select {
			case <-notify:
				// Local agent connected or disconnected.
			case <-busCh:
				// Remote node device state change.
			case <-heartbeat.C:
			case <-h.done:
				return
			}
			if err := writeSSEComment(w, "heartbeat"); err != nil {
				return
			}
			next, listErr := h.listVisibleDeviceSummaries(ctx, principal.UID, principal.Email)
			if listErr != nil {
				return
			}
			if err := sendSnapshot(next); err != nil {
				return
			}
		}
	})
}

func (h *Handler) GetDeviceIdentityKey(c fiber.Ctx) error {
	principal := auth.PrincipalFromContext(c)
	if principal == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	deviceID, err := validateID(c.Params("device_id"), "device_id")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	rec, found, err := h.store.GetDevice(c.Context(), deviceID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to read device"})
	}
	if !found {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "device not found"})
	}
	if !h.canAccessDeviceForPrincipal(c.Context(), principal.UID, principal.Email, deviceID) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
	}
	if strings.TrimSpace(rec.IdentityKey) == "" {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "device identity not found"})
	}

	return c.JSON(fiber.Map{
		"algorithm":  "ed25519",
		"public_key": rec.IdentityKey,
		"updated_at": time.Unix(rec.UpdatedAt, 0).UTC().Format(time.RFC3339),
	})
}

func (h *Handler) canAccessDevice(ctx context.Context, uid, deviceID string) bool {
	return h.canAccessDeviceForPrincipal(ctx, uid, "", deviceID)
}

func (h *Handler) canAccessDeviceForPrincipal(ctx context.Context, uid, email, deviceID string) bool {
	device, found, err := h.store.GetDevice(ctx, deviceID)
	if err != nil || !found {
		return false
	}
	if h.ownerMatchesPrincipal(device.OwnerUID, device.OwnerEmail, uid, email) {
		return true
	}
	now := time.Now().UTC().Unix()
	return h.hasActiveGrant(ctx, deviceID, uid, now)
}

func (h *Handler) listVisibleDeviceSummaries(ctx context.Context, uid, email string) ([]listedDeviceSummary, error) {
	now := time.Now().UTC().Unix()

	// Collect owned devices via index
	ownedRecords, err := h.store.ListDevicesByOwner(ctx, uid)
	if err != nil {
		return nil, err
	}

	// Collect granted device IDs via grantee index
	granteeGrants, err := h.store.ListShareGrantsByGranteeUID(ctx, uid)
	if err != nil {
		return nil, err
	}
	grantedDeviceIDs := make(map[string]struct{})
	for _, grant := range granteeGrants {
		if grant == nil {
			continue
		}
		if effectiveGrantStatus(grant, now) == "active" {
			grantedDeviceIDs[grant.DeviceID] = struct{}{}
		}
	}

	// Build deduplicated record list with roles
	type deviceWithRole struct {
		rec  deviceRecord
		role string
	}
	seen := make(map[string]struct{}, len(ownedRecords)+len(grantedDeviceIDs))
	candidates := make([]deviceWithRole, 0, len(ownedRecords)+len(grantedDeviceIDs))
	for _, rec := range ownedRecords {
		seen[rec.DeviceID] = struct{}{}
		candidates = append(candidates, deviceWithRole{rec: rec, role: "owner"})
	}
	for deviceID := range grantedDeviceIDs {
		if _, already := seen[deviceID]; already {
			continue
		}
		rec, found, err := h.store.GetDevice(ctx, deviceID)
		if err != nil || !found {
			continue
		}
		candidates = append(candidates, deviceWithRole{rec: rec, role: "collaborator"})
	}

	out := make([]listedDeviceSummary, 0, len(candidates))
	for _, c := range candidates {
		rec := c.rec
		role := c.role

		status := "offline"
		connected := rec.Connected &&
			(rec.PresenceExpiresAt == 0 || time.Now().UTC().Unix() <= rec.PresenceExpiresAt)
		connectedAt := ""
		lastSeenAt := ""
		if connected {
			status = "online"
			if rec.ConnectedAt > 0 {
				connectedAt = time.Unix(rec.ConnectedAt, 0).UTC().Format(time.RFC3339)
			}
			if rec.LastSeenAt > 0 {
				lastSeenAt = time.Unix(rec.LastSeenAt, 0).UTC().Format(time.RFC3339)
			}
		}

		updatedAt := rec.UpdatedAt
		if updatedAt <= 0 {
			updatedAt = now
		}
		displayName := strings.TrimSpace(rec.DisplayName)
		if displayName == "" {
			displayName = rec.DeviceID
		}
		summary := listedDeviceSummary{
			DeviceID:    rec.DeviceID,
			DisplayName: displayName,
			Name:        displayName,
			OwnerUID:    rec.OwnerUID,
			OwnerEmail:  rec.OwnerEmail,
			Algorithm:   "ed25519",
			Status:      status,
			Connected:   connected,
			UpdatedAt:   time.Unix(updatedAt, 0).UTC().Format(time.RFC3339),
			ConnectedAt: connectedAt,
			LastSeenAt:  lastSeenAt,
			DeviceClass: "agent",
			Role:        role,
		}
		out = append(out, summary)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Connected != out[j].Connected {
			return out[i].Connected
		}
		if out[i].UpdatedAt != out[j].UpdatedAt {
			return out[i].UpdatedAt > out[j].UpdatedAt
		}
		return out[i].DeviceID < out[j].DeviceID
	})

	return out, nil
}

func (h *Handler) ownerMatchesPrincipal(ownerUID, ownerEmail, principalUID, principalEmail string) bool {
	if strings.TrimSpace(ownerUID) != "" && strings.TrimSpace(principalUID) != "" && strings.TrimSpace(ownerUID) == strings.TrimSpace(principalUID) {
		return true
	}
	if h == nil || h.cfg == nil {
		return false
	}
	// Email-based ownership fallback is intentionally restricted to demo mode.
	// In real IdP-backed modes (firebase/oidc), subject/UID must remain authoritative.
	if h.cfg.AuthMode != "" && h.cfg.AuthMode != config.AuthModeDemo {
		return false
	}
	return canonicalEmail(ownerEmail) != "" && canonicalEmail(ownerEmail) == canonicalEmail(principalEmail)
}

func writeDeviceStatusEvent(w *bufio.Writer, deviceID, status, at string) error {
	payload, err := json.Marshal(fiber.Map{
		"deviceId": deviceID,
		"status":   status,
		"at":       at,
	})
	if err != nil {
		return err
	}
	if _, err := w.WriteString("event: device.status\n"); err != nil {
		return err
	}
	if _, err := w.WriteString("data: " + string(payload) + "\n\n"); err != nil {
		return err
	}
	return w.Flush()
}
