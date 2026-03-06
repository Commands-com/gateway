package gateway

import (
	"bufio"
	"context"
	"encoding/json"
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
	rec, exists, err := h.store.GetDevice(context.Background(), deviceID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to read device"})
	}
	if exists && !h.ownerMatchesPrincipal(rec.OwnerUID, rec.OwnerEmail, principal.UID, principal.Email) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "you do not own this device"})
	}
	// Enforce per-owner device registration limit for new devices
	if !exists {
		ownerDeviceCount, countErr := h.store.CountDevicesByOwner(context.Background(), principal.UID)
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
	if err := h.store.SaveDevice(context.Background(), rec); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to save device"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *Handler) ListDevices(c fiber.Ctx) error {
	principal := auth.PrincipalFromContext(c)
	if principal == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}

	devices, err := h.listVisibleDeviceSummaries(principal.UID, principal.Email)
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

	return c.SendStreamWriter(func(w *bufio.Writer) {
		if err := writeSSEComment(w, "connected"); err != nil {
			return
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

		initial, err := h.listVisibleDeviceSummaries(principal.UID, principal.Email)
		if err != nil {
			return
		}
		if err := sendSnapshot(initial); err != nil {
			return
		}

		heartbeat := time.NewTicker(15 * time.Second)
		defer heartbeat.Stop()

		for {
			<-heartbeat.C
			if err := writeSSEComment(w, "heartbeat"); err != nil {
				return
			}
			next, err := h.listVisibleDeviceSummaries(principal.UID, principal.Email)
			if err != nil {
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

	rec, found, err := h.store.GetDevice(context.Background(), deviceID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to read device"})
	}
	if !found {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "device not found"})
	}
	if !h.canAccessDeviceForPrincipal(principal.UID, principal.Email, deviceID) {
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

func (h *Handler) canAccessDevice(uid, deviceID string) bool {
	return h.canAccessDeviceForPrincipal(uid, "", deviceID)
}

func (h *Handler) canAccessDeviceForPrincipal(uid, email, deviceID string) bool {
	device, found, err := h.store.GetDevice(context.Background(), deviceID)
	if err != nil || !found {
		return false
	}
	if h.ownerMatchesPrincipal(device.OwnerUID, device.OwnerEmail, uid, email) {
		return true
	}
	now := time.Now().UTC().Unix()
	return h.hasActiveGrant(deviceID, uid, now)
}

func (h *Handler) listVisibleDeviceSummaries(uid, email string) ([]listedDeviceSummary, error) {
	now := time.Now().UTC().Unix()
	records, err := h.store.ListDevices(context.Background())
	if err != nil {
		return nil, err
	}

	out := make([]listedDeviceSummary, 0, len(records))
	for _, rec := range records {
		role := ""
		if h.ownerMatchesPrincipal(rec.OwnerUID, rec.OwnerEmail, uid, email) {
			role = "owner"
		} else if h.hasActiveGrant(rec.DeviceID, uid, now) {
			role = "collaborator"
		} else {
			continue
		}

		connected, connectedAt, lastSeenAt := h.deviceConnectionState(rec.DeviceID)
		status := "offline"
		if connected {
			status = "online"
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

func (h *Handler) deviceConnectionState(deviceID string) (connected bool, connectedAt string, lastSeenAt string) {
	h.mu.RLock()
	conn, ok := h.agents[deviceID]
	h.mu.RUnlock()
	if !ok || conn == nil {
		return false, "", ""
	}
	connected = true
	if !conn.connectedAt.IsZero() {
		connectedAt = conn.connectedAt.UTC().Format(time.RFC3339)
	}
	if !conn.lastSeenAt.IsZero() {
		lastSeenAt = conn.lastSeenAt.UTC().Format(time.RFC3339)
	}
	return connected, connectedAt, lastSeenAt
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
