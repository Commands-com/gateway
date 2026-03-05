package gateway

import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"

	"oss-commands-gateway/internal/auth"
	"oss-commands-gateway/internal/gatewaycrypto"
)

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
	_ = c.Bind().Body(&req)
	if strings.TrimSpace(req.IdentityKey) != "" {
		if err := gatewaycrypto.ValidateEd25519PublicKey(strings.TrimSpace(req.IdentityKey)); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid identity key"})
		}
	}
	now := time.Now().UTC().Unix()

	h.mu.Lock()
	defer h.mu.Unlock()

	rec, exists := h.devices[deviceID]
	if exists && rec.OwnerUID != "" && rec.OwnerUID != principal.UID {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "you do not own this device"})
	}
	rec.DeviceID = deviceID
	rec.OwnerUID = principal.UID
	rec.OwnerEmail = canonicalEmail(principal.Email)
	if strings.TrimSpace(req.IdentityKey) != "" {
		rec.IdentityKey = strings.TrimSpace(req.IdentityKey)
	}
	rec.UpdatedAt = now
	h.devices[deviceID] = rec

	return c.JSON(fiber.Map{
		"deviceId":    rec.DeviceID,
		"ownerUid":    rec.OwnerUID,
		"identityKey": rec.IdentityKey,
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

	h.mu.RLock()
	rec, found := h.devices[deviceID]
	if !found {
		h.mu.RUnlock()
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "device not found"})
	}
	if !h.canAccessDeviceLocked(principal.UID, deviceID) {
		h.mu.RUnlock()
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
	}
	h.mu.RUnlock()

	return c.JSON(fiber.Map{
		"deviceId":    rec.DeviceID,
		"ownerUid":    rec.OwnerUID,
		"identityKey": rec.IdentityKey,
	})
}

func (h *Handler) canAccessDeviceLocked(uid, deviceID string) bool {
	device, exists := h.devices[deviceID]
	if !exists {
		return false
	}
	if device.OwnerUID == uid {
		return true
	}
	now := time.Now().UTC().Unix()
	return h.hasActiveGrantLocked(deviceID, uid, now)
}
