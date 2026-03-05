package gateway

import (
	"context"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"

	"oss-commands-gateway/internal/auth"
	"oss-commands-gateway/internal/gatewaycrypto"
)

const maxDevicesPerOwner = 200

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
	if strings.TrimSpace(req.IdentityKey) != "" {
		if err := gatewaycrypto.ValidateEd25519PublicKey(strings.TrimSpace(req.IdentityKey)); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid identity key"})
		}
	}
	now := time.Now().UTC().Unix()
	rec, exists, err := h.store.GetDevice(context.Background(), deviceID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to read device"})
	}
	if exists && rec.OwnerUID != "" && rec.OwnerUID != principal.UID {
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
	if strings.TrimSpace(req.IdentityKey) != "" {
		rec.IdentityKey = strings.TrimSpace(req.IdentityKey)
	}
	rec.UpdatedAt = now
	if err := h.store.SaveDevice(context.Background(), rec); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to save device"})
	}

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

	rec, found, err := h.store.GetDevice(context.Background(), deviceID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to read device"})
	}
	if !found {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "device not found"})
	}
	if !h.canAccessDeviceLocked(principal.UID, deviceID) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
	}

	return c.JSON(fiber.Map{
		"deviceId":    rec.DeviceID,
		"ownerUid":    rec.OwnerUID,
		"identityKey": rec.IdentityKey,
	})
}

func (h *Handler) canAccessDeviceLocked(uid, deviceID string) bool {
	device, found, err := h.store.GetDevice(context.Background(), deviceID)
	if err != nil || !found {
		return false
	}
	if device.OwnerUID == uid {
		return true
	}
	now := time.Now().UTC().Unix()
	return h.hasActiveGrantLocked(deviceID, uid, now)
}
