package gateway

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"oss-commands-gateway/internal/auth"
	"oss-commands-gateway/internal/httputil"
)

func (h *Handler) CreateShareInvite(c fiber.Ctx) error {
	principal := auth.PrincipalFromContext(c)
	if principal == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}

	var req createShareInviteRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid json body"})
	}
	deviceID, err := validateID(req.DeviceID, "deviceId")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	granteeEmail := canonicalEmail(req.Email)
	if granteeEmail == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid email"})
	}
	if canonicalEmail(principal.Email) == granteeEmail {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "cannot invite yourself"})
	}

	inviteTTL := req.InviteTokenTtlSeconds
	if inviteTTL <= 0 {
		inviteTTL = defaultInviteTTLSeconds
	}
	if inviteTTL > maxInviteTTLSeconds {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "inviteTokenTtlSeconds exceeds maximum"})
	}

	now := time.Now().UTC().Unix()
	inviteExpiresAt := now + inviteTTL
	rec, found, err := h.store.GetDevice(c.Context(), deviceID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to read device"})
	}
	if !found {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "device not found"})
	}
	if rec.OwnerUID != principal.UID {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "you do not own this device"})
	}

	grantsForDevice, err := h.store.ListShareGrantsByDevice(c.Context(), deviceID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to read grants"})
	}
	for _, grant := range grantsForDevice {
		if grant == nil || grant.GranteeEmail != granteeEmail {
			continue
		}
		status := effectiveGrantStatus(grant, now)
		if status == "pending" || status == "active" {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "an active or pending grant already exists for this email and device"})
		}
	}

	token, err := httputil.RandomToken(32)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate invite token"})
	}
	tokenHash := hashToken(token)
	grantID := "gr_" + strings.ReplaceAll(uuid.NewString(), "-", "")

	grant := &shareGrant{
		GrantID:              grantID,
		DeviceID:             deviceID,
		OwnerUID:             principal.UID,
		OwnerEmail:           canonicalEmail(principal.Email),
		GranteeEmail:         granteeEmail,
		Role:                 "collaborator",
		Status:               "pending",
		InviteTokenHash:      tokenHash,
		InviteTokenExpiresAt: inviteExpiresAt,
		GrantExpiresAt:       req.GrantExpiresAt,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := h.store.SaveShareGrant(c.Context(), grant); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to save grant"})
	}
	if err := h.store.SaveInviteGrantMapping(c.Context(), tokenHash, grantID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to save invite"})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"grantId":              grantID,
		"status":               "pending",
		"inviteUrl":            inviteURL(h.cfg.FrontendURL, token),
		"inviteTokenExpiresAt": inviteExpiresAt,
		"grantExpiresAt":       req.GrantExpiresAt,
	})
}

func (h *Handler) AcceptShareInvite(c fiber.Ctx) error {
	principal := auth.PrincipalFromContext(c)
	if principal == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	acceptorEmail := canonicalEmail(principal.Email)
	if acceptorEmail == "" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "email is required to accept invites"})
	}

	var req acceptShareInviteRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid json body"})
	}
	token := strings.TrimSpace(req.Token)
	if token == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "token is required"})
	}
	granteeDeviceID := ""
	if strings.TrimSpace(req.DeviceID) != "" {
		deviceID, err := validateID(req.DeviceID, "deviceId")
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		rec, exists, err := h.store.GetDevice(c.Context(), deviceID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to read device"})
		}
		if !exists || rec.OwnerUID != principal.UID {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "you do not own this device"})
		}
		granteeDeviceID = deviceID
	}

	now := time.Now().UTC().Unix()
	tokenHash := hashToken(token)
	grant, err := h.store.AcceptShareInviteAtomic(c.Context(), tokenHash, principal.UID, acceptorEmail, granteeDeviceID, now)
	if err != nil {
		switch {
		case errors.Is(err, ErrInviteNotFound):
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "invite not found or already used"})
		case errors.Is(err, ErrInviteGrantNotFound):
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "invite not found"})
		case errors.Is(err, ErrInviteExpired):
			return c.Status(fiber.StatusGone).JSON(fiber.Map{"error": "invite has expired"})
		case errors.Is(err, ErrInviteEmailMismatch):
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "email does not match this invite"})
		default:
			var statusErr *InviteStatusError
			if errors.As(err, &statusErr) {
				return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": fmt.Sprintf("invite is %s", statusErr.Status)})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to accept invite"})
		}
	}

	return c.JSON(fiber.Map{
		"grantId":  grant.GrantID,
		"deviceId": grant.DeviceID,
		"role":     grant.Role,
		"status":   grant.Status,
	})
}

func (h *Handler) ListShareGrants(c fiber.Ctx) error {
	principal := auth.PrincipalFromContext(c)
	if principal == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	deviceID, err := validateID(c.Params("device_id"), "device_id")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	now := time.Now().UTC().Unix()
	rec, found, err := h.store.GetDevice(c.Context(), deviceID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to read device"})
	}
	if !found {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "device not found"})
	}
	if rec.OwnerUID != principal.UID {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "you do not own this device"})
	}
	deviceGrants, err := h.store.ListAllShareGrantsByDevice(c.Context(), deviceID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to read grants"})
	}
	grants := make([]fiber.Map, 0)
	for _, grant := range deviceGrants {
		grants = append(grants, fiber.Map{
			"grantId":         grant.GrantID,
			"granteeEmail":    grant.GranteeEmail,
			"granteeUid":      grant.GranteeUID,
			"granteeDeviceId": grant.GranteeDeviceID,
			"role":            grant.Role,
			"status":          effectiveGrantStatus(grant, now),
			"grantExpiresAt":  grant.GrantExpiresAt,
			"acceptedAt":      grant.AcceptedAt,
			"createdAt":       grant.CreatedAt,
		})
	}

	return c.JSON(fiber.Map{
		"deviceId": deviceID,
		"grants":   grants,
	})
}

func (h *Handler) RevokeShareGrant(c fiber.Ctx) error {
	principal := auth.PrincipalFromContext(c)
	if principal == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	grantID := strings.TrimSpace(c.Params("grant_id"))
	if grantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "grant_id is required"})
	}

	now := time.Now().UTC().Unix()
	grant, found, err := h.store.GetShareGrant(c.Context(), grantID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to read grant"})
	}
	if !found {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "grant not found"})
	}
	if grant.OwnerUID != principal.UID {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
	}
	if grant.Status == "revoked" {
		return c.JSON(fiber.Map{"grantId": grantID, "status": "revoked"})
	}
	if grant.Status != "pending" && grant.Status != "active" {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": fmt.Sprintf("cannot revoke grant in %s state", grant.Status)})
	}

	grant.Status = "revoked"
	grant.RevokedAt = now
	grant.RevokedByUID = principal.UID
	grant.UpdatedAt = now
	if err := h.store.SaveShareGrant(c.Context(), grant); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to save grant"})
	}
	if err := h.store.DeleteShareGrantFromDeviceIndex(c.Context(), grant.DeviceID, grant.GrantID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update grant index"})
	}

	// Proactively evict any open SSE streams for the revoked grantee
	if grant.GranteeUID != "" {
		h.evictSubscribersByUID(grant.GranteeUID, grant.DeviceID)
	}

	return c.JSON(fiber.Map{"grantId": grantID, "status": "revoked"})
}

func (h *Handler) LeaveShareGrant(c fiber.Ctx) error {
	principal := auth.PrincipalFromContext(c)
	if principal == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	grantID := strings.TrimSpace(c.Params("grant_id"))
	if grantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "grant_id is required"})
	}

	now := time.Now().UTC().Unix()
	grant, found, err := h.store.GetShareGrant(c.Context(), grantID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to read grant"})
	}
	if !found {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "grant not found"})
	}
	if grant.GranteeUID != principal.UID {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
	}
	if grant.Status == "revoked" {
		return c.JSON(fiber.Map{"grantId": grantID, "status": "revoked"})
	}
	if grant.Status != "active" {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": fmt.Sprintf("cannot leave grant in %s state", grant.Status)})
	}
	grant.Status = "revoked"
	grant.RevokedAt = now
	grant.RevokedByUID = principal.UID
	grant.UpdatedAt = now
	if err := h.store.SaveShareGrant(c.Context(), grant); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to save grant"})
	}
	if err := h.store.DeleteShareGrantFromDeviceIndex(c.Context(), grant.DeviceID, grant.GrantID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update grant index"})
	}

	// Proactively evict any open SSE streams for the leaving grantee
	if grant.GranteeUID != "" {
		h.evictSubscribersByUID(grant.GranteeUID, grant.DeviceID)
	}

	return c.JSON(fiber.Map{"grantId": grantID, "status": "revoked"})
}
