package gateway

import (
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"oss-commands-gateway/internal/auth"
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

	h.mu.Lock()
	defer h.mu.Unlock()

	rec, found := h.devices[deviceID]
	if !found {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "device not found"})
	}
	if rec.OwnerUID != principal.UID {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "you do not own this device"})
	}

	for _, grant := range h.grantsByDevice[deviceID] {
		if grant == nil || grant.GranteeEmail != granteeEmail {
			continue
		}
		status := effectiveGrantStatus(grant, now)
		if status == "pending" || status == "active" {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "an active or pending grant already exists for this email and device"})
		}
	}

	token, err := randomToken(32)
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
	h.grants[grantID] = grant
	h.addGrantToDeviceIndexLocked(grant)
	h.inviteToID[tokenHash] = grantID

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
	if canonicalEmail(principal.Email) == "" {
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

	now := time.Now().UTC().Unix()
	tokenHash := hashToken(token)

	h.mu.Lock()
	defer h.mu.Unlock()

	grantID, ok := h.inviteToID[tokenHash]
	if !ok {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "invite not found or already used"})
	}
	grant, found := h.grants[grantID]
	if !found {
		delete(h.inviteToID, tokenHash)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "invite not found"})
	}
	if grant.Status != "pending" {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": fmt.Sprintf("invite is %s", grant.Status)})
	}
	if grant.InviteTokenExpiresAt > 0 && now > grant.InviteTokenExpiresAt {
		grant.Status = "expired"
		grant.UpdatedAt = now
		return c.Status(fiber.StatusGone).JSON(fiber.Map{"error": "invite has expired"})
	}
	if grant.GranteeEmail != "" && grant.GranteeEmail != canonicalEmail(principal.Email) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "email does not match this invite"})
	}
	if strings.TrimSpace(req.DeviceID) != "" {
		deviceID, err := validateID(req.DeviceID, "deviceId")
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		if rec, exists := h.devices[deviceID]; !exists || rec.OwnerUID != principal.UID {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "you do not own this device"})
		}
		grant.GranteeDeviceID = deviceID
	}

	grant.Status = "active"
	grant.GranteeUID = principal.UID
	grant.AcceptedAt = now
	grant.UpdatedAt = now

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

	h.mu.RLock()
	rec, found := h.devices[deviceID]
	if !found {
		h.mu.RUnlock()
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "device not found"})
	}
	if rec.OwnerUID != principal.UID {
		h.mu.RUnlock()
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "you do not own this device"})
	}
	grants := make([]fiber.Map, 0)
	for _, grant := range h.grants {
		if grant.DeviceID != deviceID {
			continue
		}
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
	h.mu.RUnlock()

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

	h.mu.Lock()
	defer h.mu.Unlock()

	grant, found := h.grants[grantID]
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
	h.removeGrantFromDeviceIndexLocked(grant.DeviceID, grant.GrantID)

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

	h.mu.Lock()
	defer h.mu.Unlock()

	grant, found := h.grants[grantID]
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
	h.removeGrantFromDeviceIndexLocked(grant.DeviceID, grant.GrantID)

	// Proactively evict any open SSE streams for the leaving grantee
	if grant.GranteeUID != "" {
		h.evictSubscribersByUID(grant.GranteeUID, grant.DeviceID)
	}

	return c.JSON(fiber.Map{"grantId": grantID, "status": "revoked"})
}

func (h *Handler) addGrantToDeviceIndexLocked(grant *shareGrant) {
	if grant == nil || grant.DeviceID == "" {
		return
	}
	h.grantsByDevice[grant.DeviceID] = append(h.grantsByDevice[grant.DeviceID], grant)
}

func (h *Handler) removeGrantFromDeviceIndexLocked(deviceID, grantID string) {
	if deviceID == "" || grantID == "" {
		return
	}
	grants := h.grantsByDevice[deviceID]
	if len(grants) == 0 {
		return
	}
	filtered := grants[:0]
	for _, grant := range grants {
		if grant == nil || grant.GrantID == grantID {
			continue
		}
		filtered = append(filtered, grant)
	}
	if len(filtered) == 0 {
		delete(h.grantsByDevice, deviceID)
		return
	}
	h.grantsByDevice[deviceID] = filtered
}
