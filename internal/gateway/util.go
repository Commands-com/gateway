package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

func validateID(value, label string) (string, error) {
	value = strings.Clone(strings.TrimSpace(value))
	if value == "" {
		return "", fmt.Errorf("%s is required", label)
	}
	if len(value) < 3 || len(value) > 128 {
		return "", fmt.Errorf("invalid %s", label)
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		switch r {
		case '-', '_', '.', ':':
			continue
		default:
			return "", fmt.Errorf("invalid %s", label)
		}
	}
	return value, nil
}

func canonicalEmail(email string) string {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" || !strings.Contains(email, "@") {
		return ""
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return email
}

func effectiveGrantStatus(grant *shareGrant, now int64) string {
	status := strings.TrimSpace(grant.Status)
	if status == "pending" && grant.InviteTokenExpiresAt > 0 && now > grant.InviteTokenExpiresAt {
		return "expired"
	}
	if (status == "pending" || status == "active") && grant.GrantExpiresAt > 0 && now > grant.GrantExpiresAt {
		return "expired"
	}
	return status
}

// hasActiveGrant reports whether uid has an active grant for deviceID.
// Must be called without holding h.mu (the store handles its own concurrency).
func (h *Handler) hasActiveGrant(ctx context.Context, deviceID, uid string, now int64) bool {
	if deviceID == "" || uid == "" {
		return false
	}
	grants, err := h.store.ListShareGrantsByDevice(ctx, deviceID)
	if err != nil {
		return false
	}
	for _, grant := range grants {
		if grant == nil || grant.GranteeUID != uid {
			continue
		}
		if effectiveGrantStatus(grant, now) == "active" {
			return true
		}
	}
	return false
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func inviteURL(frontendURL, publicBaseURL, token string) string {
	// Prefer the configured frontend URL when set, so deployments with a
	// separate frontend domain or custom share-accept flow keep working.
	// Fall back to the built-in console when no frontend is configured.
	base := strings.TrimRight(strings.TrimSpace(frontendURL), "/")
	if base == "" || base == "https://example.com" {
		base = strings.TrimRight(strings.TrimSpace(publicBaseURL), "/")
		if base == "" {
			base = "https://example.com"
		}
		// Stock installs use the built-in console.
		return base + "/console#/share/" + token
	}
	// Custom frontend — use the frontend's share path convention.
	return base + "/share/" + token
}

func asString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	default:
		return ""
	}
}
