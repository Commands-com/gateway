package gateway

import (
	"crypto/rand"
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

// hasActiveGrantLocked reports whether uid has an active grant for deviceID.
// Caller must hold h.mu (read or write lock).
func (h *Handler) hasActiveGrantLocked(deviceID, uid string, now int64) bool {
	if deviceID == "" || uid == "" {
		return false
	}
	for _, grant := range h.grantsByDevice[deviceID] {
		if grant == nil || grant.GranteeUID != uid {
			continue
		}
		if effectiveGrantStatus(grant, now) == "active" {
			return true
		}
	}
	return false
}

func randomToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func inviteURL(frontendURL, token string) string {
	base := strings.TrimRight(strings.TrimSpace(frontendURL), "/")
	if base == "" {
		base = "https://example.com"
	}
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
