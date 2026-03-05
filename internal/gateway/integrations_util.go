package gateway

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

func generateRouteToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate route token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func generateRouteID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate route id: %w", err)
	}
	return "rt_" + hex.EncodeToString(buf), nil
}

func hashRouteToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func firstStringMap(frame map[string]any, keys ...string) string {
	for _, key := range keys {
		v, ok := frame[key]
		if !ok {
			continue
		}
		asString, ok := v.(string)
		if !ok {
			continue
		}
		if trimmed := strings.TrimSpace(asString); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
