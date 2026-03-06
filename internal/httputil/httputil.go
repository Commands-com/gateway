package httputil

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
)

// BearerToken extracts the token from an Authorization header value.
func BearerToken(authHeader string) string {
	authHeader = strings.TrimSpace(authHeader)
	if authHeader == "" {
		return ""
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(strings.ToLower(authHeader), strings.ToLower(prefix)) {
		return ""
	}
	return strings.TrimSpace(authHeader[len(prefix):])
}

// RandomToken generates a cryptographically random token of the given byte
// size, returned as a base64-raw-url-encoded string.
func RandomToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
