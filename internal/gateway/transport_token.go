package gateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// TransportTokenIssuer creates and verifies HMAC-signed transport tokens
// for WebSocket connection authentication.
type TransportTokenIssuer struct {
	serverSecret []byte
}

func NewTransportTokenIssuer(secret string) *TransportTokenIssuer {
	return &TransportTokenIssuer{
		serverSecret: []byte(secret),
	}
}

func canonicalEncode(fields ...string) []byte {
	size := 0
	for _, f := range fields {
		size += 2 + len(f)
	}
	buf := make([]byte, 0, size)
	for _, f := range fields {
		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, uint16(len(f)))
		buf = append(buf, lenBuf...)
		buf = append(buf, f...)
	}
	return buf
}

// IssueToken creates an HMAC-signed transport token binding a device+connection
// pair with an expiration time.
func (t *TransportTokenIssuer) IssueToken(deviceID, connectionID string, ttl time.Duration) string {
	expiresAt := time.Now().Add(ttl).UTC().Format(time.RFC3339)
	payload := canonicalEncode(deviceID, connectionID, expiresAt)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)

	mac := hmac.New(sha256.New, t.serverSecret)
	mac.Write(payload)
	sig := mac.Sum(nil)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return payloadB64 + "." + sigB64
}

// VerifyToken decodes, verifies HMAC, checks device/connection binding, and expiry.
func (t *TransportTokenIssuer) VerifyToken(tokenB64 string, expectedDeviceID, expectedConnID string) error {
	parts := strings.SplitN(tokenB64, ".", 2)
	if len(parts) != 2 {
		return fmt.Errorf("malformed_token")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("invalid_token_encoding")
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("invalid_signature_encoding")
	}

	mac := hmac.New(sha256.New, t.serverSecret)
	mac.Write(payload)
	expectedSig := mac.Sum(nil)
	if !hmac.Equal(sig, expectedSig) {
		return fmt.Errorf("invalid_signature")
	}

	deviceID, connectionID, expiresAtStr, err := decodeCanonicalFields(payload)
	if err != nil {
		return fmt.Errorf("invalid_token_payload: %w", err)
	}
	if deviceID != expectedDeviceID {
		return fmt.Errorf("device_id_mismatch")
	}
	if connectionID != expectedConnID {
		return fmt.Errorf("connection_id_mismatch")
	}

	expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
	if err != nil {
		return fmt.Errorf("invalid_expiry")
	}
	if time.Now().After(expiresAt) {
		return fmt.Errorf("token_expired")
	}
	return nil
}

func decodeCanonicalFields(data []byte) (field1, field2, field3 string, err error) {
	fields := make([]string, 0, 3)
	offset := 0
	for i := 0; i < 3; i++ {
		if offset+2 > len(data) {
			return "", "", "", fmt.Errorf("truncated at field %d length", i)
		}
		length := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		if offset+length > len(data) {
			return "", "", "", fmt.Errorf("truncated at field %d data", i)
		}
		fields = append(fields, string(data[offset:offset+length]))
		offset += length
	}
	return fields[0], fields[1], fields[2], nil
}
