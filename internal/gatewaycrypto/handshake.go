package gatewaycrypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

const (
	x25519PublicKeySize = 32
)

func decodeBase64Fixed(raw string, expectedLen int, field string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid %s encoding: %w", field, err)
	}
	if len(decoded) != expectedLen {
		return nil, fmt.Errorf("invalid %s length: got %d want %d", field, len(decoded), expectedLen)
	}
	return decoded, nil
}

// ValidateX25519PublicKey validates a base64 encoded X25519 public key.
func ValidateX25519PublicKey(pubB64 string) error {
	_, err := decodeBase64Fixed(pubB64, x25519PublicKeySize, "x25519 public key")
	return err
}

// ValidateEd25519PublicKey validates a base64 encoded Ed25519 public key.
func ValidateEd25519PublicKey(pubB64 string) error {
	_, err := decodeBase64Fixed(pubB64, ed25519.PublicKeySize, "ed25519 public key")
	return err
}

// BuildTranscriptHash computes the transcript hash used for handshake signatures.
func BuildTranscriptHash(sessionID, handshakeID, clientEphemeralPubB64, clientSessionNonce, agentEphemeralPubB64 string) string {
	joined := fmt.Sprintf("%s|%s|%s|%s|%s", sessionID, handshakeID, clientEphemeralPubB64, clientSessionNonce, agentEphemeralPubB64)
	sum := sha256.Sum256([]byte(joined))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// ConstantTimeEqualBase64 compares two base64 values in constant time.
func ConstantTimeEqualBase64(aB64, bB64 string) bool {
	a, errA := base64.StdEncoding.DecodeString(aB64)
	b, errB := base64.StdEncoding.DecodeString(bB64)
	if errA != nil || errB != nil {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// VerifyAgentSignature verifies the agent's handshake signature against transcript hash bytes.
func VerifyAgentSignature(agentIdentityPublicKeyB64, transcriptHashB64, signatureB64 string) error {
	pub, err := decodeBase64Fixed(agentIdentityPublicKeyB64, ed25519.PublicKeySize, "agent identity public key")
	if err != nil {
		return err
	}

	transcriptHash, err := decodeBase64Fixed(transcriptHashB64, sha256.Size, "transcript hash")
	if err != nil {
		return err
	}

	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length: got %d want %d", len(sig), ed25519.SignatureSize)
	}

	if !ed25519.Verify(ed25519.PublicKey(pub), transcriptHash, sig) {
		return fmt.Errorf("invalid agent identity signature")
	}

	return nil
}
