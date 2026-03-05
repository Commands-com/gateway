package gateway

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"oss-commands-gateway/internal/gatewaycrypto"
)

func testEd25519Identity(seed string) (string, ed25519.PrivateKey) {
	seedHash := sha256.Sum256([]byte("identity:" + seed))
	privateKey := ed25519.NewKeyFromSeed(seedHash[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return base64.StdEncoding.EncodeToString(publicKey), privateKey
}

func testX25519Public(seed string) string {
	sum := sha256.Sum256([]byte("x25519:" + seed))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func testNonce(seed string) string {
	sum := sha256.Sum256([]byte("nonce:" + seed))
	return base64.StdEncoding.EncodeToString(sum[:16])
}

func testSignedHandshakeAck(
	t *testing.T,
	sessionID string,
	handshakeID string,
	clientEphemeral string,
	clientNonce string,
	identityPrivateKey ed25519.PrivateKey,
) map[string]any {
	t.Helper()

	agentEphemeral := testX25519Public("agent:" + sessionID + ":" + handshakeID)
	transcriptHash := gatewaycrypto.BuildTranscriptHash(
		sessionID,
		handshakeID,
		clientEphemeral,
		clientNonce,
		agentEphemeral,
	)
	transcriptHashBytes, err := base64.StdEncoding.DecodeString(transcriptHash)
	if err != nil {
		t.Fatalf("decode transcript hash failed: %v", err)
	}
	signature := ed25519.Sign(identityPrivateKey, transcriptHashBytes)

	return map[string]any{
		"status":                     "ok",
		"agent_ephemeral_public_key": agentEphemeral,
		"agent_identity_signature":   base64.StdEncoding.EncodeToString(signature),
		"transcript_hash":            transcriptHash,
	}
}
