package gatewaycrypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestValidateX25519PublicKey(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(key[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(pub)
	if err := ValidateX25519PublicKey(b64); err != nil {
		t.Errorf("valid key rejected: %v", err)
	}
	if err := ValidateX25519PublicKey("notbase64!!!"); err == nil {
		t.Error("expected error for invalid base64")
	}
	if err := ValidateX25519PublicKey(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Error("expected error for wrong length")
	}
}

func TestValidateEd25519PublicKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	b64 := base64.StdEncoding.EncodeToString(pub)
	if err := ValidateEd25519PublicKey(b64); err != nil {
		t.Errorf("valid key rejected: %v", err)
	}
	if err := ValidateEd25519PublicKey("bad"); err == nil {
		t.Error("expected error for invalid encoding")
	}
}

func TestBuildTranscriptHash(t *testing.T) {
	h1 := BuildTranscriptHash("s1", "h1", "cpub1", "nonce1", "apub1")
	h2 := BuildTranscriptHash("s1", "h1", "cpub1", "nonce1", "apub1")
	if h1 != h2 {
		t.Error("same inputs should produce same hash")
	}
	h3 := BuildTranscriptHash("s2", "h1", "cpub1", "nonce1", "apub1")
	if h1 == h3 {
		t.Error("different inputs should produce different hash")
	}
}

func TestConstantTimeEqualBase64(t *testing.T) {
	data := []byte("test data for comparison")
	b64 := base64.StdEncoding.EncodeToString(data)
	if !ConstantTimeEqualBase64(b64, b64) {
		t.Error("same values should be equal")
	}
	other := base64.StdEncoding.EncodeToString([]byte("different data here!!"))
	if ConstantTimeEqualBase64(b64, other) {
		t.Error("different values should not be equal")
	}
	if ConstantTimeEqualBase64("notbase64!!!", b64) {
		t.Error("invalid base64 should return false")
	}
}

func TestVerifyAgentSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	transcript := BuildTranscriptHash("s", "h", "c", "n", "a")
	transcriptBytes, _ := base64.StdEncoding.DecodeString(transcript)
	sig := ed25519.Sign(priv, transcriptBytes)

	pubB64 := base64.StdEncoding.EncodeToString(pub)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	if err := VerifyAgentSignature(pubB64, transcript, sigB64); err != nil {
		t.Errorf("valid signature rejected: %v", err)
	}

	// Wrong signature
	badSig := make([]byte, ed25519.SignatureSize)
	copy(badSig, sig)
	badSig[0] ^= 0xff
	if err := VerifyAgentSignature(pubB64, transcript, base64.StdEncoding.EncodeToString(badSig)); err == nil {
		t.Error("expected error for bad signature")
	}
}
