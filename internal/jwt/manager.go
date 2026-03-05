package jwt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	Email    string `json:"email,omitempty"`
	Name     string `json:"name,omitempty"`
	Scope    string `json:"scope,omitempty"`
	AuthMode string `json:"auth_mode,omitempty"`
	jwtv5.RegisteredClaims
}

type Manager struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	issuer     string
	audience   string
	kid        string
}

func NewManager(signingSecret, issuer, audience string) (*Manager, error) {
	secret := strings.TrimSpace(signingSecret)
	if secret == "" {
		return nil, fmt.Errorf("signing secret cannot be empty")
	}
	sum := sha256.Sum256([]byte(secret))
	privateKey := ed25519.NewKeyFromSeed(sum[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	kid := base64.RawURLEncoding.EncodeToString(sum[:8])
	return &Manager{
		privateKey: privateKey,
		publicKey:  publicKey,
		issuer:     issuer,
		audience:   audience,
		kid:        kid,
	}, nil
}

func (m *Manager) IssueAccessToken(subject, email, name string, scopes []string, authMode string, ttl time.Duration) (string, int64, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(ttl)
	claims := &Claims{
		Email:    strings.TrimSpace(email),
		Name:     strings.TrimSpace(name),
		Scope:    strings.Join(scopes, " "),
		AuthMode: authMode,
		RegisteredClaims: jwtv5.RegisteredClaims{
			Subject:   subject,
			Issuer:    m.issuer,
			Audience:  []string{m.audience},
			IssuedAt:  jwtv5.NewNumericDate(now),
			NotBefore: jwtv5.NewNumericDate(now),
			ExpiresAt: jwtv5.NewNumericDate(expiresAt),
		},
	}
	tok := jwtv5.NewWithClaims(jwtv5.SigningMethodEdDSA, claims)
	tok.Header["kid"] = m.kid
	raw, err := tok.SignedString(m.privateKey)
	if err != nil {
		return "", 0, err
	}
	return raw, int64(ttl.Seconds()), nil
}

func (m *Manager) ParseAccessToken(raw string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwtv5.ParseWithClaims(raw, claims, func(token *jwtv5.Token) (interface{}, error) {
		if token.Method.Alg() != jwtv5.SigningMethodEdDSA.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Method.Alg())
		}
		return m.publicKey, nil
	},
		jwtv5.WithAudience(m.audience),
		jwtv5.WithIssuer(m.issuer),
	)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

func (m *Manager) JWKS() map[string]any {
	return map[string]any{
		"keys": []map[string]any{
			{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   base64.RawURLEncoding.EncodeToString(m.publicKey),
				"use": "sig",
				"alg": "EdDSA",
				"kid": m.kid,
			},
		},
	}
}
