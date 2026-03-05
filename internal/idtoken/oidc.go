package idtoken

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

type OIDCVerifier struct {
	verifier *oidc.IDTokenVerifier
}

func NewOIDCVerifier(ctx context.Context, issuerURL, clientID string) (*OIDCVerifier, error) {
	provider, err := oidc.NewProvider(ctx, strings.TrimSpace(issuerURL))
	if err != nil {
		return nil, fmt.Errorf("oidc provider init: %w", err)
	}
	return &OIDCVerifier{
		verifier: provider.Verifier(&oidc.Config{ClientID: strings.TrimSpace(clientID)}),
	}, nil
}

func (v *OIDCVerifier) Verify(ctx context.Context, rawToken string) (*Identity, error) {
	idToken, err := v.verifier.Verify(ctx, strings.TrimSpace(rawToken))
	if err != nil {
		return nil, err
	}
	var claims struct {
		Sub               string `json:"sub"`
		Email             string `json:"email"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}
	return &Identity{
		UID:         strings.TrimSpace(claims.Sub),
		Email:       strings.TrimSpace(claims.Email),
		DisplayName: firstNonEmpty(claims.Name, claims.PreferredUsername, claims.Email, claims.Sub),
	}, nil
}
