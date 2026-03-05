package idtoken

import (
	"context"
	"strings"
)

type Identity struct {
	UID         string
	Email       string
	DisplayName string
}

type Verifier interface {
	Verify(ctx context.Context, rawToken string) (*Identity, error)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
