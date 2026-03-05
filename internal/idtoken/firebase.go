package idtoken

import (
	"context"
	"fmt"
	"strings"

	"firebase.google.com/go/v4"
	firebaseauth "firebase.google.com/go/v4/auth"
	"google.golang.org/api/option"
)

type FirebaseVerifier struct {
	client *firebaseauth.Client
}

func NewFirebaseVerifier(ctx context.Context, projectID, credentialsPath string) (*FirebaseVerifier, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("firebase project id is required")
	}

	cfg := &firebase.Config{ProjectID: projectID}
	var opts []option.ClientOption
	if strings.TrimSpace(credentialsPath) != "" {
		opts = append(opts, option.WithCredentialsFile(credentialsPath))
	}

	app, err := firebase.NewApp(ctx, cfg, opts...)
	if err != nil {
		return nil, fmt.Errorf("firebase app init: %w", err)
	}
	authClient, err := app.Auth(ctx)
	if err != nil {
		return nil, fmt.Errorf("firebase auth init: %w", err)
	}
	return &FirebaseVerifier{client: authClient}, nil
}

func (v *FirebaseVerifier) Verify(ctx context.Context, rawToken string) (*Identity, error) {
	tok, err := v.client.VerifyIDToken(ctx, strings.TrimSpace(rawToken))
	if err != nil {
		return nil, err
	}
	email, _ := tok.Claims["email"].(string)
	name, _ := tok.Claims["name"].(string)
	if name == "" {
		name, _ = tok.Claims["display_name"].(string)
	}
	return &Identity{
		UID:         tok.UID,
		Email:       strings.TrimSpace(email),
		DisplayName: strings.TrimSpace(name),
	}, nil
}
