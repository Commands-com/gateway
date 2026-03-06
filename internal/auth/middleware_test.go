package auth

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"oss-commands-gateway/internal/jwt"
)

func newTestManager(t *testing.T) *jwt.Manager {
	t.Helper()
	m, err := jwt.NewManager("test-secret-that-is-at-least-32bytes!", "test-iss", "test-aud")
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

func issueToken(t *testing.T, m *jwt.Manager, sub, email string, scopes []string) string {
	t.Helper()
	raw, _, err := m.IssueAccessToken(sub, email, "Test", scopes, "demo", time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	return raw
}

func TestRequireUserRejectsNoToken(t *testing.T) {
	m := newTestManager(t)
	app := fiber.New()
	app.Get("/test", RequireUser(m), func(c fiber.Ctx) error {
		return c.SendString("ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, _ := app.Test(req)
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("status: got %d want 401", resp.StatusCode)
	}
}

func TestRequireUserAcceptsValidToken(t *testing.T) {
	m := newTestManager(t)
	app := fiber.New()
	app.Get("/test", RequireUser(m), func(c fiber.Ctx) error {
		p := PrincipalFromContext(c)
		return c.SendString(p.UID)
	})

	token := issueToken(t, m, "user1", "u@example.com", []string{"device"})
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := app.Test(req)
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "user1" {
		t.Errorf("body: got %q want %q", body, "user1")
	}
}

func TestOptionalUserProceedsWithoutToken(t *testing.T) {
	m := newTestManager(t)
	app := fiber.New()
	app.Get("/test", OptionalUser(m), func(c fiber.Ctx) error {
		p := PrincipalFromContext(c)
		if p != nil {
			return c.SendString(p.UID)
		}
		return c.SendString("anon")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, _ := app.Test(req)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "anon" {
		t.Errorf("expected anon, got %q", body)
	}
}

func TestRequireScopesForbidsMissing(t *testing.T) {
	m := newTestManager(t)
	app := fiber.New()
	app.Get("/test", RequireUser(m), RequireScopes("admin"), func(c fiber.Ctx) error {
		return c.SendString("ok")
	})

	token := issueToken(t, m, "user1", "u@example.com", []string{"device"})
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := app.Test(req)
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("status: got %d want 403", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "insufficient_scope") {
		t.Errorf("expected insufficient_scope error, got: %s", body)
	}
}

func TestRequireScopesPassesWithScope(t *testing.T) {
	m := newTestManager(t)
	app := fiber.New()
	app.Get("/test", RequireUser(m), RequireScopes("device"), func(c fiber.Ctx) error {
		return c.SendString("ok")
	})

	token := issueToken(t, m, "user1", "u@example.com", []string{"device", "gateway:session"})
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := app.Test(req)
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
}

func TestPrincipalHasScope(t *testing.T) {
	var nilPrincipal *Principal
	if nilPrincipal.HasScope("anything") {
		t.Error("nil principal should not have any scope")
	}
	p := &Principal{Scopes: []string{"a", "b"}}
	if !p.HasScope("a") {
		t.Error("should have scope a")
	}
	if p.HasScope("c") {
		t.Error("should not have scope c")
	}
	if p.HasScope("") {
		t.Error("empty scope should return false")
	}
}
