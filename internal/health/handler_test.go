package health

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"

	"oss-commands-gateway/internal/config"
)

func TestLiveness(t *testing.T) {
	app := fiber.New()
	h := NewHandler(&config.Config{AuthMode: "demo", StateBackend: "memory"})
	app.Get("/livez", h.Liveness)

	req := httptest.NewRequest("GET", "/livez", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("test request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"status":"ok"`) {
		t.Errorf("unexpected body: %s", body)
	}
}

func TestReadiness(t *testing.T) {
	app := fiber.New()
	h := NewHandler(&config.Config{StateBackend: "memory"})
	app.Get("/readyz", h.Readiness)

	req := httptest.NewRequest("GET", "/readyz", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("test request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"status":"ready"`) {
		t.Errorf("unexpected body: %s", body)
	}
}
