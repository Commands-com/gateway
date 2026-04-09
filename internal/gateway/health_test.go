package gateway

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"oss-commands-gateway/internal/auth"
	"oss-commands-gateway/internal/config"
)

// TestHealthCountersAreOwnerScoped verifies that the per-user Health counters
// (devices, grants, sessions, routes) only reflect records owned by the
// calling user, even when the store contains records owned by other users.
//
// This is the regression test for the dashboard/Devices-tab mismatch where
// /health reported a global device count while the Devices tab only listed
// the caller's own devices.
func TestHealthCountersAreOwnerScoped(t *testing.T) {
	h := NewHandler(&config.Config{
		FrontendURL:   "https://frontend.example",
		StateBackend:  config.StateBackendMemory,
		PublicBaseURL: "http://localhost:8080",
		AuthMode:      config.AuthModeDemo,
	})

	ctx := context.Background()
	now := time.Now().UTC().Unix()
	nowRFC := time.Now().UTC().Format(time.RFC3339)

	// Seed records for two different owners. The caller will be "owner1";
	// "owner2" records must NOT appear in owner1's Health counts.
	//
	// owner1 gets: 2 devices, 1 route, 1 session, 1 grant
	// owner2 gets: 3 devices, 2 routes, 2 sessions, 2 grants
	seed := func(ownerUID, ownerEmail string, devices, routes, sessions, grants int) {
		for i := 0; i < devices; i++ {
			devID := ownerUID + "-dev" + string(rune('a'+i))
			if err := h.store.SaveDevice(ctx, deviceRecord{
				DeviceID:   devID,
				OwnerUID:   ownerUID,
				OwnerEmail: ownerEmail,
				UpdatedAt:  now,
			}); err != nil {
				t.Fatalf("save device %s: %v", devID, err)
			}
		}
		for i := 0; i < routes; i++ {
			routeID := "rt_" + ownerUID + "route" + string(rune('a'+i))
			// Pad to the rt_<32 hex> shape loosely — the store does not
			// validate format at save time.
			for len(routeID) < 35 {
				routeID += "0"
			}
			if err := h.store.SaveIntegrationRoute(ctx, &integrationRoute{
				RouteID:       routeID,
				OwnerUID:      ownerUID,
				DeviceID:      ownerUID + "-deva",
				InterfaceType: "slack_events",
				TokenAuthMode: "path",
				Status:        "provisioned",
				CreatedAt:     nowRFC,
				UpdatedAt:     nowRFC,
			}); err != nil {
				t.Fatalf("save route %s: %v", routeID, err)
			}
		}
		for i := 0; i < sessions; i++ {
			sessID := "sess_" + ownerUID + string(rune('a'+i))
			if _, err := h.store.CreateSession(ctx, &sessionState{
				SessionID: sessID,
				DeviceID:  ownerUID + "-deva",
				OwnerUID:  ownerUID,
				Status:    "active",
				CreatedAt: now,
				UpdatedAt: now,
			}); err != nil {
				t.Fatalf("create session %s: %v", sessID, err)
			}
		}
		for i := 0; i < grants; i++ {
			grantID := "grant_" + ownerUID + string(rune('a'+i))
			// Unique grantee email per grant — CreateShareGrantIfAbsent
			// rejects duplicates for the same (device, grantee) pair.
			granteeEmail := "friend" + string(rune('a'+i)) + "@example.com"
			if _, _, err := h.store.CreateShareGrantIfAbsent(ctx, &shareGrant{
				GrantID:      grantID,
				DeviceID:     ownerUID + "-deva",
				OwnerUID:     ownerUID,
				OwnerEmail:   ownerEmail,
				GranteeEmail: granteeEmail,
				Role:         "viewer",
				Status:       "active",
				CreatedAt:    now,
				UpdatedAt:    now,
			}, now); err != nil {
				t.Fatalf("create grant %s: %v", grantID, err)
			}
		}
	}

	seed("owner1", "owner1@example.com", 2, 1, 1, 1)
	seed("owner2", "owner2@example.com", 3, 2, 2, 2)

	// Mount Health on a test app with an auth middleware that injects a
	// principal from X-Test-UID, matching the pattern used by the other
	// gateway tests.
	app := fiber.New()
	app.Use(func(c fiber.Ctx) error {
		if uid := c.Get("X-Test-UID"); uid != "" {
			c.Locals("principal", &auth.Principal{UID: uid, Email: uid + "@example.com"})
		}
		return c.Next()
	})
	app.Get("/gateway/v1/health", h.Health)

	doHealth := func(uid string) map[string]any {
		t.Helper()
		req := httptest.NewRequest("GET", "/gateway/v1/health", nil)
		req.Header.Set("X-Test-UID", uid)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("health request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != fiber.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		var out map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode health response: %v", err)
		}
		return out
	}

	intOf := func(m map[string]any, key string) int {
		t.Helper()
		v, ok := m[key]
		if !ok {
			t.Fatalf("missing %q in health response: %v", key, m)
		}
		f, ok := v.(float64)
		if !ok {
			t.Fatalf("expected number for %q, got %T", key, v)
		}
		return int(f)
	}

	o1 := doHealth("owner1")
	if got := intOf(o1, "devices"); got != 2 {
		t.Fatalf("owner1 devices: got %d want 2 (global count leaking through?)", got)
	}
	if got := intOf(o1, "routes"); got != 1 {
		t.Fatalf("owner1 routes: got %d want 1", got)
	}
	if got := intOf(o1, "sessions"); got != 1 {
		t.Fatalf("owner1 sessions: got %d want 1", got)
	}
	if got := intOf(o1, "grants"); got != 1 {
		t.Fatalf("owner1 grants: got %d want 1", got)
	}

	o2 := doHealth("owner2")
	if got := intOf(o2, "devices"); got != 3 {
		t.Fatalf("owner2 devices: got %d want 3", got)
	}
	if got := intOf(o2, "routes"); got != 2 {
		t.Fatalf("owner2 routes: got %d want 2", got)
	}
	if got := intOf(o2, "sessions"); got != 2 {
		t.Fatalf("owner2 sessions: got %d want 2", got)
	}
	if got := intOf(o2, "grants"); got != 2 {
		t.Fatalf("owner2 grants: got %d want 2", got)
	}

	// An unrelated third user sees zeros for the user-scoped counters
	// even though the store has records belonging to owner1/owner2.
	o3 := doHealth("stranger")
	for _, key := range []string{"devices", "routes", "sessions", "grants"} {
		if got := intOf(o3, key); got != 0 {
			t.Fatalf("stranger %s: got %d want 0 (owner scoping leak)", key, got)
		}
	}
}
