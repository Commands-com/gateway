package gateway

import (
	"context"
	"errors"
	"testing"
)

func TestInMemoryStoreSaveSessionDetectsVersionConflict(t *testing.T) {
	store := NewInMemoryStateStore()
	ctx := context.Background()

	if err := store.SaveSession(ctx, &sessionState{SessionID: "sess1", Status: "pending_agent_ack"}); err != nil {
		t.Fatalf("save initial session failed: %v", err)
	}

	first, ok, err := store.GetSession(ctx, "sess1")
	if err != nil || !ok {
		t.Fatalf("load first session failed: ok=%v err=%v", ok, err)
	}
	second, ok, err := store.GetSession(ctx, "sess1")
	if err != nil || !ok {
		t.Fatalf("load second session failed: ok=%v err=%v", ok, err)
	}

	first.Status = "agent_acknowledged"
	if err := store.SaveSession(ctx, first); err != nil {
		t.Fatalf("save first copy failed: %v", err)
	}

	second.Status = "agent_error"
	if err := store.SaveSession(ctx, second); !errors.Is(err, ErrSessionVersionConflict) {
		t.Fatalf("expected ErrSessionVersionConflict, got %v", err)
	}

	latest, ok, err := store.GetSession(ctx, "sess1")
	if err != nil || !ok {
		t.Fatalf("load latest session failed: ok=%v err=%v", ok, err)
	}
	if latest.Status != "agent_acknowledged" {
		t.Fatalf("expected first update to win, got status=%s", latest.Status)
	}
}

func TestInMemoryStoreUpdateSessionIncrementsVersion(t *testing.T) {
	store := NewInMemoryStateStore()
	ctx := context.Background()

	if err := store.SaveSession(ctx, &sessionState{SessionID: "sess2", Status: "pending_agent_ack"}); err != nil {
		t.Fatalf("save initial session failed: %v", err)
	}
	before, ok, err := store.GetSession(ctx, "sess2")
	if err != nil || !ok {
		t.Fatalf("load before session failed: ok=%v err=%v", ok, err)
	}

	updated, err := store.UpdateSession(ctx, "sess2", func(sess *sessionState) error {
		sess.Status = "agent_acknowledged"
		return nil
	})
	if err != nil {
		t.Fatalf("update session failed: %v", err)
	}
	if updated.Status != "agent_acknowledged" {
		t.Fatalf("expected updated status, got %s", updated.Status)
	}
	if updated.Version <= before.Version {
		t.Fatalf("expected updated version > before version (%d <= %d)", updated.Version, before.Version)
	}
}

func TestInMemoryStoreCreateSessionOnlyCreatesOnce(t *testing.T) {
	store := NewInMemoryStateStore()
	ctx := context.Background()

	created, err := store.CreateSession(ctx, &sessionState{SessionID: "sess3", Status: "pending_agent_ack"})
	if err != nil {
		t.Fatalf("create session failed: %v", err)
	}
	if !created {
		t.Fatalf("expected first create to succeed")
	}

	created, err = store.CreateSession(ctx, &sessionState{SessionID: "sess3", Status: "agent_acknowledged"})
	if err != nil {
		t.Fatalf("second create returned error: %v", err)
	}
	if created {
		t.Fatalf("expected second create to report already exists")
	}

	loaded, ok, err := store.GetSession(ctx, "sess3")
	if err != nil || !ok {
		t.Fatalf("load created session failed: ok=%v err=%v", ok, err)
	}
	if loaded.Status != "pending_agent_ack" {
		t.Fatalf("expected original status to be preserved, got %s", loaded.Status)
	}
}

func TestInMemoryStoreReturnsCopiesForMutableRecords(t *testing.T) {
	store := NewInMemoryStateStore()
	ctx := context.Background()

	route := &integrationRoute{
		RouteID:       "rt_testcopy",
		OwnerUID:      "owner1",
		DeviceID:      "dev1",
		InterfaceType: "slack_events",
		Status:        "provisioned",
	}
	if err := store.SaveIntegrationRoute(ctx, route); err != nil {
		t.Fatalf("save route failed: %v", err)
	}
	loadedRoute, found, err := store.GetIntegrationRoute(ctx, route.RouteID)
	if err != nil || !found || loadedRoute == nil {
		t.Fatalf("load route failed: found=%v err=%v", found, err)
	}
	loadedRoute.Status = "active"
	reloadedRoute, found, err := store.GetIntegrationRoute(ctx, route.RouteID)
	if err != nil || !found || reloadedRoute == nil {
		t.Fatalf("reload route failed: found=%v err=%v", found, err)
	}
	if reloadedRoute.Status != "provisioned" {
		t.Fatalf("expected stored route status to remain provisioned, got %s", reloadedRoute.Status)
	}

	grant := &shareGrant{
		GrantID:      "gr_testcopy",
		DeviceID:     "dev1",
		OwnerUID:     "owner1",
		GranteeUID:   "user2",
		GranteeEmail: "u2@example.com",
		Status:       "active",
	}
	if err := store.SaveShareGrant(ctx, grant); err != nil {
		t.Fatalf("save grant failed: %v", err)
	}
	loadedGrant, found, err := store.GetShareGrant(ctx, grant.GrantID)
	if err != nil || !found || loadedGrant == nil {
		t.Fatalf("load grant failed: found=%v err=%v", found, err)
	}
	loadedGrant.Status = "revoked"
	reloadedGrant, found, err := store.GetShareGrant(ctx, grant.GrantID)
	if err != nil || !found || reloadedGrant == nil {
		t.Fatalf("reload grant failed: found=%v err=%v", found, err)
	}
	if reloadedGrant.Status != "active" {
		t.Fatalf("expected stored grant status to remain active, got %s", reloadedGrant.Status)
	}
}
