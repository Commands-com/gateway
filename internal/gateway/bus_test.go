package gateway

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestInMemoryMessageBusPublishTunnelRequestNoSubscribers(t *testing.T) {
	bus := NewInMemoryMessageBus()
	err := bus.PublishTunnelRequest(context.Background(), "rt_missing", TunnelRequestMessage{
		RequestID: "req_missing",
		RouteID:   "rt_missing",
	})
	if !errors.Is(err, ErrMessageBusNoSubscribers) {
		t.Fatalf("expected ErrMessageBusNoSubscribers, got %v", err)
	}
}

func TestInMemoryMessageBusPublishTunnelRequestBackpressure(t *testing.T) {
	bus := NewInMemoryMessageBus()
	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()

	reqCh := make(chan TunnelRequestMessage, 1)
	unsub, err := bus.SubscribeTunnelRequests(subCtx, "rt_backpressure", reqCh)
	if err != nil {
		t.Fatalf("subscribe failed: %v", err)
	}
	defer unsub()

	// Fill the subscriber buffer so publish must wait and then fail by context timeout.
	reqCh <- TunnelRequestMessage{RequestID: "req_existing", RouteID: "rt_backpressure"}

	pubCtx, pubCancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer pubCancel()
	err = bus.PublishTunnelRequest(pubCtx, "rt_backpressure", TunnelRequestMessage{
		RequestID: "req_new",
		RouteID:   "rt_backpressure",
	})
	if !errors.Is(err, ErrMessageBusBackpressure) {
		t.Fatalf("expected ErrMessageBusBackpressure, got %v", err)
	}
}
