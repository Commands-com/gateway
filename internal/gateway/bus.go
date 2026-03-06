package gateway

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

type TunnelRequestMessage struct {
	RequestID       string
	RouteID         string
	Method          string
	Scheme          string
	Host            string
	ExternalURL     string
	RawTarget       string
	RawTargetBase64 string
	Path            string
	Query           string
	Headers         [][]string
	BodyBase64      string
	DeadlineMS      int
	ReceivedAt      time.Time
}

type TunnelResponseMessage struct {
	RequestID  string
	RouteID    string
	Status     int
	Headers    [][]string
	BodyBase64 string
}

type MessageBus interface {
	PublishSessionEvent(ctx context.Context, sessionID string, event sessionEvent) error
	SubscribeSessionEvents(ctx context.Context, sessionID string, ch chan<- sessionEvent) (unsubscribe func(), err error)

	PublishTunnelRequest(ctx context.Context, routeID string, req TunnelRequestMessage) error
	SubscribeTunnelRequests(ctx context.Context, routeID string, ch chan<- TunnelRequestMessage) (unsubscribe func(), err error)

	PublishTunnelResponse(ctx context.Context, requestID string, resp TunnelResponseMessage) error
	SubscribeTunnelResponses(ctx context.Context, requestID string, ch chan<- TunnelResponseMessage) (unsubscribe func(), err error)
}

var (
	ErrMessageBusNoSubscribers = errors.New("message_bus_no_subscribers")
	ErrMessageBusBackpressure  = errors.New("message_bus_backpressure")
)

type InMemoryMessageBus struct {
	mu sync.RWMutex

	sessionSubs map[string]map[chan<- sessionEvent]struct{}
	tunnelReq   map[string]map[chan<- TunnelRequestMessage]struct{}
	tunnelResp  map[string]map[chan<- TunnelResponseMessage]struct{}
}

func NewInMemoryMessageBus() *InMemoryMessageBus {
	return &InMemoryMessageBus{
		sessionSubs: make(map[string]map[chan<- sessionEvent]struct{}),
		tunnelReq:   make(map[string]map[chan<- TunnelRequestMessage]struct{}),
		tunnelResp:  make(map[string]map[chan<- TunnelResponseMessage]struct{}),
	}
}

func (b *InMemoryMessageBus) PublishSessionEvent(_ context.Context, sessionID string, event sessionEvent) error {
	subs := b.snapshotSessionSubs(sessionID)
	for _, ch := range subs {
		select {
		case ch <- event:
		default:
		}
	}
	return nil
}

func (b *InMemoryMessageBus) SubscribeSessionEvents(ctx context.Context, sessionID string, ch chan<- sessionEvent) (func(), error) {
	return b.subscribeSession(ctx, sessionID, ch), nil
}

func (b *InMemoryMessageBus) PublishTunnelRequest(ctx context.Context, routeID string, req TunnelRequestMessage) error {
	subs := b.snapshotTunnelReqSubs(routeID)
	if len(subs) == 0 {
		return ErrMessageBusNoSubscribers
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for _, ch := range subs {
		select {
		case ch <- req:
		case <-ctx.Done():
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("%w: %v", ErrMessageBusBackpressure, err)
			}
			return ErrMessageBusBackpressure
		}
	}
	return nil
}

func (b *InMemoryMessageBus) SubscribeTunnelRequests(ctx context.Context, routeID string, ch chan<- TunnelRequestMessage) (func(), error) {
	return b.subscribeTunnelReq(ctx, routeID, ch), nil
}

func (b *InMemoryMessageBus) PublishTunnelResponse(_ context.Context, requestID string, resp TunnelResponseMessage) error {
	subs := b.snapshotTunnelRespSubs(requestID)
	for _, ch := range subs {
		select {
		case ch <- resp:
		default:
		}
	}
	return nil
}

func (b *InMemoryMessageBus) SubscribeTunnelResponses(ctx context.Context, requestID string, ch chan<- TunnelResponseMessage) (func(), error) {
	return b.subscribeTunnelResp(ctx, requestID, ch), nil
}

func (b *InMemoryMessageBus) subscribeSession(ctx context.Context, sessionID string, ch chan<- sessionEvent) func() {
	b.mu.Lock()
	if _, ok := b.sessionSubs[sessionID]; !ok {
		b.sessionSubs[sessionID] = make(map[chan<- sessionEvent]struct{})
	}
	b.sessionSubs[sessionID][ch] = struct{}{}
	b.mu.Unlock()
	return b.makeUnsubscribe(ctx, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if subs, ok := b.sessionSubs[sessionID]; ok {
			delete(subs, ch)
			if len(subs) == 0 {
				delete(b.sessionSubs, sessionID)
			}
		}
	})
}

func (b *InMemoryMessageBus) subscribeTunnelReq(ctx context.Context, routeID string, ch chan<- TunnelRequestMessage) func() {
	b.mu.Lock()
	if _, ok := b.tunnelReq[routeID]; !ok {
		b.tunnelReq[routeID] = make(map[chan<- TunnelRequestMessage]struct{})
	}
	b.tunnelReq[routeID][ch] = struct{}{}
	b.mu.Unlock()
	return b.makeUnsubscribe(ctx, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if subs, ok := b.tunnelReq[routeID]; ok {
			delete(subs, ch)
			if len(subs) == 0 {
				delete(b.tunnelReq, routeID)
			}
		}
	})
}

func (b *InMemoryMessageBus) subscribeTunnelResp(ctx context.Context, requestID string, ch chan<- TunnelResponseMessage) func() {
	b.mu.Lock()
	if _, ok := b.tunnelResp[requestID]; !ok {
		b.tunnelResp[requestID] = make(map[chan<- TunnelResponseMessage]struct{})
	}
	b.tunnelResp[requestID][ch] = struct{}{}
	b.mu.Unlock()
	return b.makeUnsubscribe(ctx, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if subs, ok := b.tunnelResp[requestID]; ok {
			delete(subs, ch)
			if len(subs) == 0 {
				delete(b.tunnelResp, requestID)
			}
		}
	})
}

func (b *InMemoryMessageBus) makeUnsubscribe(ctx context.Context, unsubscribe func()) func() {
	var once sync.Once
	if ctx != nil {
		go func() {
			<-ctx.Done()
			once.Do(unsubscribe)
		}()
	}
	return func() {
		once.Do(unsubscribe)
	}
}

func (b *InMemoryMessageBus) snapshotSessionSubs(sessionID string) []chan<- sessionEvent {
	b.mu.RLock()
	defer b.mu.RUnlock()
	subs := b.sessionSubs[sessionID]
	out := make([]chan<- sessionEvent, 0, len(subs))
	for ch := range subs {
		out = append(out, ch)
	}
	return out
}

func (b *InMemoryMessageBus) snapshotTunnelReqSubs(routeID string) []chan<- TunnelRequestMessage {
	b.mu.RLock()
	defer b.mu.RUnlock()
	subs := b.tunnelReq[routeID]
	out := make([]chan<- TunnelRequestMessage, 0, len(subs))
	for ch := range subs {
		out = append(out, ch)
	}
	return out
}

func (b *InMemoryMessageBus) snapshotTunnelRespSubs(requestID string) []chan<- TunnelResponseMessage {
	b.mu.RLock()
	defer b.mu.RUnlock()
	subs := b.tunnelResp[requestID]
	out := make([]chan<- TunnelResponseMessage, 0, len(subs))
	for ch := range subs {
		out = append(out, ch)
	}
	return out
}
