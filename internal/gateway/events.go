package gateway

import (
	"bufio"
	"context"
	"log/slog"
	"strconv"
	"sync"
	"time"
)

const sessionBusPublishTimeout = 250 * time.Millisecond

// sseSubscriber represents an SSE client subscription.
// The evicted channel is closed to signal the SSE loop to exit (e.g. slow
// client, authorization revoked). The data channel (ch) is never closed by
// senders, avoiding send-on-closed-channel panics.
type sseSubscriber struct {
	ch        chan sessionEvent
	sessionID string
	uid       string

	once    sync.Once
	evicted chan struct{} // closed to signal the SSE writer loop to exit
}

// evict signals the subscriber to disconnect. Safe to call multiple times.
func (s *sseSubscriber) evict() {
	s.once.Do(func() { close(s.evicted) })
}

// sessionBusSub is a ref-counted, handler-level bus subscription for a single
// session. One goroutine reads from the bus channel and calls
// deliverToLocalSubscribers for events originating on other nodes. Events
// whose OriginNodeID matches the local node are skipped because they were
// already delivered directly via deliverToLocalSubscribers.
type sessionBusSub struct {
	cancel   func()
	unsub    func()
	stopOnce sync.Once
}

// stop cancels the bus subscription context and unsubscribes from the bus.
// Idempotent and safe to call on nil receivers.
func (bs *sessionBusSub) stop() {
	if bs == nil {
		return
	}
	bs.stopOnce.Do(func() {
		bs.cancel()
		if bs.unsub != nil {
			bs.unsub()
		}
	})
}

func (h *Handler) appendSessionEvent(ctx context.Context, sessionID string, payload []byte) string {
	event, err := h.store.AppendSessionEvent(ctx, sessionID, payload, maxEventBacklog)
	if err != nil {
		// keep behavior non-fatal for event append failures
		return ""
	}
	h.deliverToLocalSubscribers(sessionID, event)

	// Stamp origin before publishing so the bus goroutine on this node
	// knows to skip it (already delivered above).  sessionEvent is a
	// value type, so this does not mutate the copy sent to local subs.
	event.OriginNodeID = h.nodeID
	pubCtx, pubCancel := context.WithTimeout(context.Background(), sessionBusPublishTimeout)
	defer pubCancel()
	if err := h.bus.PublishSessionEvent(pubCtx, sessionID, event); err != nil {
		slog.Warn("session event bus publish failed", "session", sessionID, "event", event.ID, "err", err)
	}
	return event.ID
}

// deliverToLocalSubscribers pushes the event to all local SSE subscribers for
// the session. Slow subscribers whose channel is full are evicted so they
// reconnect and replay from Last-Event-ID.
func (h *Handler) deliverToLocalSubscribers(sessionID string, event sessionEvent) {
	h.mu.RLock()
	subs := h.subs[sessionID]
	snapshot := make([]*sseSubscriber, 0, len(subs))
	for sub := range subs {
		snapshot = append(snapshot, sub)
	}
	h.mu.RUnlock()

	var toEvict []*sseSubscriber
	for _, sub := range snapshot {
		select {
		case sub.ch <- event:
		default:
			toEvict = append(toEvict, sub)
		}
	}
	for _, sub := range toEvict {
		h.evictSubscriber(sessionID, sub)
	}
}

func (h *Handler) replayEvents(ctx context.Context, sessionID, lastEventID string) []sessionEvent {
	events, err := h.store.ListSessionEvents(ctx, sessionID)
	if err != nil || len(events) == 0 {
		return nil
	}
	if lastEventID == "" {
		copyOut := make([]sessionEvent, len(events))
		copy(copyOut, events)
		return copyOut
	}
	last, err := strconv.ParseInt(lastEventID, 10, 64)
	if err != nil {
		copyOut := make([]sessionEvent, len(events))
		copy(copyOut, events)
		return copyOut
	}
	filtered := make([]sessionEvent, 0, len(events))
	for _, evt := range events {
		id, parseErr := strconv.ParseInt(evt.ID, 10, 64)
		if parseErr != nil {
			continue
		}
		if id > last {
			filtered = append(filtered, evt)
		}
	}
	return filtered
}

func (h *Handler) subscribe(sessionID, uid string) *sseSubscriber {
	sub := &sseSubscriber{
		ch:        make(chan sessionEvent, 64),
		sessionID: sessionID,
		uid:       uid,
		evicted:   make(chan struct{}),
	}
	h.mu.Lock()
	if _, ok := h.subs[sessionID]; !ok {
		h.subs[sessionID] = make(map[*sseSubscriber]struct{})
	}
	h.subs[sessionID][sub] = struct{}{}
	_, hasBusSub := h.sessionBusSubs[sessionID]
	h.mu.Unlock()

	if !hasBusSub {
		h.startSessionBusSub(sessionID)
	}

	return sub
}

// startSessionBusSub creates a single handler-level bus subscription for a
// session. A dedicated goroutine reads from the bus and calls
// deliverToLocalSubscribers for events from other nodes. Events whose
// OriginNodeID matches the local node are skipped. Safe to call concurrently;
// a double-check under write lock prevents duplicate subscriptions.
func (h *Handler) startSessionBusSub(sessionID string) {
	busCtx, busCancel := context.WithCancel(context.Background())
	busCh := make(chan sessionEvent, 64)
	unsubBus, err := h.bus.SubscribeSessionEvents(busCtx, sessionID, busCh)
	if err != nil {
		busCancel()
		slog.Warn("session bus subscribe failed", "session", sessionID, "err", err)
		return
	}

	bs := &sessionBusSub{
		cancel: busCancel,
		unsub:  unsubBus,
	}

	h.mu.Lock()
	if _, exists := h.sessionBusSubs[sessionID]; exists {
		// Another goroutine won the race — discard ours.
		h.mu.Unlock()
		bs.stop()
		return
	}
	if len(h.subs[sessionID]) == 0 {
		// The subscriber that triggered this call already disconnected.
		h.mu.Unlock()
		bs.stop()
		return
	}
	nodeID := h.nodeID
	h.sessionBusSubs[sessionID] = bs
	h.mu.Unlock()

	go func() {
		defer func() {
			bs.stop()
			// Remove from map and check whether subscribers still exist.
			// If so, restart the bus subscription so remote fanout continues.
			h.mu.Lock()
			if h.sessionBusSubs[sessionID] == bs {
				delete(h.sessionBusSubs, sessionID)
			}
			hasSubscribers := len(h.subs[sessionID]) > 0
			h.mu.Unlock()

			// Don't restart if the handler is shutting down.
			select {
			case <-h.done:
				return
			default:
			}
			if hasSubscribers {
				h.startSessionBusSub(sessionID)
			}
		}()
		for {
			select {
			case <-busCtx.Done():
				return
			case <-h.done:
				return
			case evt, ok := <-busCh:
				if !ok {
					return
				}
				if evt.OriginNodeID == nodeID {
					continue
				}
				h.deliverToLocalSubscribers(sessionID, evt)
			}
		}
	}()
}

// removeSessionBusSub extracts and removes the bus subscription for a session
// from the map. Must be called with h.mu held for write. The caller must call
// stop() on the returned value after releasing h.mu.
func (h *Handler) removeSessionBusSub(sessionID string) *sessionBusSub {
	bs, ok := h.sessionBusSubs[sessionID]
	if ok {
		delete(h.sessionBusSubs, sessionID)
	}
	return bs
}

// evictSubscriber removes and signals a single subscriber. Safe for concurrent use.
func (h *Handler) evictSubscriber(sessionID string, sub *sseSubscriber) {
	var bs *sessionBusSub
	h.mu.Lock()
	if subs, ok := h.subs[sessionID]; ok {
		delete(subs, sub)
		if len(subs) == 0 {
			delete(h.subs, sessionID)
			bs = h.removeSessionBusSub(sessionID)
		}
	}
	h.mu.Unlock()
	sub.evict()
	bs.stop()
}

func (h *Handler) unsubscribe(sessionID string, sub *sseSubscriber) {
	var bs *sessionBusSub
	h.mu.Lock()
	if subs, ok := h.subs[sessionID]; ok {
		delete(subs, sub)
		if len(subs) == 0 {
			delete(h.subs, sessionID)
			bs = h.removeSessionBusSub(sessionID)
		}
	}
	h.mu.Unlock()
	sub.evict()
	bs.stop()
}

// evictSubscribersByUID evicts all SSE subscribers for the given UID on sessions
// associated with the given device.
func (h *Handler) evictSubscribersByUID(ctx context.Context, uid, deviceID string) {
	sessions, err := h.store.ListSessionsByDevice(ctx, deviceID)
	if err != nil {
		return
	}

	deviceSessions := make(map[string]struct{})
	for _, state := range sessions {
		if state == nil {
			continue
		}
		deviceSessions[state.SessionID] = struct{}{}
	}

	var busSubsToStop []*sessionBusSub
	h.mu.Lock()
	for sid := range deviceSessions {
		subs, ok := h.subs[sid]
		if !ok {
			continue
		}
		for sub := range subs {
			if sub.uid == uid {
				delete(subs, sub)
				sub.evict()
			}
		}
		if len(subs) == 0 {
			delete(h.subs, sid)
			if bs := h.removeSessionBusSub(sid); bs != nil {
				busSubsToStop = append(busSubsToStop, bs)
			}
		}
	}
	h.mu.Unlock()
	for _, bs := range busSubsToStop {
		bs.stop()
	}
}

// eventIDGreaterThan returns true when event a should be considered newer than b.
// We treat invalid Last-Event-ID values as "no cursor" to avoid suppressing live
// events when a client sends a malformed cursor.
func eventIDGreaterThan(a, b string) bool {
	aInt, aErr := strconv.ParseInt(a, 10, 64)
	bInt, bErr := strconv.ParseInt(b, 10, 64)
	if b == "" || bErr != nil {
		return true
	}
	if aErr != nil {
		return true
	}
	return aInt > bInt
}

func writeSSEComment(w *bufio.Writer, comment string) error {
	if _, err := w.WriteString(":" + comment + "\n\n"); err != nil {
		return err
	}
	return w.Flush()
}

func writeSSEEvent(w *bufio.Writer, event sessionEvent) error {
	if _, err := w.WriteString("id: " + event.ID + "\n"); err != nil {
		return err
	}
	if _, err := w.WriteString("event: session.event\n"); err != nil {
		return err
	}
	if _, err := w.WriteString("data: " + string(event.Data) + "\n\n"); err != nil {
		return err
	}
	return w.Flush()
}
