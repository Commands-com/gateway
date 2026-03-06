package gateway

import (
	"bufio"
	"context"
	"log"
	"strconv"
	"sync"
)

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

func (h *Handler) appendSessionEvent(sessionID string, payload []byte) string {
	event, err := h.store.AppendSessionEvent(context.Background(), sessionID, payload, maxEventBacklog)
	if err != nil {
		// keep behavior non-fatal for event append failures
		return ""
	}
	_ = h.bus.PublishSessionEvent(context.Background(), sessionID, event)
	return event.ID
}

func (h *Handler) replayEvents(sessionID, lastEventID string) []sessionEvent {
	events, err := h.store.ListSessionEvents(context.Background(), sessionID)
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
	h.mu.Unlock()

	// Subscribe to bus events and feed them into the subscriber channel.
	busCh := make(chan sessionEvent, 64)
	unsub, err := h.bus.SubscribeSessionEvents(context.Background(), sessionID, busCh)
	if err != nil {
		log.Printf("[gateway] bus_subscribe_failed session=%s uid=%s err=%v", sessionID, uid, err)
	}
	go func() {
		defer func() {
			if unsub != nil {
				unsub()
			}
		}()
		for {
			select {
			case <-sub.evicted:
				return
			case evt, ok := <-busCh:
				if !ok {
					return
				}
				select {
				case sub.ch <- evt:
				default:
					// Buffer full: evict slow subscriber
					h.evictSubscriber(sessionID, sub)
					return
				}
			}
		}
	}()

	return sub
}

// evictSubscriber removes and signals a single subscriber. Safe for concurrent use.
func (h *Handler) evictSubscriber(sessionID string, sub *sseSubscriber) {
	h.mu.Lock()
	if subs, ok := h.subs[sessionID]; ok {
		delete(subs, sub)
		if len(subs) == 0 {
			delete(h.subs, sessionID)
		}
	}
	h.mu.Unlock()
	sub.evict()
}

func (h *Handler) unsubscribe(sessionID string, sub *sseSubscriber) {
	h.mu.Lock()
	if subs, ok := h.subs[sessionID]; ok {
		delete(subs, sub)
		if len(subs) == 0 {
			delete(h.subs, sessionID)
		}
	}
	h.mu.Unlock()
	sub.evict()
}

// evictSubscribersByUID evicts all SSE subscribers for the given UID on sessions
// associated with the given device.
func (h *Handler) evictSubscribersByUID(uid, deviceID string) {
	sessions, err := h.store.ListSessionsByDevice(context.Background(), deviceID)
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

	h.mu.Lock()
	defer h.mu.Unlock()
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
		}
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
