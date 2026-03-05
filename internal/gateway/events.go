package gateway

import (
	"bufio"
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
	h.mu.Lock()
	h.eventSeq++
	event := sessionEvent{ID: strconv.FormatInt(h.eventSeq, 10), Data: payload}
	h.events[sessionID] = append(h.events[sessionID], event)
	if len(h.events[sessionID]) > maxEventBacklog {
		h.events[sessionID] = h.events[sessionID][len(h.events[sessionID])-maxEventBacklog:]
	}
	// Snapshot subscriber list under lock
	subscribers := make([]*sseSubscriber, 0, len(h.subs[sessionID]))
	for sub := range h.subs[sessionID] {
		subscribers = append(subscribers, sub)
	}
	h.mu.Unlock()

	for _, sub := range subscribers {
		select {
		case sub.ch <- event:
		default:
			// Buffer full: evict the slow subscriber by signalling its done
			// channel. We never close the data channel, so concurrent senders
			// cannot panic.
			h.evictSubscriber(sessionID, sub)
		}
	}
	return event.ID
}

func (h *Handler) replayEvents(sessionID, lastEventID string) []sessionEvent {
	h.mu.RLock()
	defer h.mu.RUnlock()
	events := h.events[sessionID]
	if len(events) == 0 {
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
	defer h.mu.Unlock()
	if _, ok := h.subs[sessionID]; !ok {
		h.subs[sessionID] = make(map[*sseSubscriber]struct{})
	}
	h.subs[sessionID][sub] = struct{}{}
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
	defer h.mu.Unlock()
	if subs, ok := h.subs[sessionID]; ok {
		delete(subs, sub)
		if len(subs) == 0 {
			delete(h.subs, sessionID)
		}
	}
}

// evictSubscribersByUID evicts all SSE subscribers for the given UID on sessions
// associated with the given device.
// Must be called while holding h.mu.Lock (write lock).
func (h *Handler) evictSubscribersByUID(uid, deviceID string) {
	for sid, subs := range h.subs {
		state, ok := h.sessions[sid]
		if !ok || state == nil {
			continue
		}
		// state.DeviceID is immutable after session creation.
		if state.DeviceID != deviceID {
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
