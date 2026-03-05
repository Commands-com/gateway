package gateway

import (
	"bufio"
	"strconv"
)

func (h *Handler) appendSessionEvent(sessionID string, payload []byte) string {
	h.mu.Lock()
	h.eventSeq++
	event := sessionEvent{ID: strconv.FormatInt(h.eventSeq, 10), Data: payload}
	h.events[sessionID] = append(h.events[sessionID], event)
	if len(h.events[sessionID]) > maxEventBacklog {
		h.events[sessionID] = h.events[sessionID][len(h.events[sessionID])-maxEventBacklog:]
	}
	subscribers := make([]chan sessionEvent, 0, len(h.subs[sessionID]))
	for ch := range h.subs[sessionID] {
		subscribers = append(subscribers, ch)
	}
	h.mu.Unlock()

	for _, ch := range subscribers {
		select {
		case ch <- event:
		default:
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

func (h *Handler) subscribe(sessionID string) chan sessionEvent {
	ch := make(chan sessionEvent, 64)
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.subs[sessionID]; !ok {
		h.subs[sessionID] = make(map[chan sessionEvent]struct{})
	}
	h.subs[sessionID][ch] = struct{}{}
	return ch
}

func (h *Handler) unsubscribe(sessionID string, ch chan sessionEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if subs, ok := h.subs[sessionID]; ok {
		delete(subs, ch)
		if len(subs) == 0 {
			delete(h.subs, sessionID)
		}
	}
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
