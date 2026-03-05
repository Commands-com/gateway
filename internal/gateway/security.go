package gateway

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	idempotencySweepInterval = 1 * time.Minute
)

var encryptedSessionFrameTypes = map[string]bool{
	"session.progress": true,
	"session.result":   true,
	"session.error":    true,
	"session.message":  true,
}

func validateEncryptedEnvelope(frame map[string]any) string {
	encrypted, _ := frame["encrypted"].(bool)
	if !encrypted {
		return "missing_encrypted_flag"
	}
	if firstStringMap(frame, "ciphertext") == "" {
		return "missing_ciphertext"
	}
	if firstStringMap(frame, "nonce") == "" {
		return "missing_nonce"
	}
	if firstStringMap(frame, "tag") == "" {
		return "missing_tag"
	}
	if _, ok := frame["seq"]; !ok {
		return "missing_seq"
	}
	seq, ok := extractPositiveInt(frame, "seq")
	if !ok || seq < 1 {
		return "invalid_seq"
	}
	return ""
}

func extractPositiveInt(frame map[string]any, key string) (int, bool) {
	raw, ok := frame[key]
	if !ok {
		return 0, false
	}
	switch v := raw.(type) {
	case float64:
		i := int(v)
		return i, v == float64(i) && i > 0
	case int:
		return v, v > 0
	case int64:
		i := int(v)
		return i, int64(i) == v && i > 0
	case json.Number:
		i64, err := v.Int64()
		if err != nil {
			return 0, false
		}
		i := int(i64)
		return i, int64(i) == i64 && i > 0
	default:
		return 0, false
	}
}

func (h *Handler) startIdempotencySweeper() {
	go func() {
		ticker := time.NewTicker(idempotencySweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-h.done:
				return
			case now := <-ticker.C:
				h.idempotencyMu.Lock()
				h.pruneIdempotencyKeysLocked(now.UTC())
				h.idempotencyMu.Unlock()
			}
		}
	}()
}

func (h *Handler) pruneIdempotencyKeysLocked(now time.Time) {
	for key, expiry := range h.idempotencyKeys {
		if now.After(expiry) {
			delete(h.idempotencyKeys, key)
		}
	}
}

func (h *Handler) checkAndReserveIdempotencyKey(sessionID, requesterUID, idempotencyKey string, now time.Time) bool {
	h.idempotencyMu.Lock()
	defer h.idempotencyMu.Unlock()
	h.pruneIdempotencyKeysLocked(now)

	compound := fmt.Sprintf("%s:%s:%s", sessionID, requesterUID, idempotencyKey)
	if expiry, exists := h.idempotencyKeys[compound]; exists && now.Before(expiry) {
		return false
	}
	ttl := time.Duration(h.cfg.IdempotencyTTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	h.idempotencyKeys[compound] = now.Add(ttl)
	return true
}

func (h *Handler) validateAndAdvanceTransportFrame(deviceID string, connState *agentConn, frame map[string]any) string {
	if h.transportTokenIssuer == nil {
		return ""
	}
	transportToken := strings.TrimSpace(firstStringMap(frame, "transport_token"))
	if transportToken == "" {
		return "missing_transport_token"
	}
	if err := h.transportTokenIssuer.VerifyToken(transportToken, deviceID, connState.connID); err != nil {
		return err.Error()
	}

	tSeq, ok := extractPositiveInt(frame, "t_seq")
	if !ok || tSeq < 1 {
		return "invalid_t_seq"
	}
	if tSeq <= connState.lastTransportSeq {
		return "transport_replay_detected"
	}
	connState.lastTransportSeq = tSeq
	return ""
}
