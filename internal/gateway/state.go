package gateway

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"oss-commands-gateway/internal/config"
)

const (
	defaultInviteTTLSeconds  int64 = 7 * 24 * 60 * 60
	maxInviteTTLSeconds      int64 = 90 * 24 * 60 * 60
	maxEventBacklog                = 1000
	maxInflightRequests            = 1000
	sessionSweepInterval           = 5 * time.Minute
	sessionMaxIdleAge              = 24 * time.Hour
	presenceTTL                    = 60 * time.Second
	presenceRenewInterval          = 20 * time.Second
	presenceLastSeenDebounce       = 30 * time.Second
	presenceStoreTimeout           = 2 * time.Second
	deviceBusPublishTimeout        = 250 * time.Millisecond
)

type Handler struct {
	cfg *config.Config

	// Protects handler-local volatile state (agents, tunnels, inflight, subs).
	mu             *sync.RWMutex
	store          StateStore
	bus            MessageBus
	nodeID         string
	subs           map[string]map[*sseSubscriber]struct{}
	sessionBusSubs map[string]*sessionBusSub

	agents                map[string]*agentConn
	agentConnCountByOwner map[string]int

	tunnelConns            map[string]*tunnelConn
	tunnelConnCountByOwner map[string]int
	inflightRequests       map[string]*inflightRequest

	transportTokenIssuer *TransportTokenIssuer
	transportTokenTTL    time.Duration

	agentWriteFn  func(*agentConn, map[string]any) error
	tunnelWriteFn func(*tunnelConn, map[string]any) error

	// deviceStateNotify is closed-and-replaced whenever an agent connects or
	// disconnects, waking any device-events SSE streams to re-check state.
	deviceStateNotify chan struct{}

	done chan struct{} // closed on Shutdown to stop background goroutines
}

type deviceRecord struct {
	DeviceID    string
	DisplayName string
	OwnerUID    string
	OwnerEmail  string
	IdentityKey string
	UpdatedAt   int64

	// Connection presence — written by SetDeviceOnline/SetDeviceOffline.
	Connected         bool
	ConnectedNodeID   string
	ConnectedAt       int64
	LastSeenAt        int64
	PresenceExpiresAt int64
}

type shareGrant struct {
	GrantID              string `json:"grantId"`
	DeviceID             string `json:"deviceId"`
	OwnerUID             string `json:"ownerUid"`
	OwnerEmail           string `json:"ownerEmail,omitempty"`
	GranteeUID           string `json:"granteeUid,omitempty"`
	GranteeEmail         string `json:"granteeEmail"`
	GranteeDeviceID      string `json:"granteeDeviceId,omitempty"`
	Role                 string `json:"role"`
	Status               string `json:"status"`
	InviteTokenHash      string `json:"inviteTokenHash"`
	InviteTokenExpiresAt int64  `json:"inviteTokenExpiresAt"`
	GrantExpiresAt       int64  `json:"grantExpiresAt"`
	AcceptedAt           int64  `json:"acceptedAt,omitempty"`
	RevokedAt            int64  `json:"revokedAt,omitempty"`
	RevokedByUID         string `json:"revokedByUid,omitempty"`
	CreatedAt            int64  `json:"createdAt"`
	UpdatedAt            int64  `json:"updatedAt"`
}

type sessionState struct {
	SessionID      string
	HandshakeID    string
	DeviceID       string
	OwnerUID       string
	ConversationID string
	Version        int64

	CreatedAt int64

	ClientEphemeralPublicKey string
	ClientSessionNonce       string
	AgentEphemeralPublicKey  string
	AgentIdentitySignature   string
	TranscriptHash           string
	LastError                string
	SeqClientToAgent         int
	SeqAgentToClient         int
	Status                   string
	UpdatedAt                int64
}

type sessionEvent struct {
	ID   string
	Data []byte

	// OriginNodeID is set when publishing to the MessageBus so receivers
	// can skip events that originated on their own node.  It is not
	// persisted by the store — only used in bus transit.
	OriginNodeID string
}

type putDeviceIdentityKeyRequest struct {
	Algorithm       string `json:"algorithm"`
	PublicKey       string `json:"public_key"`
	LegacyPublicKey string `json:"identityKey"`
	SnakePublicKey  string `json:"identity_key"`
	DisplayName     string `json:"display_name"`
}

type createShareInviteRequest struct {
	DeviceID              string `json:"deviceId"`
	Email                 string `json:"email"`
	GrantExpiresAt        int64  `json:"grantExpiresAt"`
	InviteTokenTtlSeconds int64  `json:"inviteTokenTtlSeconds"`
}

type acceptShareInviteRequest struct {
	Token    string `json:"token"`
	DeviceID string `json:"deviceId"`
}

type HandlerOptions struct {
	Store  StateStore
	Bus    MessageBus
	NodeID string
}

func NewHandler(cfg *config.Config) *Handler {
	return NewHandlerWithOptions(cfg, HandlerOptions{})
}

func NewHandlerWithOptions(cfg *config.Config, opts HandlerOptions) *Handler {
	transportTokenTTL := cfg.TransportTokenTTL
	if transportTokenTTL <= 0 {
		transportTokenTTL = time.Hour
	}
	var transportTokenIssuer *TransportTokenIssuer
	if strings.TrimSpace(cfg.TransportTokenSecret) != "" {
		transportTokenIssuer = NewTransportTokenIssuer(cfg.TransportTokenSecret)
	}

	store := opts.Store
	if store == nil {
		store = NewInMemoryStateStore()
	}
	bus := opts.Bus
	if bus == nil {
		bus = NewInMemoryMessageBus()
	}
	nodeID := strings.TrimSpace(opts.NodeID)
	if nodeID == "" {
		nodeID = "node-local"
	}

	h := &Handler{
		cfg:                    cfg,
		mu:                     &sync.RWMutex{},
		store:                  store,
		bus:                    bus,
		nodeID:                 nodeID,
		subs:                   make(map[string]map[*sseSubscriber]struct{}),
		sessionBusSubs:         make(map[string]*sessionBusSub),
		agents:                 make(map[string]*agentConn),
		agentConnCountByOwner:  make(map[string]int),
		tunnelConns:            make(map[string]*tunnelConn),
		tunnelConnCountByOwner: make(map[string]int),
		inflightRequests:       make(map[string]*inflightRequest),
		transportTokenIssuer:   transportTokenIssuer,
		transportTokenTTL:      transportTokenTTL,
		deviceStateNotify:      make(chan struct{}),
		done:                   make(chan struct{}),
	}

	h.agentWriteFn = func(ac *agentConn, payload map[string]any) error {
		return ac.writeJSON(payload)
	}
	h.tunnelWriteFn = func(tc *tunnelConn, payload map[string]any) error {
		return tc.writeJSON(payload)
	}
	h.startInflightSweeper()
	h.startSessionSweeper()
	return h
}

func (h *Handler) startSessionSweeper() {
	go func() {
		ticker := time.NewTicker(sessionSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-h.done:
				return
			case now := <-ticker.C:
				h.sweepStaleSessions(now.UTC())
			}
		}
	}()
}

func (h *Handler) sweepStaleSessions(now time.Time) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-h.done:
			cancel()
		case <-ctx.Done():
		}
	}()

	// Sweep expired idempotency keys if the store supports it.
	if sweeper, ok := h.store.(IdempotencyKeySweeper); ok {
		if err := sweeper.SweepExpiredIdempotencyKeys(ctx); err != nil {
			slog.Warn("idempotency key sweep failed", "err", err)
		}
	}

	cutoff := now.Add(-sessionMaxIdleAge).Unix()
	sessions, err := h.store.ListStaleSessions(ctx, cutoff)
	if err != nil {
		return
	}
	for _, sess := range sessions {
		if sess == nil {
			continue
		}
		// Don't reap sessions whose agent is still connected — the
		// handshake may still complete (pending) or the session may
		// still be in active use (acknowledged).
		if sess.DeviceID != "" {
			switch sess.Status {
			case "agent_acknowledged", "pending_agent_ack", "pending_agent_connection":
				dev, found, err := h.store.GetDevice(ctx, sess.DeviceID)
				if err != nil {
					// Store read failed — skip this session to avoid
					// deleting an active session on a transient error.
					continue
				}
				if found && dev.Connected &&
					(dev.PresenceExpiresAt == 0 || now.Unix() <= dev.PresenceExpiresAt) {
					continue
				}
			}
		}
		_ = h.store.DeleteSessionEvents(ctx, sess.SessionID)
		_ = h.store.DeleteSession(ctx, sess.SessionID)
	}
}

// notifyDeviceStateChange wakes all local device-events SSE listeners and
// publishes to the bus so listeners on other nodes are woken too.
func (h *Handler) notifyDeviceStateChange() {
	h.mu.Lock()
	ch := h.deviceStateNotify
	h.deviceStateNotify = make(chan struct{})
	h.mu.Unlock()
	close(ch)
	pubCtx, pubCancel := context.WithTimeout(context.Background(), deviceBusPublishTimeout)
	defer pubCancel()
	if err := h.bus.PublishDeviceEvent(pubCtx); err != nil {
		slog.Warn("device-state bus publish failed", "err", err)
	}
}

// Close stops background sweeper goroutines. Safe to call multiple times.
func (h *Handler) Close() {
	select {
	case <-h.done:
		// already closed
	default:
		close(h.done)
	}
}
