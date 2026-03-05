package gateway

import (
	"strings"
	"sync"
	"time"

	"oss-commands-gateway/internal/config"
)

const (
	defaultInviteTTLSeconds int64 = 7 * 24 * 60 * 60
	maxInviteTTLSeconds     int64 = 90 * 24 * 60 * 60
	maxEventBacklog               = 1000
	maxInflightRequests           = 1000
)

type Handler struct {
	cfg *config.Config

	// Protects handler-local volatile state (agents, tunnels, inflight, subs).
	mu     *sync.RWMutex
	store  StateStore
	bus    MessageBus
	nodeID string
	subs   map[string]map[*sseSubscriber]struct{}

	agents map[string]*agentConn

	tunnelConns      map[string]*tunnelConn
	inflightRequests map[string]*inflightRequest

	idempotencyMu   sync.Mutex
	idempotencyKeys map[string]time.Time

	transportTokenIssuer *TransportTokenIssuer
	transportTokenTTL    time.Duration

	agentWriteFn  func(*agentConn, map[string]any) error
	tunnelWriteFn func(*tunnelConn, map[string]any) error

	done chan struct{} // closed on Shutdown to stop background goroutines
}

type deviceRecord struct {
	DeviceID    string
	OwnerUID    string
	OwnerEmail  string
	IdentityKey string
	UpdatedAt   int64
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
}

type putDeviceIdentityKeyRequest struct {
	IdentityKey string `json:"identityKey"`
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
		cfg:                  cfg,
		mu:                   &sync.RWMutex{},
		store:                store,
		bus:                  bus,
		nodeID:               nodeID,
		subs:                 make(map[string]map[*sseSubscriber]struct{}),
		agents:               make(map[string]*agentConn),
		tunnelConns:          make(map[string]*tunnelConn),
		inflightRequests:     make(map[string]*inflightRequest),
		idempotencyKeys:      make(map[string]time.Time),
		transportTokenIssuer: transportTokenIssuer,
		transportTokenTTL:    transportTokenTTL,
		done:                 make(chan struct{}),
	}

	h.agentWriteFn = func(ac *agentConn, payload map[string]any) error {
		return ac.writeJSON(payload)
	}
	h.tunnelWriteFn = func(tc *tunnelConn, payload map[string]any) error {
		return tc.writeJSON(payload)
	}
	h.startInflightSweeper()
	h.startIdempotencySweeper()
	return h
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
