package gateway

import (
	"sync"

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

	mu         sync.RWMutex
	devices    map[string]deviceRecord
	grants     map[string]*shareGrant
	inviteToID map[string]string
	sessions   map[string]*sessionState
	events     map[string][]sessionEvent
	subs       map[string]map[chan sessionEvent]struct{}
	eventSeq   int64

	agents map[string]*agentConn

	integrationRoutes        map[string]*integrationRoute
	integrationRouteOwnerIDs map[string]map[string]struct{}
	tunnelConns              map[string]*tunnelConn
	activeRoutes             map[string]string
	inflightRequests         map[string]*inflightRequest

	agentWriteFn  func(*agentConn, map[string]any) error
	tunnelWriteFn func(*tunnelConn, map[string]any) error
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
	mu             sync.RWMutex
	SessionID      string
	HandshakeID    string
	DeviceID       string
	OwnerUID       string
	ConversationID string
	Status         string
	Members        map[string]struct{}
	UpdatedAt      int64
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

type postHandshakeClientInitRequest struct {
	DeviceID string `json:"deviceId"`
}

func NewHandler(cfg *config.Config) *Handler {
	h := &Handler{
		cfg:                      cfg,
		devices:                  make(map[string]deviceRecord),
		grants:                   make(map[string]*shareGrant),
		inviteToID:               make(map[string]string),
		sessions:                 make(map[string]*sessionState),
		events:                   make(map[string][]sessionEvent),
		subs:                     make(map[string]map[chan sessionEvent]struct{}),
		agents:                   make(map[string]*agentConn),
		integrationRoutes:        make(map[string]*integrationRoute),
		integrationRouteOwnerIDs: make(map[string]map[string]struct{}),
		tunnelConns:              make(map[string]*tunnelConn),
		activeRoutes:             make(map[string]string),
		inflightRequests:         make(map[string]*inflightRequest),
	}
	h.agentWriteFn = func(ac *agentConn, payload map[string]any) error {
		return ac.writeJSON(payload)
	}
	h.tunnelWriteFn = func(tc *tunnelConn, payload map[string]any) error {
		return tc.writeJSON(payload)
	}
	h.startInflightSweeper()
	return h
}
