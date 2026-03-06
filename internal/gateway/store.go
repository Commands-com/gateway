package gateway

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"
)

type RouteLease struct {
	RouteID   string
	NodeID    string
	ExpiresAt time.Time
}

type SessionMutator func(*sessionState) error
type IntegrationRouteMutator func(*integrationRoute) error

var (
	ErrSessionNotFound        = errors.New("session_not_found")
	ErrSessionVersionConflict = errors.New("session_version_conflict")
	ErrRouteNotFound          = errors.New("route_not_found")
	ErrRouteVersionConflict   = errors.New("route_version_conflict")
)

type StateStore interface {
	// Devices
	SaveDevice(ctx context.Context, dev deviceRecord) error
	GetDevice(ctx context.Context, deviceID string) (deviceRecord, bool, error)

	// Sessions
	CreateSession(ctx context.Context, sess *sessionState) (bool, error)
	SaveSession(ctx context.Context, sess *sessionState) error
	GetSession(ctx context.Context, sessionID string) (*sessionState, bool, error)
	UpdateSession(ctx context.Context, sessionID string, mutateFn SessionMutator) (*sessionState, error)
	ListSessions(ctx context.Context) ([]*sessionState, error)
	ListSessionsByDevice(ctx context.Context, deviceID string) ([]*sessionState, error)

	// Share grants and invite token mappings
	SaveShareGrant(ctx context.Context, grant *shareGrant) error
	GetShareGrant(ctx context.Context, grantID string) (*shareGrant, bool, error)
	ListShareGrants(ctx context.Context) ([]*shareGrant, error)
	ListShareGrantsByDevice(ctx context.Context, deviceID string) ([]*shareGrant, error)
	ListAllShareGrantsByDevice(ctx context.Context, deviceID string) ([]*shareGrant, error)
	DeleteShareGrantFromDeviceIndex(ctx context.Context, deviceID, grantID string) error
	SaveInviteGrantMapping(ctx context.Context, tokenHash, grantID string) error
	GetInviteGrantID(ctx context.Context, tokenHash string) (string, bool, error)
	DeleteInviteGrantMapping(ctx context.Context, tokenHash string) error

	// Integration routes
	SaveIntegrationRoute(ctx context.Context, route *integrationRoute) error
	GetIntegrationRoute(ctx context.Context, routeID string) (*integrationRoute, bool, error)
	UpdateIntegrationRoute(ctx context.Context, routeID string, mutateFn IntegrationRouteMutator) (*integrationRoute, error)
	SetIntegrationRouteStatus(ctx context.Context, routeID string, status string, updatedAt string) error
	DeleteIntegrationRoute(ctx context.Context, routeID string) error
	TouchIntegrationRouteLastUsed(ctx context.Context, routeID string, ts string) error
	ListIntegrationRoutesByOwner(ctx context.Context, ownerUID string) ([]*integrationRoute, error)
	SetActiveRouteDevice(ctx context.Context, routeID, deviceID string) error
	GetActiveRouteDevice(ctx context.Context, routeID string) (string, bool, error)
	DeleteActiveRoute(ctx context.Context, routeID string) error

	// Session events
	AppendSessionEvent(ctx context.Context, sessionID string, payload []byte, maxBacklog int) (sessionEvent, error)
	ListSessionEvents(ctx context.Context, sessionID string) ([]sessionEvent, error)

	// Route lease ownership (for multi-node ingress/tunnel routing).
	ClaimRouteLease(ctx context.Context, routeID, nodeID string, ttl time.Duration) (RouteLease, bool, error)
	RenewRouteLease(ctx context.Context, routeID, nodeID string, ttl time.Duration) (RouteLease, bool, error)
	GetRouteLease(ctx context.Context, routeID string) (RouteLease, bool, error)
	ReleaseRouteLease(ctx context.Context, routeID, nodeID string) error

	// Device counting by owner (for limits).
	CountDevicesByOwner(ctx context.Context, ownerUID string) (int, error)

	// Metrics / health counters.
	CountDevices(ctx context.Context) (int, error)
	CountShareGrants(ctx context.Context) (int, error)
	CountSessions(ctx context.Context) (int, error)
	CountIntegrationRoutes(ctx context.Context) (int, error)
	CountSessionEventBacklogs(ctx context.Context) (int, error)
}

type InMemoryStateStore struct {
	mu sync.RWMutex

	devices        map[string]deviceRecord
	grants         map[string]*shareGrant
	grantsByDevice map[string][]*shareGrant
	inviteToID     map[string]string
	sessions       map[string]*sessionState

	integrationRoutes        map[string]*integrationRoute
	integrationRouteOwnerIDs map[string]map[string]struct{}
	activeRoutes             map[string]string

	events   map[string][]sessionEvent
	eventSeq int64

	routeLeases map[string]RouteLease
}

func NewInMemoryStateStore() *InMemoryStateStore {
	return &InMemoryStateStore{
		devices:                  make(map[string]deviceRecord),
		grants:                   make(map[string]*shareGrant),
		grantsByDevice:           make(map[string][]*shareGrant),
		inviteToID:               make(map[string]string),
		sessions:                 make(map[string]*sessionState),
		integrationRoutes:        make(map[string]*integrationRoute),
		integrationRouteOwnerIDs: make(map[string]map[string]struct{}),
		activeRoutes:             make(map[string]string),
		events:                   make(map[string][]sessionEvent),
		routeLeases:              make(map[string]RouteLease),
	}
}

func (s *InMemoryStateStore) SaveDevice(_ context.Context, dev deviceRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[dev.DeviceID] = dev
	return nil
}

func (s *InMemoryStateStore) GetDevice(_ context.Context, deviceID string) (deviceRecord, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	dev, ok := s.devices[deviceID]
	return dev, ok, nil
}

func (s *InMemoryStateStore) CreateSession(_ context.Context, sess *sessionState) (bool, error) {
	if sess == nil || sess.SessionID == "" {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sessions[sess.SessionID]; exists {
		return false, nil
	}
	next := cloneSessionState(sess)
	if next.Version <= 0 {
		next.Version = 1
	}
	s.sessions[sess.SessionID] = next
	return true, nil
}

func (s *InMemoryStateStore) SaveSession(_ context.Context, sess *sessionState) error {
	if sess == nil || sess.SessionID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	current, exists := s.sessions[sess.SessionID]
	next := cloneSessionState(sess)
	if exists && current != nil {
		if sess.Version <= 0 || sess.Version != current.Version {
			return ErrSessionVersionConflict
		}
		next.Version = current.Version + 1
	} else if next.Version <= 0 {
		next.Version = 1
	}
	s.sessions[sess.SessionID] = next
	return nil
}

func (s *InMemoryStateStore) GetSession(_ context.Context, sessionID string) (*sessionState, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[sessionID]
	if !ok || sess == nil {
		return nil, false, nil
	}
	return cloneSessionState(sess), true, nil
}

func (s *InMemoryStateStore) UpdateSession(_ context.Context, sessionID string, mutateFn SessionMutator) (*sessionState, error) {
	if mutateFn == nil {
		return nil, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	current, ok := s.sessions[sessionID]
	if !ok || current == nil {
		return nil, ErrSessionNotFound
	}

	working := cloneSessionState(current)
	baseVersion := working.Version
	if baseVersion <= 0 {
		baseVersion = 1
	}
	working.Version = baseVersion

	if err := mutateFn(working); err != nil {
		return nil, err
	}
	if current.Version != baseVersion {
		return nil, ErrSessionVersionConflict
	}

	working.Version = baseVersion + 1
	s.sessions[sessionID] = working
	return cloneSessionState(working), nil
}

func (s *InMemoryStateStore) ListSessions(_ context.Context) ([]*sessionState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*sessionState, 0, len(s.sessions))
	for _, sess := range s.sessions {
		if sess == nil {
			continue
		}
		out = append(out, cloneSessionState(sess))
	}
	return out, nil
}

func (s *InMemoryStateStore) ListSessionsByDevice(_ context.Context, deviceID string) ([]*sessionState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*sessionState, 0)
	for _, sess := range s.sessions {
		if sess == nil || sess.DeviceID != deviceID {
			continue
		}
		out = append(out, cloneSessionState(sess))
	}
	return out, nil
}

func (s *InMemoryStateStore) SaveShareGrant(_ context.Context, grant *shareGrant) error {
	if grant == nil || grant.GrantID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	stored := cloneShareGrant(grant)
	old, hadOld := s.grants[grant.GrantID]
	s.grants[grant.GrantID] = stored
	s.rebuildGrantsByDeviceLocked(stored.DeviceID)
	if hadOld && old != nil && old.DeviceID != "" && old.DeviceID != stored.DeviceID {
		s.rebuildGrantsByDeviceLocked(old.DeviceID)
	}
	return nil
}

func (s *InMemoryStateStore) GetShareGrant(_ context.Context, grantID string) (*shareGrant, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	grant, ok := s.grants[grantID]
	if !ok || grant == nil {
		return nil, false, nil
	}
	return cloneShareGrant(grant), true, nil
}

func (s *InMemoryStateStore) ListShareGrants(_ context.Context) ([]*shareGrant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*shareGrant, 0, len(s.grants))
	for _, grant := range s.grants {
		if grant == nil {
			continue
		}
		out = append(out, cloneShareGrant(grant))
	}
	return out, nil
}

func (s *InMemoryStateStore) ListShareGrantsByDevice(_ context.Context, deviceID string) ([]*shareGrant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	grants := s.grantsByDevice[deviceID]
	out := make([]*shareGrant, 0, len(grants))
	for _, grant := range grants {
		if grant == nil {
			continue
		}
		out = append(out, cloneShareGrant(grant))
	}
	return out, nil
}

// ListAllShareGrantsByDevice returns all grants for a device from the main grants map,
// including revoked/expired ones that have been removed from the device index.
func (s *InMemoryStateStore) ListAllShareGrantsByDevice(_ context.Context, deviceID string) ([]*shareGrant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*shareGrant, 0)
	for _, grant := range s.grants {
		if grant == nil || grant.DeviceID != deviceID {
			continue
		}
		out = append(out, cloneShareGrant(grant))
	}
	return out, nil
}

func (s *InMemoryStateStore) DeleteShareGrantFromDeviceIndex(_ context.Context, deviceID, grantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if deviceID == "" || grantID == "" {
		return nil
	}
	grants := s.grantsByDevice[deviceID]
	if len(grants) == 0 {
		return nil
	}
	filtered := grants[:0]
	for _, grant := range grants {
		if grant == nil || grant.GrantID == grantID {
			continue
		}
		filtered = append(filtered, grant)
	}
	if len(filtered) == 0 {
		delete(s.grantsByDevice, deviceID)
		return nil
	}
	s.grantsByDevice[deviceID] = filtered
	return nil
}

func (s *InMemoryStateStore) SaveInviteGrantMapping(_ context.Context, tokenHash, grantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inviteToID[tokenHash] = grantID
	return nil
}

func (s *InMemoryStateStore) GetInviteGrantID(_ context.Context, tokenHash string) (string, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	grantID, ok := s.inviteToID[tokenHash]
	return grantID, ok, nil
}

func (s *InMemoryStateStore) DeleteInviteGrantMapping(_ context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inviteToID, tokenHash)
	return nil
}

func (s *InMemoryStateStore) SaveIntegrationRoute(_ context.Context, route *integrationRoute) error {
	if route == nil || route.RouteID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	stored := cloneIntegrationRoute(route)
	old, hadOld := s.integrationRoutes[stored.RouteID]
	if hadOld && old != nil {
		if stored.Version <= 0 || stored.Version != old.Version {
			return ErrRouteVersionConflict
		}
		stored.Version = old.Version + 1
	} else if stored.Version <= 0 {
		stored.Version = 1
	}
	s.integrationRoutes[stored.RouteID] = stored
	if stored.OwnerUID != "" {
		if _, ok := s.integrationRouteOwnerIDs[stored.OwnerUID]; !ok {
			s.integrationRouteOwnerIDs[stored.OwnerUID] = make(map[string]struct{})
		}
		s.integrationRouteOwnerIDs[stored.OwnerUID][stored.RouteID] = struct{}{}
	}
	if hadOld && old != nil && old.OwnerUID != "" && old.OwnerUID != stored.OwnerUID {
		if ownerRoutes, ok := s.integrationRouteOwnerIDs[old.OwnerUID]; ok {
			delete(ownerRoutes, stored.RouteID)
			if len(ownerRoutes) == 0 {
				delete(s.integrationRouteOwnerIDs, old.OwnerUID)
			}
		}
	}
	return nil
}

func (s *InMemoryStateStore) UpdateIntegrationRoute(_ context.Context, routeID string, mutateFn IntegrationRouteMutator) (*integrationRoute, error) {
	if mutateFn == nil {
		return nil, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	current, ok := s.integrationRoutes[routeID]
	if !ok || current == nil {
		return nil, ErrRouteNotFound
	}

	working := cloneIntegrationRoute(current)
	baseVersion := working.Version
	if baseVersion <= 0 {
		baseVersion = 1
	}
	working.Version = baseVersion

	if err := mutateFn(working); err != nil {
		return nil, err
	}
	if current.Version != baseVersion {
		return nil, ErrRouteVersionConflict
	}

	working.Version = baseVersion + 1
	s.integrationRoutes[routeID] = working
	// Update owner index if owner changed
	if current.OwnerUID != working.OwnerUID {
		if current.OwnerUID != "" {
			if ownerRoutes, has := s.integrationRouteOwnerIDs[current.OwnerUID]; has {
				delete(ownerRoutes, routeID)
				if len(ownerRoutes) == 0 {
					delete(s.integrationRouteOwnerIDs, current.OwnerUID)
				}
			}
		}
		if working.OwnerUID != "" {
			if _, has := s.integrationRouteOwnerIDs[working.OwnerUID]; !has {
				s.integrationRouteOwnerIDs[working.OwnerUID] = make(map[string]struct{})
			}
			s.integrationRouteOwnerIDs[working.OwnerUID][routeID] = struct{}{}
		}
	}
	return cloneIntegrationRoute(working), nil
}

func (s *InMemoryStateStore) SetIntegrationRouteStatus(_ context.Context, routeID string, status string, updatedAt string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	route, ok := s.integrationRoutes[routeID]
	if !ok || route == nil {
		return nil
	}
	route.Status = status
	route.UpdatedAt = updatedAt
	route.Version++
	return nil
}

func (s *InMemoryStateStore) GetIntegrationRoute(_ context.Context, routeID string) (*integrationRoute, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	route, ok := s.integrationRoutes[routeID]
	if !ok || route == nil {
		return nil, false, nil
	}
	return cloneIntegrationRoute(route), true, nil
}

func (s *InMemoryStateStore) DeleteIntegrationRoute(_ context.Context, routeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	route, ok := s.integrationRoutes[routeID]
	if !ok {
		return nil
	}
	delete(s.integrationRoutes, routeID)
	delete(s.activeRoutes, routeID)
	delete(s.routeLeases, routeID)
	if route.OwnerUID != "" {
		if ownerRoutes, hasOwner := s.integrationRouteOwnerIDs[route.OwnerUID]; hasOwner {
			delete(ownerRoutes, routeID)
			if len(ownerRoutes) == 0 {
				delete(s.integrationRouteOwnerIDs, route.OwnerUID)
			}
		}
	}
	return nil
}

func (s *InMemoryStateStore) ListIntegrationRoutesByOwner(_ context.Context, ownerUID string) ([]*integrationRoute, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := s.integrationRouteOwnerIDs[ownerUID]
	out := make([]*integrationRoute, 0, len(ids))
	for routeID := range ids {
		route := s.integrationRoutes[routeID]
		if route == nil {
			continue
		}
		out = append(out, cloneIntegrationRoute(route))
	}
	return out, nil
}

func (s *InMemoryStateStore) TouchIntegrationRouteLastUsed(_ context.Context, routeID string, ts string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	route, ok := s.integrationRoutes[routeID]
	if !ok || route == nil {
		return nil
	}
	route.TokenLastUsedAt = ts
	route.UpdatedAt = ts
	return nil
}

func (s *InMemoryStateStore) SetActiveRouteDevice(_ context.Context, routeID, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeRoutes[routeID] = deviceID
	return nil
}

func (s *InMemoryStateStore) GetActiveRouteDevice(_ context.Context, routeID string) (string, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	deviceID, ok := s.activeRoutes[routeID]
	return deviceID, ok, nil
}

func (s *InMemoryStateStore) DeleteActiveRoute(_ context.Context, routeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.activeRoutes, routeID)
	return nil
}

func (s *InMemoryStateStore) AppendSessionEvent(_ context.Context, sessionID string, payload []byte, maxBacklog int) (sessionEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventSeq++
	event := sessionEvent{ID: strconv.FormatInt(s.eventSeq, 10), Data: payload}
	s.events[sessionID] = append(s.events[sessionID], event)
	if maxBacklog > 0 && len(s.events[sessionID]) > maxBacklog {
		s.events[sessionID] = s.events[sessionID][len(s.events[sessionID])-maxBacklog:]
	}
	return event, nil
}

func (s *InMemoryStateStore) ListSessionEvents(_ context.Context, sessionID string) ([]sessionEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	events := s.events[sessionID]
	out := make([]sessionEvent, len(events))
	copy(out, events)
	return out, nil
}

func (s *InMemoryStateStore) ClaimRouteLease(_ context.Context, routeID, nodeID string, ttl time.Duration) (RouteLease, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ttl <= 0 {
		ttl = 15 * time.Second
	}
	now := time.Now().UTC()
	current, exists := s.routeLeases[routeID]
	if exists && now.Before(current.ExpiresAt) && current.NodeID != nodeID {
		return current, false, nil
	}
	lease := RouteLease{
		RouteID:   routeID,
		NodeID:    nodeID,
		ExpiresAt: now.Add(ttl),
	}
	s.routeLeases[routeID] = lease
	return lease, true, nil
}

func (s *InMemoryStateStore) RenewRouteLease(_ context.Context, routeID, nodeID string, ttl time.Duration) (RouteLease, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ttl <= 0 {
		ttl = 15 * time.Second
	}
	now := time.Now().UTC()
	current, exists := s.routeLeases[routeID]
	if !exists || current.NodeID != nodeID || now.After(current.ExpiresAt) {
		return RouteLease{}, false, nil
	}
	current.ExpiresAt = now.Add(ttl)
	s.routeLeases[routeID] = current
	return current, true, nil
}

func (s *InMemoryStateStore) GetRouteLease(_ context.Context, routeID string) (RouteLease, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.routeLeases[routeID]
	if !exists {
		return RouteLease{}, false, nil
	}
	if time.Now().UTC().After(current.ExpiresAt) {
		delete(s.routeLeases, routeID)
		return RouteLease{}, false, nil
	}
	return current, true, nil
}

func (s *InMemoryStateStore) ReleaseRouteLease(_ context.Context, routeID, nodeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.routeLeases[routeID]
	if !exists {
		return nil
	}
	if current.NodeID == nodeID {
		delete(s.routeLeases, routeID)
	}
	return nil
}

func (s *InMemoryStateStore) CountDevicesByOwner(_ context.Context, ownerUID string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, dev := range s.devices {
		if dev.OwnerUID == ownerUID {
			count++
		}
	}
	return count, nil
}

func (s *InMemoryStateStore) CountDevices(_ context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.devices), nil
}

func (s *InMemoryStateStore) CountShareGrants(_ context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.grants), nil
}

func (s *InMemoryStateStore) CountSessions(_ context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions), nil
}

func (s *InMemoryStateStore) CountIntegrationRoutes(_ context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.integrationRoutes), nil
}

func (s *InMemoryStateStore) CountSessionEventBacklogs(_ context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events), nil
}

func cloneSessionState(sess *sessionState) *sessionState {
	if sess == nil {
		return nil
	}
	return &sessionState{
		SessionID:                sess.SessionID,
		HandshakeID:              sess.HandshakeID,
		DeviceID:                 sess.DeviceID,
		OwnerUID:                 sess.OwnerUID,
		ConversationID:           sess.ConversationID,
		Version:                  sess.Version,
		CreatedAt:                sess.CreatedAt,
		ClientEphemeralPublicKey: sess.ClientEphemeralPublicKey,
		ClientSessionNonce:       sess.ClientSessionNonce,
		AgentEphemeralPublicKey:  sess.AgentEphemeralPublicKey,
		AgentIdentitySignature:   sess.AgentIdentitySignature,
		TranscriptHash:           sess.TranscriptHash,
		LastError:                sess.LastError,
		SeqClientToAgent:         sess.SeqClientToAgent,
		SeqAgentToClient:         sess.SeqAgentToClient,
		Status:                   sess.Status,
		UpdatedAt:                sess.UpdatedAt,
	}
}

func cloneShareGrant(grant *shareGrant) *shareGrant {
	if grant == nil {
		return nil
	}
	cloned := *grant
	return &cloned
}

func cloneIntegrationRoute(route *integrationRoute) *integrationRoute {
	if route == nil {
		return nil
	}
	cloned := *route
	return &cloned
}

func (s *InMemoryStateStore) rebuildGrantsByDeviceLocked(deviceID string) {
	if deviceID == "" {
		return
	}
	out := make([]*shareGrant, 0)
	for _, grant := range s.grants {
		if grant == nil || grant.DeviceID != deviceID {
			continue
		}
		out = append(out, grant)
	}
	if len(out) == 0 {
		delete(s.grantsByDevice, deviceID)
		return
	}
	s.grantsByDevice[deviceID] = out
}
