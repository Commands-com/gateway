package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"
)

const oauthSweepInterval = 5 * time.Minute

type authorizationCodeRecord struct {
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Subject             string
	Email               string
	DisplayName         string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           int64
}

type refreshTokenRecord struct {
	ClientID    string
	Subject     string
	Email       string
	DisplayName string
	Scope       string
	ExpiresAt   int64
	FamilyID    string
}

// consumedTokenTombstone records the family ID and expiry of a consumed
// refresh token so that post-consumption replay can still trigger family
// revocation.
type consumedTokenTombstone struct {
	FamilyID  string
	ExpiresAt int64
}

type memoryStore struct {
	mu             sync.Mutex
	authCodes      map[string]authorizationCodeRecord
	refreshToken   map[string]refreshTokenRecord
	consumedTokens map[string]consumedTokenTombstone // tokenHash → tombstone
	done           chan struct{}
}

func newMemoryStore() *memoryStore {
	s := &memoryStore{
		authCodes:      make(map[string]authorizationCodeRecord),
		refreshToken:   make(map[string]refreshTokenRecord),
		consumedTokens: make(map[string]consumedTokenTombstone),
		done:           make(chan struct{}),
	}
	go s.sweepExpired()
	return s
}

func (s *memoryStore) sweepExpired() {
	ticker := time.NewTicker(oauthSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case now := <-ticker.C:
			nowUnix := now.UTC().Unix()
			s.mu.Lock()
			for code, rec := range s.authCodes {
				if rec.ExpiresAt > 0 && nowUnix > rec.ExpiresAt {
					delete(s.authCodes, code)
				}
			}
			for token, rec := range s.refreshToken {
				if rec.ExpiresAt > 0 && nowUnix > rec.ExpiresAt {
					delete(s.refreshToken, token)
				}
			}
			for h, tomb := range s.consumedTokens {
				if tomb.ExpiresAt > 0 && nowUnix > tomb.ExpiresAt {
					delete(s.consumedTokens, h)
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *memoryStore) close() {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
}

func (s *memoryStore) putAuthCode(code string, rec authorizationCodeRecord, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec.ExpiresAt = time.Now().UTC().Add(ttl).Unix()
	s.authCodes[code] = rec
	return nil
}

func (s *memoryStore) getAuthCode(code string) (authorizationCodeRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.authCodes[code]
	if !ok {
		return authorizationCodeRecord{}, false, nil
	}
	if rec.ExpiresAt > 0 && time.Now().UTC().Unix() > rec.ExpiresAt {
		delete(s.authCodes, code)
		return authorizationCodeRecord{}, false, nil
	}
	return rec, true, nil
}

func (s *memoryStore) consumeAuthCode(code string) (authorizationCodeRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.authCodes[code]
	if !ok {
		return authorizationCodeRecord{}, false, nil
	}
	delete(s.authCodes, code)
	if rec.ExpiresAt > 0 && time.Now().UTC().Unix() > rec.ExpiresAt {
		return authorizationCodeRecord{}, false, nil
	}
	return rec, true, nil
}

func hashRefreshToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *memoryStore) putRefreshToken(token string, rec refreshTokenRecord, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec.ExpiresAt = time.Now().UTC().Add(ttl).Unix()
	s.refreshToken[hashRefreshToken(token)] = rec
	return nil
}

func (s *memoryStore) getRefreshToken(token string) (refreshTokenRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := hashRefreshToken(token)
	rec, ok := s.refreshToken[h]
	if !ok {
		return refreshTokenRecord{}, false, nil
	}
	if rec.ExpiresAt > 0 && time.Now().UTC().Unix() > rec.ExpiresAt {
		delete(s.refreshToken, h)
		return refreshTokenRecord{}, false, nil
	}
	return rec, true, nil
}

func (s *memoryStore) consumeRefreshToken(token string, familyID string, tombstoneTTL time.Duration) (refreshTokenRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := hashRefreshToken(token)
	rec, ok := s.refreshToken[h]
	if !ok {
		return refreshTokenRecord{}, false, nil
	}
	delete(s.refreshToken, h)
	if rec.ExpiresAt > 0 && time.Now().UTC().Unix() > rec.ExpiresAt {
		return refreshTokenRecord{}, false, nil
	}
	// Atomically write the consumed-token tombstone under the same lock
	// so there is no window where the token is deleted but the tombstone
	// is not yet present. This ensures post-consumption replay always
	// finds the family ID for revocation.
	tombFamily := familyID
	if tombFamily == "" {
		tombFamily = rec.FamilyID
	}
	if tombFamily != "" && tombstoneTTL > 0 {
		s.consumedTokens[h] = consumedTokenTombstone{
			FamilyID:  tombFamily,
			ExpiresAt: time.Now().UTC().Add(tombstoneTTL).Unix(),
		}
	}
	return rec, true, nil
}

func (s *memoryStore) deleteRefreshToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.refreshToken, hashRefreshToken(token))
}

func (s *memoryStore) deleteRefreshTokensByFamily(familyID string) {
	if familyID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for h, rec := range s.refreshToken {
		if rec.FamilyID == familyID {
			delete(s.refreshToken, h)
		}
	}
}

func (s *memoryStore) getConsumedTokenFamily(tokenHash string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tomb, ok := s.consumedTokens[tokenHash]
	if !ok {
		return "", false, nil
	}
	if tomb.ExpiresAt > 0 && time.Now().UTC().Unix() > tomb.ExpiresAt {
		delete(s.consumedTokens, tokenHash)
		return "", false, nil
	}
	return tomb.FamilyID, true, nil
}
