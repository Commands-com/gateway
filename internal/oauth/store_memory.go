package oauth

import (
	"sync"
	"time"
)

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
	Subject     string
	Email       string
	DisplayName string
	Scope       string
	ExpiresAt   int64
}

type memoryStore struct {
	mu           sync.Mutex
	authCodes    map[string]authorizationCodeRecord
	refreshToken map[string]refreshTokenRecord
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		authCodes:    make(map[string]authorizationCodeRecord),
		refreshToken: make(map[string]refreshTokenRecord),
	}
}

func (s *memoryStore) putAuthCode(code string, rec authorizationCodeRecord, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec.ExpiresAt = time.Now().UTC().Add(ttl).Unix()
	s.authCodes[code] = rec
}

func (s *memoryStore) consumeAuthCode(code string) (authorizationCodeRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.authCodes[code]
	if !ok {
		return authorizationCodeRecord{}, false
	}
	delete(s.authCodes, code)
	if rec.ExpiresAt > 0 && time.Now().UTC().Unix() > rec.ExpiresAt {
		return authorizationCodeRecord{}, false
	}
	return rec, true
}

func (s *memoryStore) putRefreshToken(token string, rec refreshTokenRecord, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec.ExpiresAt = time.Now().UTC().Add(ttl).Unix()
	s.refreshToken[token] = rec
}

func (s *memoryStore) getRefreshToken(token string) (refreshTokenRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.refreshToken[token]
	if !ok {
		return refreshTokenRecord{}, false
	}
	if rec.ExpiresAt > 0 && time.Now().UTC().Unix() > rec.ExpiresAt {
		delete(s.refreshToken, token)
		return refreshTokenRecord{}, false
	}
	return rec, true
}

func (s *memoryStore) deleteRefreshToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.refreshToken, token)
}
