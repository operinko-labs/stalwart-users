package auth

import (
	"sync"
	"time"

	"github.com/operinko-labs/stalwart-users/internal/oidc"
)

// TokenStore keeps each session's OAuth tokens in memory, keyed by session id.
// Tokens never leave the server; a restart forgets them.
type TokenStore struct {
	mu      sync.Mutex
	entries map[string]storedTokens
	now     func() time.Time
}

type storedTokens struct {
	tokens oidc.Tokens
	stored time.Time
}

func NewTokenStore() *TokenStore {
	return &TokenStore{entries: map[string]storedTokens{}, now: time.Now}
}

// Put stores t for sessionID, replacing what was there. It also drops entries
// older than a session can live, so sessions that never log out don't pile up.
func (s *TokenStore) Put(sessionID string, t oidc.Tokens) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	for id, e := range s.entries {
		if now.Sub(e.stored) > tokenTTL {
			delete(s.entries, id)
		}
	}
	s.entries[sessionID] = storedTokens{tokens: t, stored: now}
}

func (s *TokenStore) Get(sessionID string) (oidc.Tokens, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.entries[sessionID]
	if !ok || s.now().Sub(e.stored) > tokenTTL {
		return oidc.Tokens{}, false
	}
	return e.tokens, true
}

func (s *TokenStore) Delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.entries, sessionID)
}
