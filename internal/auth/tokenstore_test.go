package auth

import (
	"testing"
	"time"

	"github.com/operinko-labs/stalwart-users/internal/oidc"
)

func TestTokenStore(t *testing.T) {
	t.Parallel()

	s := NewTokenStore()
	if _, ok := s.Get("missing"); ok {
		t.Fatal("Get(missing) ok = true, want false")
	}

	first := oidc.Tokens{AccessToken: "a1", RefreshToken: "r1", ExpiresAt: time.Unix(100, 0)}
	s.Put("s1", first)
	s.Put("s2", oidc.Tokens{AccessToken: "a2"})

	if got, ok := s.Get("s1"); !ok || got != first {
		t.Fatalf("Get(s1) = %#v, %v; want %#v", got, ok, first)
	}

	replaced := oidc.Tokens{AccessToken: "a1b", RefreshToken: "r1b"}
	s.Put("s1", replaced)
	if got, ok := s.Get("s1"); !ok || got != replaced {
		t.Fatalf("Get(s1) after Put = %#v, %v; want %#v", got, ok, replaced)
	}

	s.Delete("s1")
	if _, ok := s.Get("s1"); ok {
		t.Fatal("Get(s1) ok after Delete, want false")
	}
	if got, ok := s.Get("s2"); !ok || got.AccessToken != "a2" {
		t.Fatalf("Get(s2) = %#v, %v; Delete removed the wrong entry", got, ok)
	}
	s.Delete("missing")
}

// A session can't outlive tokenTTL, so its tokens are dropped after that.
func TestTokenStoreDropsEntriesOlderThanTheSession(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	s := NewTokenStore()
	s.now = func() time.Time { return now }

	s.Put("old", oidc.Tokens{AccessToken: "a"})
	now = now.Add(tokenTTL + time.Second)

	if _, ok := s.Get("old"); ok {
		t.Fatal("Get(old) ok after tokenTTL, want false")
	}

	s.Put("new", oidc.Tokens{AccessToken: "b"})
	s.mu.Lock()
	_, kept := s.entries["old"]
	s.mu.Unlock()
	if kept {
		t.Fatal("Put kept an entry older than tokenTTL")
	}
}
