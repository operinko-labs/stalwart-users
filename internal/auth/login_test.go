package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const loginTestJWTSecret = testJWTSecret

type stubAuthenticator struct {
	user *AuthenticatedUser
	err  error
	seen struct {
		username string
		password string
	}
}

func (s *stubAuthenticator) Authenticate(_ context.Context, username, password string) (*AuthenticatedUser, error) {
	s.seen.username = username
	s.seen.password = password
	return s.user, s.err
}

type fakeChecker struct {
	ok   bool
	err  error
	seen [2]string
}

func (f *fakeChecker) Authenticate(_ context.Context, username, password string) (bool, error) {
	f.seen = [2]string{username, password}
	return f.ok, f.err
}

type fakeAccess struct {
	admins map[string]bool
	asked  []string
}

func (f *fakeAccess) IsAdmin(name string) (bool, error) {
	f.asked = append(f.asked, name)
	return f.admins[name], nil
}

func (f *fakeAccess) ListAdminDomains(string) ([]string, error) { return nil, nil }

func TestStalwartAuthenticatorSuccess(t *testing.T) {
	t.Parallel()

	checker := &fakeChecker{ok: true}
	access := &fakeAccess{admins: map[string]bool{"root@vaderrp.com": true}}
	authenticator := NewStalwartAuthenticator(checker, access)

	user, err := authenticator.Authenticate(context.Background(), "  Root@VaderRP.com ", "secret")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if user == nil || user.Username != "root@vaderrp.com" || !user.IsAdmin {
		t.Fatalf("user = %#v, want root@vaderrp.com admin", user)
	}
	if checker.seen != [2]string{"root@vaderrp.com", "secret"} {
		t.Fatalf("checker saw %v, want normalised username", checker.seen)
	}

	checker.ok = true
	user, err = authenticator.Authenticate(context.Background(), "bob@client.fi", "secret")
	if err != nil || user == nil || user.IsAdmin {
		t.Fatalf("user = %#v, err = %v; want non-admin bob", user, err)
	}
}

func TestStalwartAuthenticatorInvalid(t *testing.T) {
	t.Parallel()

	access := &fakeAccess{}
	authenticator := NewStalwartAuthenticator(&fakeChecker{}, access)

	user, err := authenticator.Authenticate(context.Background(), "bob@client.fi", "wrong")
	if err != nil || user != nil {
		t.Fatalf("Authenticate() = %#v, %v; want nil, nil", user, err)
	}
	if len(access.asked) != 0 {
		t.Fatalf("IsAdmin asked for %v after failed login", access.asked)
	}
}

func TestStalwartAuthenticatorCheckerError(t *testing.T) {
	t.Parallel()

	authenticator := NewStalwartAuthenticator(&fakeChecker{err: errors.New("down")}, &fakeAccess{})

	if user, err := authenticator.Authenticate(context.Background(), "bob@client.fi", "pw"); err == nil || user != nil {
		t.Fatalf("Authenticate() = %#v, %v; want error", user, err)
	}
}

func TestLoginHandlerCreatesSessionCookieAndReturnsSession(t *testing.T) {
	t.Parallel()

	tokens, err := NewTokenManager(loginTestJWTSecret)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}

	authenticator := &stubAuthenticator{user: &AuthenticatedUser{Username: "alice@example.com", IsAdmin: true}}
	handler := LoginHandler(authenticator, tokens)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"email":"alice@example.com","password":"secret"}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if authenticator.seen.username != "alice@example.com" || authenticator.seen.password != "secret" {
		t.Fatalf("authenticator saw (%q, %q), want alice@example.com/secret", authenticator.seen.username, authenticator.seen.password)
	}

	var body Session
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if body.Username != "alice@example.com" || !body.IsAdmin {
		t.Fatalf("body = %#v, want alice@example.com admin", body)
	}

	result := rr.Result()
	defer result.Body.Close()
	if len(result.Cookies()) != 1 || result.Cookies()[0].Name != tokenCookieName {
		t.Fatalf("cookies = %#v, want token cookie", result.Cookies())
	}
}

func TestLoginHandlerRejectsInvalidCredentials(t *testing.T) {
	t.Parallel()

	tokens, err := NewTokenManager(loginTestJWTSecret)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}

	handler := LoginHandler(&stubAuthenticator{}, tokens)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"email":"alice@example.com","password":"wrong"}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestLoginHandlerHandlesAuthenticatorFailure(t *testing.T) {
	t.Parallel()

	tokens, err := NewTokenManager(loginTestJWTSecret)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}

	handler := LoginHandler(&stubAuthenticator{err: errors.New("boom")}, tokens)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"email":"alice@example.com","password":"secret"}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestLoginHandlerValidatesRequestBody(t *testing.T) {
	t.Parallel()

	tokens, err := NewTokenManager(loginTestJWTSecret)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}

	handler := LoginHandler(&stubAuthenticator{}, tokens)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"email":""}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}
