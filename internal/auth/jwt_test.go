package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testJWTSecret = "0123456789abcdef0123456789abcdef"

func TestNewTokenManagerRequiresSecret(t *testing.T) {
	t.Parallel()

	if _, err := NewTokenManager(""); err == nil {
		t.Fatal("expected error for missing secret")
	}
}

func TestNewTokenManagerRejectsShortSecret(t *testing.T) {
	t.Parallel()

	if _, err := NewTokenManager(strings.Repeat("a", minJWTSecretLen-1)); err == nil {
		t.Fatal("expected error for short secret")
	}
}

func TestTokenManagerGeneratesAndValidatesToken(t *testing.T) {
	t.Parallel()

	m, err := NewTokenManager(testJWTSecret)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}

	now := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }

	token, err := m.GenerateToken("alice@example.com", true)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	session, err := m.ParseToken(token)
	if err != nil {
		t.Fatalf("ParseToken() error = %v", err)
	}

	if session.Username != "alice@example.com" || !session.IsAdmin {
		t.Fatalf("session = %#v, want alice@example.com admin", session)
	}
}

func TestTokenManagerRejectsExpiredToken(t *testing.T) {
	t.Parallel()

	m, err := NewTokenManager(testJWTSecret)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}

	now := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }

	token, err := m.GenerateToken("alice@example.com", false)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	m.now = func() time.Time { return now.Add(tokenTTL + time.Minute) }

	if _, err := m.ParseToken(token); err == nil {
		t.Fatal("expected expired token error")
	}
}

func TestTokenManagerSetsAndClearsCookie(t *testing.T) {
	t.Parallel()

	m, err := NewTokenManager(testJWTSecret)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}

	loginRecorder := httptest.NewRecorder()
	m.SetCookie(loginRecorder, "signed-token")

	loginResult := loginRecorder.Result()
	defer loginResult.Body.Close()

	cookies := loginResult.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies len = %d, want 1", len(cookies))
	}
	if cookies[0].Name != tokenCookieName || cookies[0].Value != "signed-token" {
		t.Fatalf("cookie = %#v, want token cookie", cookies[0])
	}
	if !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != "/" {
		t.Fatalf("cookie attrs = %#v, want httpOnly secure strict path=/", cookies[0])
	}

	logoutRecorder := httptest.NewRecorder()
	m.ClearCookie(logoutRecorder)

	logoutResult := logoutRecorder.Result()
	defer logoutResult.Body.Close()

	cleared := logoutResult.Cookies()[0]
	if cleared.MaxAge != -1 {
		t.Fatalf("cleared cookie MaxAge = %d, want -1", cleared.MaxAge)
	}
}

func TestTokenMiddlewareSetsContextForValidSession(t *testing.T) {
	t.Parallel()

	m, err := NewTokenManager(testJWTSecret)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}

	token, err := m.GenerateToken("alice@example.com", true)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	handler := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSONHeader(w)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"username": UsernameFromContext(r.Context()),
			"isAdmin":  IsAdminFromContext(r.Context()),
		})
	}))

	req := httptest.NewRequest(http.MethodGet, "/accounts", nil)
	req.AddCookie(&http.Cookie{Name: tokenCookieName, Value: token})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusOK)
	}

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if body["username"] != "alice@example.com" || body["isAdmin"] != true {
		t.Fatalf("body = %#v, want username/isAdmin from context", body)
	}
}

func TestTokenMiddlewareRejectsMissingCookie(t *testing.T) {
	t.Parallel()

	m, err := NewTokenManager(testJWTSecret)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}

	handler := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/accounts", nil))

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}
