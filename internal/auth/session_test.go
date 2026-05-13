package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMeHandlerReturnsCurrentSession(t *testing.T) {
	t.Parallel()

	tokens, err := NewTokenManager(testJWTSecret)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}

	token, err := tokens.GenerateToken("alice@example.com", true)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: tokenCookieName, Value: token})
	rr := httptest.NewRecorder()

	MeHandler(tokens).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusOK)
	}

	var session Session
	if err := json.Unmarshal(rr.Body.Bytes(), &session); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if session.Username != "alice@example.com" || !session.IsAdmin {
		t.Fatalf("session = %#v, want alice@example.com admin", session)
	}
}

func TestMeHandlerReturnsUnauthorizedWithoutValidSession(t *testing.T) {
	t.Parallel()

	tokens, err := NewTokenManager(testJWTSecret)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}

	rr := httptest.NewRecorder()
	MeHandler(tokens).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/auth/me", nil))

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestLogoutHandlerClearsSessionCookie(t *testing.T) {
	t.Parallel()

	tokens, err := NewTokenManager(testJWTSecret)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}

	rr := httptest.NewRecorder()
	LogoutHandler(tokens).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusOK)
	}

	result := rr.Result()
	defer result.Body.Close()

	cookies := result.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies len = %d, want 1", len(cookies))
	}
	if cookies[0].Name != tokenCookieName || cookies[0].MaxAge != -1 {
		t.Fatalf("cookie = %#v, want cleared token cookie", cookies[0])
	}
}
