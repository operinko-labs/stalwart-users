package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const serverTestJWTSecret = "0123456789abcdef0123456789abcdef"

func TestNewServerHandlerRegistersPasswordChangeRoute(t *testing.T) {
	t.Parallel()

	handler, err := newServerHandler(serverConfig{
		JWTSecret:          serverTestJWTSecret,
		StalwartAdminToken: "admin-token",
		StalwartURL:        "http://localhost:8080",
	}, nil)
	if err != nil {
		t.Fatalf("newServerHandler() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPut, "/api/accounts/alice/password", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: "invalid-token"})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestCORSMiddlewareSetsHeaders(t *testing.T) {
	t.Parallel()

	handler := newCORSMiddleware("https://email-users.vaderrp.com")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/accounts", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://email-users.vaderrp.com" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want configured origin", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("Access-Control-Allow-Credentials = %q, want true", got)
	}
}

func TestCORSMiddlewareHandlesPreflight(t *testing.T) {
	t.Parallel()

	called := false
	handler := newCORSMiddleware("*")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/accounts", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusNoContent)
	}
	if called {
		t.Fatal("expected preflight request to stop before next handler")
	}
	if got := rr.Header().Get("Access-Control-Allow-Methods"); got != "GET, POST, PUT, PATCH, DELETE, OPTIONS" {
		t.Fatalf("Access-Control-Allow-Methods = %q, want configured methods", got)
	}
}
