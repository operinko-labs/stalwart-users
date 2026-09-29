package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/operinko-labs/stalwart-users/internal/auth"
)

const serverTestJWTSecret = "0123456789abcdef0123456789abcdef"

func TestNewServerHandlerRegistersPasswordChangeRoute(t *testing.T) {
	t.Parallel()

	handler, err := newServerHandler(serverConfig{
		JWTSecret: serverTestJWTSecret,
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

func TestNewServerHandlerAuthorizesRoutes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		method   string
		path     string
		username string
		isAdmin  bool
		want     int
	}{
		// 503 means the request reached its handler, which has no database here.
		{name: "admin reads admin domains", method: http.MethodGet, path: "/api/accounts/dora@client.fi/admin-domains", username: "admin@example.com", isAdmin: true, want: http.StatusServiceUnavailable},
		{name: "admin sets admin domains", method: http.MethodPut, path: "/api/accounts/dora@client.fi/admin-domains", username: "admin@example.com", isAdmin: true, want: http.StatusServiceUnavailable},
		{name: "user reads own admin domains", method: http.MethodGet, path: "/api/accounts/bob@client.fi/admin-domains", username: "bob@client.fi", want: http.StatusForbidden},
		{name: "user changes own password", method: http.MethodPut, path: "/api/accounts/bob@client.fi/password", username: "bob@client.fi", want: http.StatusServiceUnavailable},
		{name: "user changes another password", method: http.MethodPut, path: "/api/accounts/eve@client.fi/password", username: "bob@client.fi", want: http.StatusForbidden},
		{name: "user adds own address", method: http.MethodPost, path: "/api/accounts/bob@client.fi/emails", username: "bob@client.fi", want: http.StatusForbidden},
	}

	handler, err := newServerHandler(serverConfig{JWTSecret: serverTestJWTSecret}, nil)
	if err != nil {
		t.Fatalf("newServerHandler() error = %v", err)
	}
	tokens, err := auth.NewTokenManager(serverTestJWTSecret)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			token, err := tokens.GenerateToken(tt.username, tt.isAdmin)
			if err != nil {
				t.Fatalf("GenerateToken() error = %v", err)
			}

			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.AddCookie(&http.Cookie{Name: "token", Value: token})
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != tt.want {
				t.Fatalf("status code = %d, want %d; body=%s", rr.Code, tt.want, rr.Body.String())
			}
		})
	}
}

func TestNewServerHandlerRegistersAccountRoutesWithOptionalStalwartConfig(t *testing.T) {
	t.Parallel()

	handler, err := newServerHandler(serverConfig{
		JWTSecret:          serverTestJWTSecret,
		StalwartURL:        "http://stalwart.internal",
		StalwartAdminToken: "token",
	}, nil)
	if err != nil {
		t.Fatalf("newServerHandler() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/accounts/alice", nil)
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
