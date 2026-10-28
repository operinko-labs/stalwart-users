package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/operinko-labs/stalwart-users/internal/auth"
	"github.com/operinko-labs/stalwart-users/internal/directory"
	"github.com/operinko-labs/stalwart-users/internal/stalwart"
)

const serverTestJWTSecret = "0123456789abcdef0123456789abcdef"

// emptyStalwart is a Stalwart with no accounts or domains.
type emptyStalwart struct{}

func (emptyStalwart) ListAccounts(context.Context) ([]stalwart.Account, error) { return nil, nil }
func (emptyStalwart) ListDomains(context.Context) ([]stalwart.Domain, error)   { return nil, nil }
func (emptyStalwart) CreateAccount(context.Context, string, string, string, int64) error {
	return nil
}
func (emptyStalwart) UpdateAccount(context.Context, string, map[string]any) error { return nil }
func (emptyStalwart) DeleteAccount(context.Context, string) error                 { return nil }
func (emptyStalwart) Authenticate(context.Context, string, string) (bool, error) {
	return false, nil
}
func (emptyStalwart) SetPassword(context.Context, stalwart.Account, string) error { return nil }

// accountsStalwart is a Stalwart holding a fixed set of accounts.
type accountsStalwart struct {
	emptyStalwart
	accounts []stalwart.Account
}

func (f accountsStalwart) ListAccounts(context.Context) ([]stalwart.Account, error) {
	return f.accounts, nil
}

// exactAdminDomains matches names exactly, like the Postgres table.
type exactAdminDomains map[string][]string

func (f exactAdminDomains) ListAdminDomains(name string) ([]string, error) { return f[name], nil }
func (f exactAdminDomains) SetAdminDomains(string, []string) error         { return nil }
func (f exactAdminDomains) DeleteAdminDomains(string) error                { return nil }

type noAdminDomains struct{}

func (noAdminDomains) ListAdminDomains(string) ([]string, error) { return nil, nil }
func (noAdminDomains) SetAdminDomains(string, []string) error    { return nil }
func (noAdminDomains) DeleteAdminDomains(string) error           { return nil }

func newTestServerHandler(t *testing.T) http.Handler {
	t.Helper()

	handler, err := newServerHandler(serverConfig{JWTSecret: serverTestJWTSecret}, nil, directory.New(emptyStalwart{}, noAdminDomains{}))
	if err != nil {
		t.Fatalf("newServerHandler() error = %v", err)
	}

	return handler
}

func TestLoadConfigRequiresStalwartAndDatabase(t *testing.T) {
	required := []string{"DATABASE_URL", "STALWART_URL", "STALWART_ADMIN_TOKEN"}

	for _, missing := range required {
		t.Run(missing, func(t *testing.T) {
			t.Setenv("JWT_SECRET", serverTestJWTSecret)
			for _, name := range required {
				t.Setenv(name, "set")
			}
			t.Setenv(missing, "")

			_, err := loadConfigFromEnv()
			if err == nil || !strings.Contains(err.Error(), missing) {
				t.Fatalf("loadConfigFromEnv() error = %v, want one naming %s", err, missing)
			}
		})
	}
}

func TestLoadConfigAcceptsCompleteConfig(t *testing.T) {
	t.Setenv("JWT_SECRET", serverTestJWTSecret)
	t.Setenv("DATABASE_URL", "postgres://db")
	t.Setenv("STALWART_URL", "http://stalwart")
	t.Setenv("STALWART_ADMIN_TOKEN", "token")

	cfg, err := loadConfigFromEnv()
	if err != nil {
		t.Fatalf("loadConfigFromEnv() error = %v", err)
	}
	if cfg.DatabaseURL != "postgres://db" || cfg.StalwartURL != "http://stalwart" || cfg.StalwartAdminToken != "token" {
		t.Fatalf("cfg = %#v", cfg)
	}
}

func TestNewServerHandlerRegistersPasswordChangeRoute(t *testing.T) {
	t.Parallel()

	handler := newTestServerHandler(t)

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
		// 404 and 400 mean the request reached its handler: the test Stalwart
		// has no accounts and the requests have no body.
		{name: "admin reads admin domains", method: http.MethodGet, path: "/api/accounts/dora@client.fi/admin-domains", username: "admin@example.com", isAdmin: true, want: http.StatusNotFound},
		{name: "admin sets admin domains", method: http.MethodPut, path: "/api/accounts/dora@client.fi/admin-domains", username: "admin@example.com", isAdmin: true, want: http.StatusNotFound},
		{name: "user reads own admin domains", method: http.MethodGet, path: "/api/accounts/bob@client.fi/admin-domains", username: "bob@client.fi", want: http.StatusForbidden},
		{name: "user changes own password", method: http.MethodPut, path: "/api/accounts/bob@client.fi/password", username: "bob@client.fi", want: http.StatusBadRequest},
		{name: "user changes another password", method: http.MethodPut, path: "/api/accounts/eve@client.fi/password", username: "bob@client.fi", want: http.StatusForbidden},
		{name: "user adds own address", method: http.MethodPost, path: "/api/accounts/bob@client.fi/emails", username: "bob@client.fi", want: http.StatusForbidden},
	}

	handler := newTestServerHandler(t)
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

func TestDomainAdminCannotUseMixedCaseNamesToBypassChecks(t *testing.T) {
	t.Parallel()

	store := directory.New(accountsStalwart{accounts: []stalwart.Account{
		{ID: "d", Type: "User", Email: "dora@client.fi"},
		{ID: "p", Type: "User", Email: "pete@client.fi"},
	}}, exactAdminDomains{
		"dora@client.fi": {"client.fi"},
		"pete@client.fi": {"client.fi", "other.fi"},
	})
	handler, err := newServerHandler(serverConfig{JWTSecret: serverTestJWTSecret}, nil, store)
	if err != nil {
		t.Fatalf("newServerHandler() error = %v", err)
	}
	tokens, err := auth.NewTokenManager(serverTestJWTSecret)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}
	token, err := tokens.GenerateToken("dora@client.fi", false)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	tests := []struct {
		name   string
		method string
		path   string
		body   string
		want   int
		error  string
	}{
		{name: "reset peer password", method: http.MethodPut, path: "/api/accounts/Pete@client.fi/password", body: `{"new_password":"new-Password-1"}`, want: http.StatusForbidden, error: "forbidden"},
		{name: "delete peer", method: http.MethodDelete, path: "/api/accounts/Pete@Client.fi", want: http.StatusForbidden, error: "forbidden"},
		{name: "own password without current", method: http.MethodPut, path: "/api/accounts/Dora@client.fi/password", body: `{"new_password":"new-Password-1"}`, want: http.StatusBadRequest, error: "current_password is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			req.AddCookie(&http.Cookie{Name: "token", Value: token})
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != tt.want || !strings.Contains(rr.Body.String(), tt.error) {
				t.Fatalf("status = %d body = %s; want %d with %q", rr.Code, rr.Body.String(), tt.want, tt.error)
			}
		})
	}
}
