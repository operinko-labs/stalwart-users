package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthorizationMiddlewareAllowsAdminUsers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		method  string
		pattern string
		path    string
	}{
		{name: "list accounts", method: http.MethodGet, pattern: "GET /accounts", path: "/accounts"},
		{name: "create account", method: http.MethodPost, pattern: "POST /accounts", path: "/accounts"},
		{name: "delete account", method: http.MethodDelete, pattern: "DELETE /accounts/{name}", path: "/accounts/bob@example.com"},
		{name: "delete email", method: http.MethodDelete, pattern: "DELETE /accounts/{name}/emails/{address}", path: "/accounts/bob@example.com/emails/alias@example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rr := performAuthorizationRequest(t, tt.method, []route{{pattern: tt.pattern, status: http.StatusNoContent}}, tt.path, "admin@example.com", true)
			if rr.Code != http.StatusNoContent {
				t.Fatalf("status code = %d, want %d", rr.Code, http.StatusNoContent)
			}
		})
	}
}

func TestAuthorizationMiddlewareAllowsOwnAccountSelfServiceRoutes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		method  string
		pattern string
		path    string
	}{
		{name: "get own account", method: http.MethodGet, pattern: "GET /accounts/{name}", path: "/accounts/alice@example.com"},
		{name: "patch own account", method: http.MethodPatch, pattern: "PATCH /accounts/{name}", path: "/accounts/alice@example.com"},
		{name: "get own emails", method: http.MethodGet, pattern: "GET /accounts/{name}/emails", path: "/accounts/alice@example.com/emails"},
		{name: "post own emails", method: http.MethodPost, pattern: "POST /accounts/{name}/emails", path: "/accounts/alice@example.com/emails"},
		{name: "delete own email", method: http.MethodDelete, pattern: "DELETE /accounts/{name}/emails/{address}", path: "/accounts/alice@example.com/emails/alias@example.com"},
		{name: "get own groups", method: http.MethodGet, pattern: "GET /accounts/{name}/groups", path: "/accounts/alice@example.com/groups"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rr := performAuthorizationRequest(t, tt.method, []route{{pattern: tt.pattern, status: http.StatusNoContent}}, tt.path, "alice@example.com", false)
			if rr.Code != http.StatusNoContent {
				t.Fatalf("status code = %d, want %d", rr.Code, http.StatusNoContent)
			}
		})
	}
}

func TestAuthorizationMiddlewareRejectsAccessToOtherUsers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		method  string
		pattern string
		path    string
	}{
		{name: "get other account", method: http.MethodGet, pattern: "GET /accounts/{name}", path: "/accounts/bob@example.com"},
		{name: "post other emails", method: http.MethodPost, pattern: "POST /accounts/{name}/emails", path: "/accounts/bob@example.com/emails"},
		{name: "delete other email", method: http.MethodDelete, pattern: "DELETE /accounts/{name}/emails/{address}", path: "/accounts/bob@example.com/emails/alias@example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rr := performAuthorizationRequest(t, tt.method, []route{{pattern: tt.pattern, status: http.StatusNoContent}}, tt.path, "alice@example.com", false)
			assertForbidden(t, rr)
		})
	}
}

func TestAuthorizationMiddlewareRejectsListingAccountsForNonAdmin(t *testing.T) {
	t.Parallel()

	rr := performAuthorizationRequest(t, http.MethodGet, []route{{pattern: "GET /accounts", status: http.StatusNoContent}}, "/accounts", "alice@example.com", false)
	assertForbidden(t, rr)
}

func TestAuthorizationMiddlewareRejectsCreatingAccountsForNonAdmin(t *testing.T) {
	t.Parallel()

	rr := performAuthorizationRequest(t, http.MethodPost, []route{{pattern: "POST /accounts", status: http.StatusNoContent}}, "/accounts", "alice@example.com", false)
	assertForbidden(t, rr)
}

func TestAuthorizationMiddlewareRejectsDeletingOwnAccountForNonAdmin(t *testing.T) {
	t.Parallel()

	rr := performAuthorizationRequest(t, http.MethodDelete, []route{{pattern: "DELETE /accounts/{name}", status: http.StatusNoContent}}, "/accounts/alice@example.com", "alice@example.com", false)
	assertForbidden(t, rr)
}

func TestAuthorizationMiddlewareRejectsOtherOwnAccountRoutesForNonAdmin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		method  string
		pattern string
		path    string
	}{
		{name: "patch own nested route", method: http.MethodPatch, pattern: "PATCH /accounts/{name}/settings", path: "/accounts/alice@example.com/settings"},
		{name: "get own nested route", method: http.MethodGet, pattern: "GET /accounts/{name}/settings", path: "/accounts/alice@example.com/settings"},
		{name: "post own groups", method: http.MethodPost, pattern: "POST /accounts/{name}/groups", path: "/accounts/alice@example.com/groups"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rr := performAuthorizationRequest(t, tt.method, []route{{pattern: tt.pattern, status: http.StatusNoContent}}, tt.path, "alice@example.com", false)
			assertForbidden(t, rr)
		})
	}
}

func TestAuthorizationMiddlewarePassesThroughNotFound(t *testing.T) {
	t.Parallel()

	rr := performAuthorizationRequest(t, http.MethodGet, nil, "/accounts/alice@example.com", "alice@example.com", false)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

type route struct {
	pattern string
	status  int
}

func performAuthorizationRequest(t *testing.T, method string, routes []route, path, username string, isAdmin bool) *httptest.ResponseRecorder {
	t.Helper()

	called := false
	mux := http.NewServeMux()
	for _, route := range routes {
		status := route.status
		mux.Handle(route.pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(status)
		}))
	}

	handler := AuthorizationMiddleware(mux)

	req := httptest.NewRequest(method, path, nil)
	ctx := context.WithValue(req.Context(), usernameKey, username)
	ctx = context.WithValue(ctx, isAdminKey, isAdmin)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code == http.StatusNoContent && !called {
		t.Fatal("expected wrapped handler to be called")
	}
	if rr.Code == http.StatusForbidden && called {
		t.Fatal("expected wrapped handler not to be called")
	}

	return rr
}

func assertForbidden(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusForbidden)
	}

	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if body["error"] != errForbidden {
		t.Fatalf("error body = %#v, want forbidden", body)
	}
}
