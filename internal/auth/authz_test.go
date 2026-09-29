package auth

import (
	"context"
	"encoding/json"
	"errors"
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
		{name: "get own groups", method: http.MethodGet, pattern: "GET /accounts/{name}/groups", path: "/accounts/alice@example.com/groups"},
		{name: "change own password", method: http.MethodPut, pattern: "PUT /accounts/{name}/password", path: "/accounts/alice@example.com/password"},
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
		{name: "post own emails", method: http.MethodPost, pattern: "POST /accounts/{name}/emails", path: "/accounts/alice@example.com/emails"},
		{name: "delete own email", method: http.MethodDelete, pattern: "DELETE /accounts/{name}/emails/{address}", path: "/accounts/alice@example.com/emails/alias@example.com"},
		{name: "get own admin domains", method: http.MethodGet, pattern: "GET /accounts/{name}/admin-domains", path: "/accounts/alice@example.com/admin-domains"},
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

var domainAdminStore = &fakeAccessStore{
	domains: map[string][]string{
		"dora@client.fi": {"client.fi", "client2.fi"},
		"sam@client.fi":  {"client.fi"},
		"pam@client.fi":  {"client.fi", "other.fi"},
	},
	admins: map[string]bool{"boss@client.fi": true},
}

func TestAuthorizationMiddlewareLetsDomainAdminsManagePeersOnlyWithinTheirDomains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want int
	}{
		{name: "self", path: "/accounts/dora@client.fi/emails", want: http.StatusNoContent},
		{name: "peer with a subset of domains", path: "/accounts/sam@client.fi/emails", want: http.StatusNoContent},
		{name: "peer with a domain they don't manage", path: "/accounts/pam@client.fi/emails", want: http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rr := performAuthorizationRequestWithStore(t, domainAdminStore, http.MethodPost, []route{{pattern: "POST /accounts/{name}/emails", status: http.StatusNoContent}}, tt.path, "dora@client.fi", false)
			if rr.Code != tt.want {
				t.Fatalf("status code = %d, want %d", rr.Code, tt.want)
			}
		})
	}
}

func TestCanManageAccount(t *testing.T) {
	t.Parallel()

	ctx := WithAdminDomains(context.Background(), []string{"client.fi", "client2.fi"})

	tests := []struct {
		name string
		want bool
	}{
		{name: "bob@client.fi", want: true},
		{name: "sam@client.fi", want: true},
		{name: "pam@client.fi", want: false},
		{name: "boss@client.fi", want: false},
		{name: "eve@other.fi", want: false},
		{name: "admins", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := CanManageAccount(ctx, domainAdminStore, tt.name)
			if err != nil {
				t.Fatalf("CanManageAccount() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("CanManageAccount(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestAuthorizationMiddlewareAllowsDomainAdminsWithinTheirDomains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		method  string
		pattern string
		path    string
	}{
		{name: "list accounts", method: http.MethodGet, pattern: "GET /accounts", path: "/accounts"},
		{name: "create account", method: http.MethodPost, pattern: "POST /accounts", path: "/accounts"},
		{name: "get account", method: http.MethodGet, pattern: "GET /accounts/{name}", path: "/accounts/bob@client.fi"},
		{name: "get account on second domain", method: http.MethodGet, pattern: "GET /accounts/{name}", path: "/accounts/carl@client2.fi"},
		{name: "get account with mixed case", method: http.MethodGet, pattern: "GET /accounts/{name}", path: "/accounts/Bob@Client.FI"},
		{name: "patch account", method: http.MethodPatch, pattern: "PATCH /accounts/{name}", path: "/accounts/bob@client.fi"},
		{name: "delete account", method: http.MethodDelete, pattern: "DELETE /accounts/{name}", path: "/accounts/bob@client.fi"},
		{name: "reset password", method: http.MethodPut, pattern: "PUT /accounts/{name}/password", path: "/accounts/bob@client.fi/password"},
		{name: "list emails", method: http.MethodGet, pattern: "GET /accounts/{name}/emails", path: "/accounts/bob@client.fi/emails"},
		{name: "add email", method: http.MethodPost, pattern: "POST /accounts/{name}/emails", path: "/accounts/bob@client.fi/emails"},
		{name: "delete email", method: http.MethodDelete, pattern: "DELETE /accounts/{name}/emails/{address}", path: "/accounts/bob@client.fi/emails/sales@client.fi"},
		{name: "list groups", method: http.MethodGet, pattern: "GET /accounts/{name}/groups", path: "/accounts/bob@client.fi/groups"},
		{name: "add group", method: http.MethodPost, pattern: "POST /accounts/{name}/groups", path: "/accounts/bob@client.fi/groups"},
		{name: "remove group", method: http.MethodDelete, pattern: "DELETE /accounts/{name}/groups/{group}", path: "/accounts/bob@client.fi/groups/team@client.fi"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rr := performAuthorizationRequestWithStore(t, domainAdminStore, tt.method, []route{{pattern: tt.pattern, status: http.StatusNoContent}}, tt.path, "dora@client.fi", false)
			if rr.Code != http.StatusNoContent {
				t.Fatalf("status code = %d, want %d", rr.Code, http.StatusNoContent)
			}
		})
	}
}

func TestAuthorizationMiddlewareRejectsDomainAdminsOutsideTheirDomains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		method  string
		pattern string
		path    string
	}{
		{name: "get account on other domain", method: http.MethodGet, pattern: "GET /accounts/{name}", path: "/accounts/eve@other.fi"},
		{name: "delete account on other domain", method: http.MethodDelete, pattern: "DELETE /accounts/{name}", path: "/accounts/eve@other.fi"},
		{name: "reset password on other domain", method: http.MethodPut, pattern: "PUT /accounts/{name}/password", path: "/accounts/eve@other.fi/password"},
		{name: "account without domain", method: http.MethodGet, pattern: "GET /accounts/{name}", path: "/accounts/admin"},
		{name: "subdomain is not the domain", method: http.MethodGet, pattern: "GET /accounts/{name}", path: "/accounts/eve@mail.client.fi"},
		{name: "delete email on other domain", method: http.MethodDelete, pattern: "DELETE /accounts/{name}/emails/{address}", path: "/accounts/bob@client.fi/emails/postmaster@other.fi"},
		{name: "remove group on other domain", method: http.MethodDelete, pattern: "DELETE /accounts/{name}/groups/{group}", path: "/accounts/bob@client.fi/groups/staff@other.fi"},
		{name: "full admin account in their domain", method: http.MethodPatch, pattern: "PATCH /accounts/{name}", path: "/accounts/boss@client.fi"},
		{name: "reset full admin password", method: http.MethodPut, pattern: "PUT /accounts/{name}/password", path: "/accounts/boss@client.fi/password"},
		{name: "read admin domains", method: http.MethodGet, pattern: "GET /accounts/{name}/admin-domains", path: "/accounts/bob@client.fi/admin-domains"},
		{name: "set admin domains", method: http.MethodPut, pattern: "PUT /accounts/{name}/admin-domains", path: "/accounts/bob@client.fi/admin-domains"},
		{name: "set own admin domains", method: http.MethodPut, pattern: "PUT /accounts/{name}/admin-domains", path: "/accounts/dora@client.fi/admin-domains"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rr := performAuthorizationRequestWithStore(t, domainAdminStore, tt.method, []route{{pattern: tt.pattern, status: http.StatusNoContent}}, tt.path, "dora@client.fi", false)
			assertForbidden(t, rr)
		})
	}
}

func TestAuthorizationMiddlewarePassesAdminDomainsToHandlers(t *testing.T) {
	t.Parallel()

	var got []string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /accounts", func(w http.ResponseWriter, r *http.Request) {
		got = AdminDomainsFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/accounts", nil)
	req = req.WithContext(WithUser(req.Context(), "dora@client.fi", false))
	rr := httptest.NewRecorder()

	AuthorizationMiddleware(mux, domainAdminStore).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusNoContent)
	}
	if len(got) != 2 || got[0] != "client.fi" || got[1] != "client2.fi" {
		t.Fatalf("admin domains = %#v, want [client.fi client2.fi]", got)
	}
}

func TestAuthorizationMiddlewareReturnsServerErrorWhenPermissionLookupFails(t *testing.T) {
	t.Parallel()

	store := &fakeAccessStore{err: errors.New("db down")}
	rr := performAuthorizationRequestWithStore(t, store, http.MethodGet, []route{{pattern: "GET /accounts", status: http.StatusNoContent}}, "/accounts", "dora@client.fi", false)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestAuthorizationMiddlewareSkipsPermissionLookupForFullAdmins(t *testing.T) {
	t.Parallel()

	store := &fakeAccessStore{err: errors.New("db down")}
	rr := performAuthorizationRequestWithStore(t, store, http.MethodGet, []route{{pattern: "GET /accounts", status: http.StatusNoContent}}, "/accounts", "admin@example.com", true)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusNoContent)
	}
}

type fakeAccessStore struct {
	domains map[string][]string
	admins  map[string]bool
	err     error
}

func (f *fakeAccessStore) ListAdminDomains(name string) ([]string, error) {
	return f.domains[name], f.err
}

func (f *fakeAccessStore) IsAdmin(name string) (bool, error) {
	return f.admins[name], f.err
}

type route struct {
	pattern string
	status  int
}

func performAuthorizationRequest(t *testing.T, method string, routes []route, path, username string, isAdmin bool) *httptest.ResponseRecorder {
	t.Helper()

	return performAuthorizationRequestWithStore(t, &fakeAccessStore{}, method, routes, path, username, isAdmin)
}

func performAuthorizationRequestWithStore(t *testing.T, store AccessStore, method string, routes []route, path, username string, isAdmin bool) *httptest.ResponseRecorder {
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

	handler := AuthorizationMiddleware(mux, store)

	req := httptest.NewRequest(method, path, nil)
	req = req.WithContext(WithUser(req.Context(), username, isAdmin))

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
