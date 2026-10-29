package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

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

func TestLoadConfigRequiresStalwartDatabaseAndOIDC(t *testing.T) {
	required := []string{
		"DATABASE_URL", "STALWART_URL", "STALWART_ADMIN_TOKEN",
		"OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_REDIRECT_URL",
	}

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
	t.Setenv("OIDC_ISSUER", "https://mail.example.com")
	t.Setenv("OIDC_CLIENT_ID", "stalwart-users")
	t.Setenv("OIDC_CLIENT_SECRET", "client-secret")
	t.Setenv("OIDC_REDIRECT_URL", "https://users.example.com/api/auth/callback")

	cfg, err := loadConfigFromEnv()
	if err != nil {
		t.Fatalf("loadConfigFromEnv() error = %v", err)
	}
	if cfg.DatabaseURL != "postgres://db" || cfg.StalwartURL != "http://stalwart" || cfg.StalwartAdminToken != "token" ||
		cfg.OIDCIssuer != "https://mail.example.com" || cfg.OIDCClientID != "stalwart-users" ||
		cfg.OIDCClientSecret != "client-secret" || cfg.OIDCRedirectURL != "https://users.example.com/api/auth/callback" {
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

			token, _, err := tokens.GenerateToken(tt.username, tt.isAdmin)
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
		{ID: "s", Type: "User", Email: "sam@client.fi"},
	}}, exactAdminDomains{
		"dora@client.fi": {"client.fi"},
		"pete@client.fi": {"client.fi", "other.fi"},
		"sam@client.fi":  {"client.fi", "other.fi"},
	})
	handler, err := newServerHandler(serverConfig{JWTSecret: serverTestJWTSecret}, nil, store)
	if err != nil {
		t.Fatalf("newServerHandler() error = %v", err)
	}
	tokens, err := auth.NewTokenManager(serverTestJWTSecret)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}
	token, _, err := tokens.GenerateToken("dora@client.fi", false)
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
		// %C5%BF is U+017F, which case-folds to "s" but doesn't lower-case to it.
		{name: "reset folded peer password", method: http.MethodPut, path: "/api/accounts/%C5%BFam@client.fi/password", body: `{"new_password":"new-Password-1"}`, want: http.StatusNotFound, error: "account not found"},
		{name: "delete folded peer", method: http.MethodDelete, path: "/api/accounts/%C5%BFam@client.fi", want: http.StatusNotFound, error: "account not found"},
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

// fakeProvider is a Stalwart OIDC provider that signs in whoever email names.
func fakeProvider(t *testing.T, email string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 srv.URL,
				"authorization_endpoint": srv.URL + "/login",
				"token_endpoint":         srv.URL + "/auth/token",
				"userinfo_endpoint":      srv.URL + "/auth/userinfo",
			})
		case "/auth/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "refresh_token": "rt", "expires_in": 3600})
		case "/auth/userinfo":
			_ = json.NewEncoder(w).Encode(map[string]string{"sub": "1", "email": email})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func oidcTestConfig(issuer, prefix string) serverConfig {
	return serverConfig{
		JWTSecret:        serverTestJWTSecret,
		PathPrefix:       prefix,
		OIDCIssuer:       issuer,
		OIDCClientID:     "stalwart-users",
		OIDCClientSecret: "client-secret",
		OIDCRedirectURL:  "https://users.example.com" + prefix + "/api/auth/callback",
	}
}

// signIn runs the browser through GET /auth/login and the callback and
// returns the callback response.
func signIn(t *testing.T, handler http.Handler, prefix string) *httptest.ResponseRecorder {
	t.Helper()

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, prefix+"/api/auth/login", nil))
	if rr.Code != http.StatusFound {
		t.Fatalf("login status = %d, want 302; body=%s", rr.Code, rr.Body.String())
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("login Location: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, prefix+"/api/auth/callback?"+url.Values{"code": {"c"}, "state": {loc.Query().Get("state")}}.Encode(), nil)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func sessionCookie(rr *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rr.Result().Cookies() {
		if c.Name == "token" && c.Value != "" {
			return c
		}
	}
	return nil
}

func TestOIDCSignInResolvesOnlyPrimaryAddresses(t *testing.T) {
	t.Parallel()

	accounts := []stalwart.Account{
		{ID: "d", Type: "User", Email: "dora@client.fi", IsAdmin: true, Aliases: map[string]stalwart.Alias{"0": {Name: "sales", DomainID: "c"}}},
		{ID: "s", Type: "User", Email: "sam@client.fi"},
		{ID: "g", Type: "Group", Email: "team@client.fi"},
	}

	tests := []struct {
		email string
		want  string
	}{
		{email: "Dora@Client.fi", want: "/"},
		{email: "sales@client.fi", want: "/login?error=no_mailbox"},
		{email: "team@client.fi", want: "/login?error=no_mailbox"},
		{email: "ſam@client.fi", want: "/login?error=no_mailbox"},
		{email: "", want: "/login?error=no_mailbox"},
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			t.Parallel()

			store := directory.New(accountsStalwart{accounts: accounts}, noAdminDomains{})
			handler, err := newServerHandler(oidcTestConfig(fakeProvider(t, tt.email).URL, ""), nil, store)
			if err != nil {
				t.Fatalf("newServerHandler() error = %v", err)
			}

			rr := signIn(t, handler, "")

			if rr.Code != http.StatusFound || rr.Header().Get("Location") != tt.want {
				t.Fatalf("callback = %d %q, want 302 %q", rr.Code, rr.Header().Get("Location"), tt.want)
			}
			c := sessionCookie(rr)
			if (c != nil) != (tt.want == "/") {
				t.Fatalf("session cookie = %v, want one only on success", c)
			}
			if c == nil {
				return
			}

			req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
			req.AddCookie(c)
			me := httptest.NewRecorder()
			handler.ServeHTTP(me, req)
			if !strings.Contains(me.Body.String(), `"username":"dora@client.fi"`) || !strings.Contains(me.Body.String(), `"isAdmin":true`) {
				t.Fatalf("/auth/me = %s, want admin dora@client.fi", me.Body.String())
			}
		})
	}
}

func TestOIDCRoutesRespectPathPrefix(t *testing.T) {
	t.Parallel()

	store := directory.New(accountsStalwart{accounts: []stalwart.Account{{ID: "d", Type: "User", Email: "dora@client.fi"}}}, noAdminDomains{})
	handler, err := newServerHandler(oidcTestConfig(fakeProvider(t, "dora@client.fi").URL, "/users"), nil, store)
	if err != nil {
		t.Fatalf("newServerHandler() error = %v", err)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/users/api/auth/login", nil))
	var stateCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "su_oidc" {
			stateCookie = c
		}
	}
	if stateCookie == nil || stateCookie.Path != "/users/api/auth" {
		t.Fatalf("state cookie = %#v, want Path=/users/api/auth", stateCookie)
	}

	rr = signIn(t, handler, "/users")
	if rr.Header().Get("Location") != "/users/" || sessionCookie(rr) == nil {
		t.Fatalf("callback Location = %q, want /users/ with a session", rr.Header().Get("Location"))
	}

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/users/api/auth/callback?code=c&state=s", nil))
	if rr.Header().Get("Location") != "/users/login?error=state" {
		t.Fatalf("callback without cookie Location = %q, want /users/login?error=state", rr.Header().Get("Location"))
	}
}

func TestBasicLoginRouteIsGone(t *testing.T) {
	t.Parallel()

	rr := httptest.NewRecorder()
	newTestServerHandler(t).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"email":"a@b.c","password":"p"}`)))

	if rr.Code != http.StatusUnauthorized || sessionCookie(rr) != nil {
		t.Fatalf("POST /api/auth/login = %d, want 401 from the session middleware", rr.Code)
	}
}

func TestLoadConfigClientSecretIsOptional(t *testing.T) {
	setBase := func(t *testing.T) {
		t.Setenv("JWT_SECRET", serverTestJWTSecret)
		t.Setenv("DATABASE_URL", "postgres://db")
		t.Setenv("STALWART_URL", "http://stalwart")
		t.Setenv("STALWART_ADMIN_TOKEN", "token")
		t.Setenv("OIDC_ISSUER", "https://mail.example.com")
		t.Setenv("OIDC_CLIENT_ID", "stalwart-users")
		t.Setenv("OIDC_REDIRECT_URL", "https://users.example.com/api/auth/callback")
	}

	t.Run("derived when empty", func(t *testing.T) {
		setBase(t)
		t.Setenv("OIDC_CLIENT_SECRET", "")

		cfg, err := loadConfigFromEnv()
		if err != nil {
			t.Fatalf("loadConfigFromEnv() error = %v", err)
		}
		if want := auth.DeriveOAuthClientSecret(serverTestJWTSecret); cfg.OIDCClientSecret != want {
			t.Fatalf("OIDCClientSecret = %q, want the derived secret", cfg.OIDCClientSecret)
		}
	})

	t.Run("override wins", func(t *testing.T) {
		setBase(t)
		t.Setenv("OIDC_CLIENT_SECRET", "explicit")

		cfg, err := loadConfigFromEnv()
		if err != nil {
			t.Fatalf("loadConfigFromEnv() error = %v", err)
		}
		if cfg.OIDCClientSecret != "explicit" {
			t.Fatalf("OIDCClientSecret = %q, want explicit", cfg.OIDCClientSecret)
		}
	})
}

type fakeEnsurer struct {
	failures int
	calls    int
	specs    []stalwart.OAuthClientSpec
	created  bool
}

func (f *fakeEnsurer) EnsureOAuthClient(_ context.Context, spec stalwart.OAuthClientSpec) (bool, error) {
	f.calls++
	f.specs = append(f.specs, spec)
	if f.calls <= f.failures {
		return false, errors.New("stalwart not ready")
	}
	return f.created, nil
}

func TestOAuthClientSpecFromConfig(t *testing.T) {
	t.Parallel()

	spec := oauthClientSpec(oidcTestConfig("https://mail.example.com", ""))
	want := stalwart.OAuthClientSpec{
		ClientID:    "stalwart-users",
		Secret:      "client-secret",
		RedirectURI: "https://users.example.com/api/auth/callback",
		Description: "stalwart-users",
	}
	if spec != want {
		t.Fatalf("spec = %#v, want %#v", spec, want)
	}
}

func TestRegisterOAuthClientRetriesUntilItSucceeds(t *testing.T) {
	t.Parallel()

	ensurer := &fakeEnsurer{failures: 3}
	var sleeps []time.Duration
	sleep := func(_ context.Context, d time.Duration) bool {
		sleeps = append(sleeps, d)
		return true
	}

	registerOAuthClient(context.Background(), ensurer, stalwart.OAuthClientSpec{ClientID: "stalwart-users"}, sleep)

	if ensurer.calls != 4 {
		t.Fatalf("EnsureOAuthClient calls = %d, want 4", ensurer.calls)
	}
	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second}
	if len(sleeps) != len(want) {
		t.Fatalf("sleeps = %v, want %v", sleeps, want)
	}
	for i := range want {
		if sleeps[i] != want[i] {
			t.Fatalf("sleeps = %v, want %v", sleeps, want)
		}
	}
}

func TestRegisterOAuthClientBackoffCapsAtOneMinute(t *testing.T) {
	t.Parallel()

	ensurer := &fakeEnsurer{failures: 8}
	var sleeps []time.Duration
	registerOAuthClient(context.Background(), ensurer, stalwart.OAuthClientSpec{}, func(_ context.Context, d time.Duration) bool {
		sleeps = append(sleeps, d)
		return true
	})

	if last := sleeps[len(sleeps)-1]; last != 60*time.Second {
		t.Fatalf("sleeps = %v, want the last at the 60s cap", sleeps)
	}
	for _, d := range sleeps {
		if d > 60*time.Second {
			t.Fatalf("sleeps = %v, want none above 60s", sleeps)
		}
	}
}

func TestRegisterOAuthClientStopsWhenContextIsCancelled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	ensurer := &fakeEnsurer{failures: 1 << 30}
	done := make(chan struct{})
	go func() {
		defer close(done)
		registerOAuthClient(ctx, ensurer, stalwart.OAuthClientSpec{}, func(ctx context.Context, d time.Duration) bool {
			cancel()
			return false
		})
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("registerOAuthClient did not return after the context was cancelled")
	}
	if ensurer.calls != 1 {
		t.Fatalf("EnsureOAuthClient calls = %d, want 1", ensurer.calls)
	}
}
