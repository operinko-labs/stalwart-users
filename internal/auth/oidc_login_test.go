package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/operinko-labs/stalwart-users/internal/model"
	"github.com/operinko-labs/stalwart-users/internal/oidc"
)

// fakeOIDC stands in for the oidc.Client on both legs of the flow.
type fakeOIDC struct {
	tokens      oidc.Tokens
	info        oidc.UserInfo
	exchangeErr error
	userInfoErr error

	state, challenge, code, verifier, accessToken string
	exchanged                                     bool
}

func (f *fakeOIDC) AuthCodeURL(_ context.Context, state, challenge string) (string, error) {
	f.state, f.challenge = state, challenge
	return "https://mail.example.com/login?state=" + url.QueryEscape(state), nil
}

func (f *fakeOIDC) Exchange(_ context.Context, code, verifier string) (oidc.Tokens, error) {
	f.exchanged = true
	f.code, f.verifier = code, verifier
	return f.tokens, f.exchangeErr
}

func (f *fakeOIDC) UserInfo(_ context.Context, accessToken string) (oidc.UserInfo, error) {
	f.accessToken = accessToken
	return f.info, f.userInfoErr
}

// fakeAccounts resolves names like directory.Store: only a User's primary
// address, compared exactly on its canonical form.
type fakeAccounts struct {
	users  map[string]*model.Account
	admins map[string]bool
	err    error
}

func (f *fakeAccounts) GetAccount(name string) (*model.Account, error) {
	return f.users[CanonicalName(name)], f.err
}

func (f *fakeAccounts) IsAdmin(name string) (bool, error) { return f.admins[name], f.err }

func newLoginTestTokens(t *testing.T) *TokenManager {
	t.Helper()
	m, err := NewTokenManager(testJWTSecret)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}
	return m
}

func doraAccounts() *fakeAccounts {
	return &fakeAccounts{
		users:  map[string]*model.Account{"dora@client.fi": {Name: "Dora@client.fi"}},
		admins: map[string]bool{"dora@client.fi": true},
	}
}

func signedInOIDC() *fakeOIDC {
	return &fakeOIDC{
		tokens: oidc.Tokens{AccessToken: "access-1", RefreshToken: "refresh-1", ExpiresAt: time.Unix(2000000000, 0)},
		info:   oidc.UserInfo{Subject: "42", Email: " Dora@Client.FI ", PreferredUsername: "admin"},
	}
}

func findCookie(rr *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rr.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// startLogin runs the login leg and returns the state cookie and the state
// sent to the provider.
func startLogin(t *testing.T, tokens *TokenManager, f *fakeOIDC) (*http.Cookie, string) {
	t.Helper()
	rr := httptest.NewRecorder()
	LoginStartHandler(f, tokens).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/auth/login", nil))
	if rr.Code != http.StatusFound {
		t.Fatalf("login status = %d, want 302", rr.Code)
	}
	c := findCookie(rr, stateCookieName)
	if c == nil {
		t.Fatal("login set no state cookie")
	}
	return c, f.state
}

func callback(tokens *TokenManager, f *fakeOIDC, accounts accountResolver, store *TokenStore, query string, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/auth/callback?"+query, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	CallbackHandler(f, accounts, tokens, store).ServeHTTP(rr, req)
	return rr
}

func callbackQuery(code, state string) string {
	return url.Values{"code": {code}, "state": {state}}.Encode()
}

func assertRedirect(t *testing.T, rr *httptest.ResponseRecorder, want string) {
	t.Helper()
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != want {
		t.Fatalf("status = %d Location = %q, want 302 %q", rr.Code, rr.Header().Get("Location"), want)
	}
}

func assertNoSession(t *testing.T, rr *httptest.ResponseRecorder, store *TokenStore) {
	t.Helper()
	if c := findCookie(rr, tokenCookieName); c != nil && c.Value != "" {
		t.Fatal("session cookie set on a refused sign-in")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.entries) != 0 {
		t.Fatalf("token store holds %d entries after a refused sign-in", len(store.entries))
	}
}

func TestLoginRedirectsOnlyToAuthorizeEndpoint(t *testing.T) {
	t.Parallel()

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/login",
			"token_endpoint":         srv.URL + "/auth/token",
			"userinfo_endpoint":      srv.URL + "/auth/userinfo",
		})
	}))
	defer srv.Close()

	client := oidc.New(oidc.Config{
		Issuer:      srv.URL,
		ClientID:    "stalwart-users",
		RedirectURL: "https://email-users.example.com/api/auth/callback",
	}, srv.Client())

	req := httptest.NewRequest(http.MethodGet, "/api/auth/login?redirect_uri=https%3A%2F%2Fevil.example%2Fcb&next=https%3A%2F%2Fevil.example&state=attacker&client_id=evil", nil)
	rr := httptest.NewRecorder()
	LoginStartHandler(client, newLoginTestTokens(t)).ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	authorize, _ := url.Parse(srv.URL + "/login")
	if loc.Scheme != authorize.Scheme || loc.Host != authorize.Host || loc.Path != authorize.Path {
		t.Fatalf("Location = %s, want the authorize endpoint %s", loc, authorize)
	}
	q := loc.Query()
	if q.Get("redirect_uri") != "https://email-users.example.com/api/auth/callback" || q.Get("client_id") != "stalwart-users" {
		t.Fatalf("query = %v, want the configured client and redirect", q)
	}
	if q.Get("state") == "attacker" || q.Get("state") == "" || len(q["state"]) != 1 {
		t.Fatalf("state = %v, want one fresh state", q["state"])
	}
	if q.Has("next") {
		t.Fatalf("query = %v, carried a parameter from the request", q)
	}
}

func TestLoginSetsSignedStateCookie(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct{ prefix, path string }{{"", "/api/auth"}, {"/users", "/users/api/auth"}} {
		tokens := newLoginTestTokens(t)
		tokens.SetPaths(tt.prefix, "/api")
		f := &fakeOIDC{}

		c, state := startLogin(t, tokens, f)

		if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != tt.path {
			t.Fatalf("cookie = %#v, want HttpOnly Secure Lax Path=%s", c, tt.path)
		}
		if c.MaxAge != int(stateTTL.Seconds()) {
			t.Fatalf("MaxAge = %d, want %d", c.MaxAge, int(stateTTL.Seconds()))
		}

		raw, err := base64.RawURLEncoding.DecodeString(state)
		if err != nil || len(raw) != 32 {
			t.Fatalf("state %q is not 32 base64url bytes", state)
		}
		parts := strings.Split(c.Value, "|")
		if len(parts) != 4 || parts[0] != state {
			t.Fatalf("cookie value has %d fields, want state|verifier|expiry|mac", len(parts))
		}
		sum := sha256.Sum256([]byte(parts[1]))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge {
			t.Fatal("cookie verifier doesn't match the challenge sent to the provider")
		}
	}
}

func TestCallbackSuccess(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct{ prefix, want string }{{"", "/"}, {"/users", "/users/"}} {
		tokens := newLoginTestTokens(t)
		tokens.SetPaths(tt.prefix, "/api")
		f := signedInOIDC()
		store := NewTokenStore()
		cookie, state := startLogin(t, tokens, f)

		rr := callback(tokens, f, doraAccounts(), store, callbackQuery("the-code", state), cookie)

		assertRedirect(t, rr, tt.want)
		if f.code != "the-code" || f.accessToken != "access-1" {
			t.Fatalf("exchange got code %q, userinfo got token %q", f.code, f.accessToken)
		}
		sum := sha256.Sum256([]byte(f.verifier))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge {
			t.Fatal("exchange verifier doesn't match the login challenge")
		}

		sc := findCookie(rr, tokenCookieName)
		if sc == nil {
			t.Fatal("no session cookie")
		}
		session, err := tokens.ParseToken(sc.Value)
		if err != nil {
			t.Fatalf("ParseToken() error = %v", err)
		}
		if session.Username != "dora@client.fi" || !session.IsAdmin || session.ID == "" {
			t.Fatalf("session = %#v, want admin dora@client.fi with an id", session)
		}
		if got, ok := store.Get(session.ID); !ok || got != f.tokens {
			t.Fatalf("store.Get(session id) = %#v, %v; want the exchanged tokens", got, ok)
		}
	}
}

func TestCallbackRejectsBadState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// mutate returns the cookie and query state to send.
		mutate func(t *testing.T, tokens *TokenManager, c *http.Cookie, state string) (*http.Cookie, string)
	}{
		{"missing cookie", func(_ *testing.T, _ *TokenManager, _ *http.Cookie, state string) (*http.Cookie, string) {
			return nil, state
		}},
		{"tampered mac", func(_ *testing.T, _ *TokenManager, c *http.Cookie, state string) (*http.Cookie, string) {
			parts := strings.Split(c.Value, "|")
			mac := []byte(parts[3])
			mac[0] ^= 1
			parts[3] = string(mac)
			return &http.Cookie{Name: c.Name, Value: strings.Join(parts, "|")}, state
		}},
		{"tampered state in cookie", func(_ *testing.T, _ *TokenManager, c *http.Cookie, _ string) (*http.Cookie, string) {
			parts := strings.Split(c.Value, "|")
			parts[0] = "forged"
			return &http.Cookie{Name: c.Name, Value: strings.Join(parts, "|")}, "forged"
		}},
		{"extended expiry", func(_ *testing.T, _ *TokenManager, c *http.Cookie, state string) (*http.Cookie, string) {
			parts := strings.Split(c.Value, "|")
			parts[2] = "9999999999"
			return &http.Cookie{Name: c.Name, Value: strings.Join(parts, "|")}, state
		}},
		{"expired", func(_ *testing.T, tokens *TokenManager, c *http.Cookie, state string) (*http.Cookie, string) {
			later := time.Now().Add(stateTTL + time.Minute)
			tokens.now = func() time.Time { return later }
			return c, state
		}},
		{"state mismatch", func(_ *testing.T, _ *TokenManager, c *http.Cookie, _ string) (*http.Cookie, string) {
			return c, "some-other-state"
		}},
		{"missing query state", func(_ *testing.T, _ *TokenManager, c *http.Cookie, _ string) (*http.Cookie, string) {
			return c, ""
		}},
		{"signed with another secret", func(t *testing.T, _ *TokenManager, _ *http.Cookie, _ string) (*http.Cookie, string) {
			other, err := NewTokenManager(strings.Repeat("z", 32))
			if err != nil {
				t.Fatal(err)
			}
			return startLogin(t, other, &fakeOIDC{})
		}},
		{"malformed", func(_ *testing.T, _ *TokenManager, c *http.Cookie, state string) (*http.Cookie, string) {
			return &http.Cookie{Name: c.Name, Value: state}, state
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tokens := newLoginTestTokens(t)
			f := signedInOIDC()
			store := NewTokenStore()
			c, state := startLogin(t, tokens, f)
			c, state = tt.mutate(t, tokens, c, state)

			rr := callback(tokens, f, doraAccounts(), store, callbackQuery("the-code", state), c)

			assertRedirect(t, rr, "/login?error=state")
			assertNoSession(t, rr, store)
			if f.exchanged {
				t.Fatal("code exchanged despite a bad state")
			}
		})
	}
}

func TestCallbackStateCookieSingleUse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		setup    func(f *fakeOIDC, a *fakeAccounts)
		query    func(state string) string
		noCookie bool
		want     string
	}{
		{name: "success", query: func(s string) string { return callbackQuery("c", s) }, want: "/"},
		{name: "denied", query: func(s string) string { return "error=access_denied&state=" + s }, want: "/login?error=denied"},
		{name: "bad state", query: func(string) string { return callbackQuery("c", "wrong") }, want: "/login?error=state"},
		{name: "no cookie", query: func(s string) string { return callbackQuery("c", s) }, noCookie: true, want: "/login?error=state"},
		{name: "exchange fails", setup: func(f *fakeOIDC, _ *fakeAccounts) {
			f.exchangeErr = errors.New("oidc token: status 400: invalid_grant")
		}, query: func(s string) string { return callbackQuery("c", s) }, want: "/login?error=signin"},
		{name: "no mailbox", setup: func(f *fakeOIDC, _ *fakeAccounts) { f.info.Email = "nobody@client.fi" }, query: func(s string) string { return callbackQuery("c", s) }, want: "/login?error=no_mailbox"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tokens := newLoginTestTokens(t)
			tokens.SetPaths("/users", "/api")
			f := signedInOIDC()
			accounts := doraAccounts()
			if tt.setup != nil {
				tt.setup(f, accounts)
			}
			c, state := startLogin(t, tokens, f)
			if tt.noCookie {
				c = nil
			}

			rr := callback(tokens, f, accounts, NewTokenStore(), tt.query(state), c)

			if got := rr.Header().Get("Location"); got != "/users"+tt.want {
				t.Fatalf("Location = %q, want %q", got, "/users"+tt.want)
			}
			cleared := findCookie(rr, stateCookieName)
			if cleared == nil || cleared.MaxAge != -1 || cleared.Value != "" || cleared.Path != "/users/api/auth" {
				t.Fatalf("state cookie = %#v, want it cleared on Path=/users/api/auth", cleared)
			}
		})
	}
}

func TestCallbackRejectsNonPrimaryIdentity(t *testing.T) {
	t.Parallel()

	// sales@ is one of dora's aliases and team@ a Group; neither is a User's
	// primary address. U+017F case-folds to "s" but doesn't lower-case to it.
	for _, email := range []string{"sales@client.fi", "team@client.fi", "ſam@client.fi", "dora", ""} {
		t.Run(email, func(t *testing.T) {
			t.Parallel()

			tokens := newLoginTestTokens(t)
			f := signedInOIDC()
			f.info = oidc.UserInfo{Subject: "dora", Email: email, PreferredUsername: "dora@client.fi"}
			accounts := doraAccounts()
			accounts.users["sam@client.fi"] = &model.Account{Name: "sam@client.fi"}
			store := NewTokenStore()
			c, state := startLogin(t, tokens, f)

			rr := callback(tokens, f, accounts, store, callbackQuery("c", state), c)

			assertRedirect(t, rr, "/login?error=no_mailbox")
			assertNoSession(t, rr, store)
		})
	}
}

func TestCallbackProviderError(t *testing.T) {
	t.Parallel()

	tokens := newLoginTestTokens(t)
	f := signedInOIDC()
	store := NewTokenStore()
	c, state := startLogin(t, tokens, f)

	rr := callback(tokens, f, doraAccounts(), store, "error=access_denied&error_description=%3Cscript%3E&state="+state, c)

	assertRedirect(t, rr, "/login?error=denied")
	assertNoSession(t, rr, store)
	if f.exchanged {
		t.Fatal("exchanged a code after a provider error")
	}
}

func TestCallbackSignInFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(f *fakeOIDC, a *fakeAccounts)
		query func(state string) string
	}{
		{name: "exchange", setup: func(f *fakeOIDC, _ *fakeAccounts) { f.exchangeErr = errors.New("boom") }},
		{name: "userinfo", setup: func(f *fakeOIDC, _ *fakeAccounts) { f.userInfoErr = errors.New("boom") }},
		{name: "account lookup", setup: func(_ *fakeOIDC, a *fakeAccounts) { a.err = errors.New("stalwart down") }},
		{name: "missing code", query: func(state string) string { return "state=" + state }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tokens := newLoginTestTokens(t)
			f := signedInOIDC()
			accounts := doraAccounts()
			if tt.setup != nil {
				tt.setup(f, accounts)
			}
			store := NewTokenStore()
			c, state := startLogin(t, tokens, f)
			query := callbackQuery("c", state)
			if tt.query != nil {
				query = tt.query(state)
			}

			rr := callback(tokens, f, accounts, store, query, c)

			assertRedirect(t, rr, "/login?error=signin")
			assertNoSession(t, rr, store)
		})
	}
}
