package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeProvider struct {
	srv            *httptest.Server
	discoveryHits  atomic.Int32
	issuerOverride atomic.Value // string
	tokenHandler   func(w http.ResponseWriter, r *http.Request)
	userinfoAuth   atomic.Value // string
	userinfoStatus int
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	p := &fakeProvider{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		p.discoveryHits.Add(1)
		issuer := p.srv.URL
		if o, _ := p.issuerOverride.Load().(string); o != "" {
			issuer = o
		}
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": p.srv.URL + "/login",
			"token_endpoint":         p.srv.URL + "/auth/token",
			"userinfo_endpoint":      p.srv.URL + "/auth/userinfo",
		})
	})
	mux.HandleFunc("/auth/token", func(w http.ResponseWriter, r *http.Request) {
		p.tokenHandler(w, r)
	})
	mux.HandleFunc("/auth/userinfo", func(w http.ResponseWriter, r *http.Request) {
		p.userinfoAuth.Store(r.Header.Get("Authorization"))
		if p.userinfoStatus != 0 {
			http.Error(w, "nope", p.userinfoStatus)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"sub": "42", "email": "alice@example.com", "preferred_username": "alice", "name": "ignored",
		})
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeProvider) client() *Client {
	return New(Config{
		Issuer:       p.srv.URL,
		ClientID:     "my id",
		ClientSecret: "s3cr&t",
		RedirectURL:  "https://app.example/api/auth/callback",
	}, p.srv.Client())
}

func TestAuthCodeURLParameters(t *testing.T) {
	t.Parallel()
	p := newFakeProvider(t)
	c := p.client()

	for i := 0; i < 2; i++ {
		raw, err := c.AuthCodeURL(context.Background(), "state123", "challenge456")
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := u.Scheme + "://" + u.Host + u.Path; got != p.srv.URL+"/login" {
			t.Fatalf("endpoint = %s", got)
		}
		want := map[string]string{
			"response_type":         "code",
			"client_id":             "my id",
			"redirect_uri":          "https://app.example/api/auth/callback",
			"scope":                 "openid offline_access",
			"state":                 "state123",
			"code_challenge":        "challenge456",
			"code_challenge_method": "S256",
		}
		q := u.Query()
		for k, v := range want {
			if q.Get(k) != v {
				t.Errorf("%s = %q, want %q", k, q.Get(k), v)
			}
		}
	}
	if n := p.discoveryHits.Load(); n != 1 {
		t.Fatalf("discovery fetched %d times, want 1", n)
	}
}

func TestDiscoveryIssuerMismatch(t *testing.T) {
	t.Parallel()
	p := newFakeProvider(t)
	p.issuerOverride.Store("https://evil.example")
	c := p.client()
	if _, err := c.AuthCodeURL(context.Background(), "s", "c"); err == nil {
		t.Fatal("expected issuer mismatch error")
	}
	// A failed fetch is retried, and succeeds once the provider is fixed.
	p.issuerOverride.Store(p.srv.URL + "/") // trailing slash tolerated
	if _, err := c.AuthCodeURL(context.Background(), "s", "c"); err != nil {
		t.Fatalf("retry after failure: %v", err)
	}
	if n := p.discoveryHits.Load(); n != 2 {
		t.Fatalf("discovery hits = %d, want 2", n)
	}
}

func TestExchangeSendsBasicAuthAndVerifier(t *testing.T) {
	t.Parallel()
	p := newFakeProvider(t)
	var gotForm url.Values
	var gotUser, gotPass string
	var basicOK bool
	p.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("content-type = %q", ct)
		}
		r.ParseForm()
		gotForm = r.PostForm
		gotUser, gotPass, basicOK = r.BasicAuth()
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "token_type": "bearer", "expires_in": 300, "refresh_token": "rt",
		})
	}
	before := time.Now()
	tok, err := p.client().Exchange(context.Background(), "the-code", "the-verifier")
	if err != nil {
		t.Fatal(err)
	}
	if !basicOK {
		t.Fatal("no basic auth")
	}
	// RFC 6749 section 2.3.1: id and secret are form-urlencoded before Basic encoding.
	if gotUser != "my+id" || gotPass != "s3cr%26t" {
		t.Errorf("basic creds = %q / %q", gotUser, gotPass)
	}
	for k, v := range map[string]string{
		"grant_type":    "authorization_code",
		"code":          "the-code",
		"redirect_uri":  "https://app.example/api/auth/callback",
		"code_verifier": "the-verifier",
	} {
		if gotForm.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, gotForm.Get(k), v)
		}
	}
	if gotForm.Get("client_secret") != "" {
		t.Error("client secret must not be in the body")
	}
	if tok.AccessToken != "at" || tok.RefreshToken != "rt" {
		t.Errorf("tokens = %+v", tok)
	}
	if d := tok.ExpiresAt.Sub(before); d < 299*time.Second || d > 302*time.Second {
		t.Errorf("ExpiresAt offset = %v", d)
	}
}

func TestExchangeError(t *testing.T) {
	t.Parallel()
	p := newFakeProvider(t)
	p.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant","error_description":"bad"}`))
	}
	_, err := p.client().Exchange(context.Background(), "SECRET-CODE", "SECRET-VERIFIER")
	if err == nil {
		t.Fatal("expected error")
	}
	for _, s := range []string{"SECRET-CODE", "SECRET-VERIFIER", "s3cr&t", "s3cr%26t"} {
		if strings.Contains(err.Error(), s) {
			t.Errorf("error leaks %q: %v", s, err)
		}
	}
	if !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("error should name the OAuth error: %v", err)
	}
}

func TestExchangeRejectsEmptyAccessToken(t *testing.T) {
	t.Parallel()
	p := newFakeProvider(t)
	p.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"token_type":"bearer","expires_in":1}`))
	}
	if _, err := p.client().Exchange(context.Background(), "c", "v"); err == nil {
		t.Fatal("expected error for missing access_token")
	}
}

func TestRefreshKeepsRefreshToken(t *testing.T) {
	t.Parallel()
	p := newFakeProvider(t)
	var gotForm url.Values
	respond := map[string]any{"access_token": "at2", "token_type": "bearer", "expires_in": 60}
	p.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		gotForm = r.PostForm
		json.NewEncoder(w).Encode(respond)
	}
	c := p.client()

	tok, err := c.Refresh(context.Background(), "old-rt")
	if err != nil {
		t.Fatal(err)
	}
	if gotForm.Get("grant_type") != "refresh_token" || gotForm.Get("refresh_token") != "old-rt" {
		t.Errorf("form = %v", gotForm)
	}
	if tok.AccessToken != "at2" || tok.RefreshToken != "old-rt" {
		t.Errorf("tokens = %+v", tok)
	}

	respond["refresh_token"] = "new-rt"
	tok, err = c.Refresh(context.Background(), "old-rt")
	if err != nil {
		t.Fatal(err)
	}
	if tok.RefreshToken != "new-rt" {
		t.Errorf("refresh token = %q, want rotated", tok.RefreshToken)
	}
}

func TestUserInfo(t *testing.T) {
	t.Parallel()
	p := newFakeProvider(t)
	ui, err := p.client().UserInfo(context.Background(), "the-at")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.userinfoAuth.Load(); got != "Bearer the-at" {
		t.Errorf("Authorization = %v", got)
	}
	if ui != (UserInfo{Subject: "42", Email: "alice@example.com", PreferredUsername: "alice"}) {
		t.Errorf("userinfo = %+v", ui)
	}
}

func TestUserInfoErrorDoesNotLeakToken(t *testing.T) {
	t.Parallel()
	p := newFakeProvider(t)
	p.userinfoStatus = http.StatusUnauthorized
	_, err := p.client().UserInfo(context.Background(), "SECRET-AT")
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "SECRET-AT") {
		t.Errorf("error leaks token: %v", err)
	}
}

func TestNewPKCE(t *testing.T) {
	t.Parallel()
	// RFC 7636 Appendix B.
	if got := challengeS256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Errorf("challenge = %s", got)
	}
	v, ch, err := NewPKCE()
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 43 || strings.ContainsAny(v, "=+/") {
		t.Errorf("verifier = %q", v)
	}
	if ch != challengeS256(v) {
		t.Error("challenge does not match verifier")
	}
	v2, _, _ := NewPKCE()
	if v == v2 {
		t.Error("verifiers must differ")
	}
}
