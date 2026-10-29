package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestOIDCRefusesCrossHostRedirect(t *testing.T) {
	t.Parallel()
	other := newFakeProvider(t) // another listener, so another host:port
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.srv.URL+"/.well-known/openid-configuration", http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	c := New(Config{Issuer: redirector.URL, ClientID: "id", ClientSecret: "s", RedirectURL: "https://app/cb"}, nil)
	if _, err := c.AuthCodeURL(context.Background(), "s", "c"); err == nil {
		t.Fatal("expected an error for a redirect to another host")
	}
	if n := other.discoveryHits.Load(); n != 0 {
		t.Fatalf("the other host was contacted %d times", n)
	}
}

func TestOIDCFollowsSameHostRedirect(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/moved", http.StatusFound)
	})
	mux.HandleFunc("/moved", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 base,
			"authorization_endpoint": base + "/login",
			"token_endpoint":         base + "/auth/token",
			"userinfo_endpoint":      base + "/auth/userinfo",
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := New(Config{Issuer: srv.URL, ClientID: "id", ClientSecret: "s", RedirectURL: "https://app/cb"}, nil)
	if _, err := c.AuthCodeURL(context.Background(), "s", "c"); err != nil {
		t.Fatalf("same-host redirect: %v", err)
	}
}

func TestOIDCStopsAfterThreeRedirects(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Redirect(w, r, "/again", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	c := New(Config{Issuer: srv.URL, ClientID: "id", ClientSecret: "s", RedirectURL: "https://app/cb"}, nil)
	if _, err := c.AuthCodeURL(context.Background(), "s", "c"); err == nil {
		t.Fatal("expected an error after too many redirects")
	}
	if n := requests.Load(); n != 4 { // the original request + 3 followed redirects
		t.Fatalf("requests = %d, want 4", n)
	}
}

func TestRefusesHTTPSDowngradeRedirect(t *testing.T) {
	t.Parallel()
	check := New(Config{}, nil).httpClient.CheckRedirect
	if check == nil {
		t.Fatal("default client has no CheckRedirect")
	}
	httpsReq := &http.Request{URL: &url.URL{Scheme: "https", Host: "mail.example"}}
	httpReq := &http.Request{URL: &url.URL{Scheme: "http", Host: "mail.example"}}
	if err := check(httpReq, []*http.Request{httpsReq}); err == nil {
		t.Fatal("https -> http redirect was allowed")
	}
	sameHTTPS := &http.Request{URL: &url.URL{Scheme: "https", Host: "mail.example", Path: "/x"}}
	if err := check(sameHTTPS, []*http.Request{httpsReq}); err != nil {
		t.Fatalf("same-host https redirect refused: %v", err)
	}
}

func TestNewEnforcesRedirectPolicyOnSuppliedClient(t *testing.T) {
	t.Parallel()
	supplied := &http.Client{Timeout: 3 * time.Second}
	c := New(Config{}, supplied)
	if c.httpClient.CheckRedirect == nil || c.httpClient.Timeout != 3*time.Second {
		t.Fatalf("client = %#v, want CheckRedirect set and Timeout kept", c.httpClient)
	}
	if supplied.CheckRedirect != nil {
		t.Fatal("New mutated the caller's client")
	}
}
