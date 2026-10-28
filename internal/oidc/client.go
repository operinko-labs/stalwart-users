// Package oidc is a minimal OpenID Connect client for Stalwart's OIDC
// provider: authorization code flow with PKCE (S256), confidential client
// authenticating with HTTP Basic (client_secret_basic).
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	scope = "openid offline_access"

	// maxBodyBytes bounds how much of any provider response is read.
	maxBodyBytes = 1 << 20
)

type Config struct {
	Issuer, ClientID, ClientSecret, RedirectURL string
}

type Tokens struct {
	AccessToken, RefreshToken string
	ExpiresAt                 time.Time // now + expires_in
}

type UserInfo struct{ Subject, Email, PreferredUsername string }

type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

type Client struct {
	cfg        Config
	httpClient *http.Client

	mu   sync.Mutex
	disc *discovery
}

// New returns a client for cfg. A nil httpClient gets one with a 15s timeout.
func New(cfg Config, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{cfg: cfg, httpClient: httpClient}
}

// discover fetches the discovery document on first use and caches it. A
// failed fetch is not cached, so a later call retries.
func (c *Client) discover(ctx context.Context) (*discovery, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.disc != nil {
		return c.disc, nil
	}

	issuer := strings.TrimSuffix(c.cfg.Issuer, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc discovery: unexpected status %d", resp.StatusCode)
	}
	var d discovery
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("oidc discovery: decode: %w", err)
	}
	if strings.TrimSuffix(d.Issuer, "/") != issuer {
		return nil, fmt.Errorf("oidc discovery: issuer mismatch: got %q, want %q", d.Issuer, issuer)
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.UserinfoEndpoint == "" {
		return nil, errors.New("oidc discovery: document is missing required endpoints")
	}
	c.disc = &d
	return c.disc, nil
}

// AuthCodeURL returns the authorization endpoint URL to send the browser to.
func (c *Client) AuthCodeURL(ctx context.Context, state, codeChallenge string) (string, error) {
	d, err := c.discover(ctx)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(d.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("oidc: authorization endpoint: %w", err)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", c.cfg.ClientID)
	q.Set("redirect_uri", c.cfg.RedirectURL)
	q.Set("scope", scope)
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Exchange trades an authorization code (and its PKCE verifier) for tokens.
func (c *Client) Exchange(ctx context.Context, code, codeVerifier string) (Tokens, error) {
	return c.token(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.cfg.RedirectURL},
		"code_verifier": {codeVerifier},
	}, "")
}

// Refresh obtains a new access token. If the provider does not rotate the
// refresh token, the one passed in is kept.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (Tokens, error) {
	return c.token(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}, refreshToken)
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

type oauthError struct {
	Error string `json:"error"`
}

// token POSTs form to the token endpoint. Errors carry only the HTTP status
// and the OAuth error code, never the request values or the response tokens.
func (c *Client) token(ctx context.Context, form url.Values, keepRefresh string) (Tokens, error) {
	d, err := c.discover(ctx)
	if err != nil {
		return Tokens{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Tokens{}, errors.New("oidc token: build request failed")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// RFC 6749 section 2.3.1: form-urlencode id and secret before Basic encoding.
	req.SetBasicAuth(url.QueryEscape(c.cfg.ClientID), url.QueryEscape(c.cfg.ClientSecret))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return Tokens{}, fmt.Errorf("oidc token: request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return Tokens{}, errors.New("oidc token: read response failed")
	}
	if resp.StatusCode != http.StatusOK {
		var oe oauthError
		if json.Unmarshal(body, &oe) == nil && oe.Error != "" && len(oe.Error) <= 64 {
			return Tokens{}, fmt.Errorf("oidc token: status %d: %s", resp.StatusCode, oe.Error)
		}
		return Tokens{}, fmt.Errorf("oidc token: status %d", resp.StatusCode)
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return Tokens{}, errors.New("oidc token: decode response failed")
	}
	if tr.AccessToken == "" {
		return Tokens{}, errors.New("oidc token: response has no access_token")
	}
	t := Tokens{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second),
	}
	if t.RefreshToken == "" {
		t.RefreshToken = keepRefresh
	}
	return t, nil
}

// UserInfo fetches the userinfo claims for accessToken.
func (c *Client) UserInfo(ctx context.Context, accessToken string) (UserInfo, error) {
	d, err := c.discover(ctx)
	if err != nil {
		return UserInfo{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.UserinfoEndpoint, nil)
	if err != nil {
		return UserInfo{}, errors.New("oidc userinfo: build request failed")
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return UserInfo{}, fmt.Errorf("oidc userinfo: request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return UserInfo{}, errors.New("oidc userinfo: read response failed")
	}
	if resp.StatusCode != http.StatusOK {
		return UserInfo{}, fmt.Errorf("oidc userinfo: status %d", resp.StatusCode)
	}
	var raw struct {
		Sub               string `json:"sub"`
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return UserInfo{}, errors.New("oidc userinfo: decode response failed")
	}
	return UserInfo{Subject: raw.Sub, Email: raw.Email, PreferredUsername: raw.PreferredUsername}, nil
}

// NewPKCE returns a fresh PKCE verifier (32 random bytes, base64url without
// padding) and its S256 challenge.
func NewPKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("oidc pkce: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	return verifier, challengeS256(verifier), nil
}

func challengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
