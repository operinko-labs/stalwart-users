package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/operinko-labs/stalwart-users/internal/auth"
	"github.com/operinko-labs/stalwart-users/internal/oidc"
	"github.com/operinko-labs/stalwart-users/internal/stalwart"
)

const passwordTestJWTSecret = "0123456789abcdef0123456789abcdef"

var passwordTestNow = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

type mockPasswordsStore struct {
	setErr error

	updatedName string
	updatedPass string
	updateCalls int
}

func (m *mockPasswordsStore) SetPassword(name, password string) error {
	m.updateCalls++
	m.updatedName = name
	m.updatedPass = password
	return m.setErr
}

type fakeSessionTokens struct {
	entries map[string]oidc.Tokens
	puts    int
}

func (f *fakeSessionTokens) Get(sessionID string) (oidc.Tokens, bool) {
	t, ok := f.entries[sessionID]
	return t, ok
}

func (f *fakeSessionTokens) Put(sessionID string, t oidc.Tokens) {
	f.puts++
	f.entries[sessionID] = t
}

type fakeRefresher struct {
	result oidc.Tokens
	err    error

	calls int
	seen  string
}

func (f *fakeRefresher) Refresh(_ context.Context, refreshToken string) (oidc.Tokens, error) {
	f.calls++
	f.seen = refreshToken
	return f.result, f.err
}

type ownPasswordCall struct{ accessToken, current, next, otpCode string }

type fakeOwnPassword struct {
	errs  []error // returned in order; nil once exhausted
	calls []ownPasswordCall
	// blockUntilDone makes the call wait for its context, like a hung Stalwart.
	blockUntilDone bool
}

func (f *fakeOwnPassword) ChangeOwnPassword(ctx context.Context, accessToken, current, next, otpCode string) error {
	f.calls = append(f.calls, ownPasswordCall{accessToken, current, next, otpCode})
	if f.blockUntilDone {
		<-ctx.Done()
		return ctx.Err()
	}
	if len(f.errs) == 0 {
		return nil
	}
	err := f.errs[0]
	f.errs = f.errs[1:]
	return err
}

type passwordFixture struct {
	store     *mockPasswordsStore
	tokens    *fakeSessionTokens
	refresher *fakeRefresher
	stalwart  *fakeOwnPassword

	// stored, when set, is what the token store holds for the request's session.
	stored *oidc.Tokens
	// domains, when set, makes the user a domain admin for them.
	domains []string
	// sessionID is the id of the last request's session.
	sessionID string
	// timeout is the handler's outbound-call timeout; zero keeps the default.
	timeout time.Duration
}

func newPasswordFixture() *passwordFixture {
	return &passwordFixture{
		store:     &mockPasswordsStore{},
		tokens:    &fakeSessionTokens{entries: map[string]oidc.Tokens{}},
		refresher: &fakeRefresher{},
		stalwart:  &fakeOwnPassword{},
	}
}

// serve sends a password change for name through the session middleware, as
// username, so the handler sees the session id the way it does in production.
func (f *passwordFixture) serve(t *testing.T, username string, isAdmin bool, name, body string) *httptest.ResponseRecorder {
	t.Helper()

	manager, err := auth.NewTokenManager(passwordTestJWTSecret)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}
	token, sessionID, err := manager.GenerateToken(username, isAdmin)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	f.sessionID = sessionID
	if f.stored != nil {
		f.tokens.entries[sessionID] = *f.stored
	}

	req := httptest.NewRequest(http.MethodPut, "/accounts/"+name+"/password", strings.NewReader(body))
	req.SetPathValue("name", name)
	req.AddCookie(&http.Cookie{Name: "token", Value: token})
	if f.domains != nil {
		req = req.WithContext(auth.WithAdminDomains(req.Context(), f.domains))
	}

	h := &passwordHandler{
		store:     f.store,
		tokens:    f.tokens,
		refresher: f.refresher,
		stalwart:  f.stalwart,
		now:       func() time.Time { return passwordTestNow },
		timeout:   f.timeout,
	}
	rr := httptest.NewRecorder()
	manager.Middleware(h).ServeHTTP(rr, req)
	return rr
}

func freshTokens() *oidc.Tokens {
	return &oidc.Tokens{AccessToken: "user-at", RefreshToken: "user-rt", ExpiresAt: passwordTestNow.Add(time.Hour)}
}

const selfChangeBody = `{"current_password":"old-password","new_password":"new-password"}`

func assertMessage(t *testing.T, rr *httptest.ResponseRecorder, message string) {
	t.Helper()

	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if body["message"] != message {
		t.Fatalf("response body = %#v, want message %q", body, message)
	}
}

func TestChangeOwnPasswordUsesUserToken(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture()
	f.stored = freshTokens()

	rr := f.serve(t, "alice@erinko.fi", false, "alice@erinko.fi", `{"current_password":"old-password","new_password":"new-password","otp_code":"123456"}`)

	assertMessage(t, rr, "password updated")
	want := []ownPasswordCall{{"user-at", "old-password", "new-password", "123456"}}
	if fmt.Sprint(f.stalwart.calls) != fmt.Sprint(want) {
		t.Fatalf("ChangeOwnPassword calls = %v, want %v", f.stalwart.calls, want)
	}
	if f.store.updateCalls != 0 {
		t.Fatalf("SetPassword calls = %d, want 0 (no admin API for self-service)", f.store.updateCalls)
	}
	if f.refresher.calls != 0 || f.tokens.puts != 0 {
		t.Fatalf("refresh calls=%d puts=%d, want 0/0 for a fresh token", f.refresher.calls, f.tokens.puts)
	}
}

func TestChangeOwnPasswordDomainAdminSelfUsesUserToken(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture()
	f.stored = freshTokens()
	f.domains = []string{"client.fi"}

	rr := f.serve(t, "dora@client.fi", false, "Dora@Client.fi", selfChangeBody)

	assertMessage(t, rr, "password updated")
	if len(f.stalwart.calls) != 1 || f.stalwart.calls[0].accessToken != "user-at" {
		t.Fatalf("ChangeOwnPassword calls = %v, want one with the user token", f.stalwart.calls)
	}
	if f.store.updateCalls != 0 {
		t.Fatalf("SetPassword calls = %d, want 0", f.store.updateCalls)
	}
}

func TestChangeOwnPasswordRefreshesExpiredToken(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture()
	f.stored = &oidc.Tokens{AccessToken: "old-at", RefreshToken: "old-rt", ExpiresAt: passwordTestNow.Add(20 * time.Second)}
	f.refresher.result = oidc.Tokens{AccessToken: "new-at", RefreshToken: "new-rt", ExpiresAt: passwordTestNow.Add(time.Hour)}

	rr := f.serve(t, "alice@erinko.fi", false, "alice@erinko.fi", selfChangeBody)

	assertMessage(t, rr, "password updated")
	if f.refresher.calls != 1 || f.refresher.seen != "old-rt" {
		t.Fatalf("Refresh calls=%d seen=%q, want 1/old-rt", f.refresher.calls, f.refresher.seen)
	}
	if f.tokens.puts != 1 || f.tokens.entries[f.sessionID] != f.refresher.result {
		t.Fatalf("puts=%d stored=%v, want the refreshed tokens stored once", f.tokens.puts, f.tokens.entries[f.sessionID])
	}
	if len(f.stalwart.calls) != 1 || f.stalwart.calls[0].accessToken != "new-at" {
		t.Fatalf("ChangeOwnPassword calls = %v, want one with the refreshed token", f.stalwart.calls)
	}
}

func TestChangeOwnPasswordRefreshesOnceOnUnauthorized(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture()
	f.stored = freshTokens()
	f.refresher.result = oidc.Tokens{AccessToken: "new-at", RefreshToken: "new-rt", ExpiresAt: passwordTestNow.Add(time.Hour)}
	f.stalwart.errs = []error{fmt.Errorf("x:AccountPassword/set: %w", stalwart.ErrUnauthorized)}

	rr := f.serve(t, "alice@erinko.fi", false, "alice@erinko.fi", selfChangeBody)

	assertMessage(t, rr, "password updated")
	if f.refresher.calls != 1 || f.tokens.puts != 1 {
		t.Fatalf("refresh calls=%d puts=%d, want 1/1", f.refresher.calls, f.tokens.puts)
	}
	if len(f.stalwart.calls) != 2 || f.stalwart.calls[0].accessToken != "user-at" || f.stalwart.calls[1].accessToken != "new-at" {
		t.Fatalf("ChangeOwnPassword calls = %v, want user-at then new-at", f.stalwart.calls)
	}
}

func TestChangeOwnPasswordReauthWhenStillUnauthorized(t *testing.T) {
	t.Parallel()

	unauthorized := fmt.Errorf("x:AccountPassword/set: %w", stalwart.ErrUnauthorized)
	tests := []struct {
		name         string
		stored       oidc.Tokens
		wantRefresh  int
		wantAttempts int
	}{
		{"retried after refresh", *freshTokens(), 1, 2},
		// A token refreshed just now is not refreshed a second time.
		{"just refreshed", oidc.Tokens{AccessToken: "old-at", RefreshToken: "old-rt", ExpiresAt: passwordTestNow}, 1, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newPasswordFixture()
			f.stored = &tt.stored
			f.refresher.result = oidc.Tokens{AccessToken: "new-at", RefreshToken: "new-rt", ExpiresAt: passwordTestNow.Add(time.Hour)}
			f.stalwart.errs = []error{unauthorized, unauthorized}

			rr := f.serve(t, "alice@erinko.fi", false, "alice@erinko.fi", selfChangeBody)

			assertError(t, rr, http.StatusUnauthorized, "reauth_required")
			if f.refresher.calls != tt.wantRefresh || len(f.stalwart.calls) != tt.wantAttempts {
				t.Fatalf("refresh calls=%d attempts=%d, want %d/%d", f.refresher.calls, len(f.stalwart.calls), tt.wantRefresh, tt.wantAttempts)
			}
		})
	}
}

func TestChangeOwnPasswordReauthWhenRefreshFails(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		stored      oidc.Tokens
		refreshErr  error
		wantRefresh int
	}{
		{"refresh error", oidc.Tokens{AccessToken: "old-at", RefreshToken: "old-rt", ExpiresAt: passwordTestNow.Add(-time.Minute)}, errors.New("oidc token: status 400: invalid_grant"), 1},
		{"no refresh token", oidc.Tokens{AccessToken: "old-at", ExpiresAt: passwordTestNow.Add(10 * time.Second)}, nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newPasswordFixture()
			f.stored = &tt.stored
			f.refresher.err = tt.refreshErr

			rr := f.serve(t, "alice@erinko.fi", false, "alice@erinko.fi", selfChangeBody)

			assertError(t, rr, http.StatusUnauthorized, "reauth_required")
			if f.refresher.calls != tt.wantRefresh {
				t.Fatalf("Refresh calls = %d, want %d", f.refresher.calls, tt.wantRefresh)
			}
			if len(f.stalwart.calls) != 0 || f.tokens.puts != 0 || f.store.updateCalls != 0 {
				t.Fatalf("attempts=%d puts=%d SetPassword=%d, want 0/0/0", len(f.stalwart.calls), f.tokens.puts, f.store.updateCalls)
			}
		})
	}
}

func TestChangeOwnPasswordReauthWhenNoTokens(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture()

	rr := f.serve(t, "alice@erinko.fi", false, "alice@erinko.fi", selfChangeBody)

	assertError(t, rr, http.StatusUnauthorized, "reauth_required")
	if len(f.stalwart.calls) != 0 || f.store.updateCalls != 0 || f.refresher.calls != 0 {
		t.Fatalf("attempts=%d SetPassword=%d refresh=%d, want 0/0/0", len(f.stalwart.calls), f.store.updateCalls, f.refresher.calls)
	}
}

func TestChangeOwnPasswordOtpRequired(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture()
	f.stored = freshTokens()
	f.stalwart.errs = []error{fmt.Errorf("change own password: %w", stalwart.ErrOTPRequired)}

	rr := f.serve(t, "alice@erinko.fi", false, "alice@erinko.fi", selfChangeBody)

	assertError(t, rr, http.StatusBadRequest, "otp_required")
}

func TestChangeOwnPasswordMapsStalwartErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		err     error
		status  int
		message string
	}{
		{"wrong current password", stalwart.ErrCurrentPasswordIncorrect, http.StatusUnauthorized, "invalid current password"},
		{"weak password", stalwart.ErrInvalid{Description: "Password is too weak"}, http.StatusBadRequest, "Password is too weak"},
		{"not allowed", stalwart.ErrPasswordChangeNotAllowed, http.StatusForbidden, "password change not allowed"},
		{"anything else", errors.New("x:AccountPassword/set request failed with status 429"), http.StatusInternalServerError, "internal error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newPasswordFixture()
			f.stored = freshTokens()
			f.stalwart.errs = []error{fmt.Errorf("change own password: %w", tt.err)}

			rr := f.serve(t, "alice@erinko.fi", false, "alice@erinko.fi", `{"current_password":"old-password","new_password":"new-password","otp_code":"123456"}`)

			assertError(t, rr, tt.status, tt.message)
			for _, secret := range []string{"old-password", "new-password", "123456", "user-at", "user-rt"} {
				if strings.Contains(rr.Body.String(), secret) {
					t.Fatalf("response %q leaks a secret", rr.Body.String())
				}
			}
			if f.store.updateCalls != 0 {
				t.Fatalf("SetPassword calls = %d, want 0", f.store.updateCalls)
			}
		})
	}
}

func TestChangeOwnPasswordTimesOutWhenStalwartHangs(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture()
	f.stored = freshTokens()
	f.stalwart.blockUntilDone = true
	f.timeout = 50 * time.Millisecond

	start := time.Now()
	rr := f.serve(t, "alice@erinko.fi", false, "alice@erinko.fi", selfChangeBody)

	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("handler took %v, want it to give up after the timeout", elapsed)
	}
	assertError(t, rr, http.StatusInternalServerError, "internal error")
}

func TestChangeOwnPasswordRequiresCurrentPassword(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture()
	f.stored = freshTokens()

	rr := f.serve(t, "alice@erinko.fi", false, "alice@erinko.fi", `{"new_password":"new-password"}`)

	assertError(t, rr, http.StatusBadRequest, "current_password is required")
	if len(f.stalwart.calls) != 0 || f.store.updateCalls != 0 {
		t.Fatalf("attempts=%d SetPassword=%d, want 0/0", len(f.stalwart.calls), f.store.updateCalls)
	}
}

func TestAdminResetStillUsesAdminKey(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture()
	f.stored = freshTokens()

	rr := f.serve(t, "admin@erinko.fi", true, "alice@erinko.fi", `{"new_password":"new-password"}`)

	assertMessage(t, rr, "password updated")
	if f.store.updateCalls != 1 || f.store.updatedName != "alice@erinko.fi" || f.store.updatedPass != "new-password" {
		t.Fatalf("SetPassword calls=%d name=%q pass=%q, want 1/alice@erinko.fi/new-password", f.store.updateCalls, f.store.updatedName, f.store.updatedPass)
	}
	if len(f.stalwart.calls) != 0 || f.refresher.calls != 0 {
		t.Fatalf("attempts=%d refresh=%d, want 0/0", len(f.stalwart.calls), f.refresher.calls)
	}
}

func TestChangePasswordFullAdminSelfUsesAdminKey(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture()
	f.stored = freshTokens()

	rr := f.serve(t, "admin@erinko.fi", true, "Admin@erinko.fi", `{"new_password":"new-password"}`)

	assertMessage(t, rr, "password updated")
	if f.store.updateCalls != 1 || len(f.stalwart.calls) != 0 {
		t.Fatalf("SetPassword calls=%d attempts=%d, want 1/0", f.store.updateCalls, len(f.stalwart.calls))
	}
}

func TestChangePasswordWeakPassword(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture()
	f.store.setErr = fmt.Errorf("update account: %w", stalwart.ErrInvalid{Description: "Password is too weak"})

	rr := f.serve(t, "admin", true, "alice", `{"new_password":"weak"}`)

	assertError(t, rr, http.StatusBadRequest, "Password is too weak")
}

func TestChangePasswordHandlerRejectsNonAdminChangingAnotherUser(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture()
	f.stored = freshTokens()

	rr := f.serve(t, "alice", false, "bob", selfChangeBody)

	assertError(t, rr, http.StatusForbidden, "forbidden")
	if len(f.stalwart.calls) != 0 || f.store.updateCalls != 0 {
		t.Fatalf("attempts=%d SetPassword=%d, want 0/0", len(f.stalwart.calls), f.store.updateCalls)
	}
}

func TestChangePasswordHandlerLetsDomainAdminsResetWithoutCurrentPassword(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture()
	f.domains = []string{"client.fi"}

	rr := f.serve(t, "dora@client.fi", false, "bob@client.fi", `{"new_password":"new-password"}`)

	assertMessage(t, rr, "password updated")
	if f.store.updateCalls != 1 || f.store.updatedName != "bob@client.fi" || len(f.stalwart.calls) != 0 {
		t.Fatalf("SetPassword calls=%d name=%q attempts=%d, want 1/bob@client.fi/0", f.store.updateCalls, f.store.updatedName, len(f.stalwart.calls))
	}
}

func TestChangePasswordHandlerTreatsMixedCaseOwnAccountAsSelf(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture()
	f.domains = []string{"client.fi"}

	rr := f.serve(t, "dora@client.fi", false, "Dora@Client.fi", `{"new_password":"new-password"}`)

	assertError(t, rr, http.StatusBadRequest, "current_password is required")
	if f.store.updateCalls != 0 {
		t.Fatalf("SetPassword calls = %d, want 0", f.store.updateCalls)
	}
}

func TestChangePasswordHandlerRejectsDomainAdminsOutsideTheirDomains(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture()
	f.domains = []string{"client.fi"}

	rr := f.serve(t, "dora@client.fi", false, "eve@other.fi", `{"new_password":"new-password"}`)

	assertError(t, rr, http.StatusForbidden, "forbidden")
	if f.store.updateCalls != 0 {
		t.Fatalf("SetPassword calls = %d, want 0", f.store.updateCalls)
	}
}

func TestChangePasswordHandlerReturnsNotFoundWhenAccountMissing(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture()
	f.store.setErr = errAccountNotFound

	rr := f.serve(t, "admin", true, "alice", `{"new_password":"new-password"}`)

	assertError(t, rr, http.StatusNotFound, "account not found")
}

func TestChangePasswordHandlerReturnsInternalServerErrorOnUpdateFailure(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture()
	f.store.setErr = errors.New("boom")

	rr := f.serve(t, "admin", true, "alice", `{"new_password":"new-password"}`)

	assertError(t, rr, http.StatusInternalServerError, "internal error")
}
