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

	"github.com/operinko-labs/stalwart-users/internal/auth"
	"github.com/operinko-labs/stalwart-users/internal/stalwart"
)

const passwordTestJWTSecret = "0123456789abcdef0123456789abcdef"

type mockPasswordsStore struct {
	authOK  bool
	authErr error
	setErr  error

	authSeen    [2]string
	authCalls   int
	updatedName string
	updatedPass string
	updateCalls int
}

func (m *mockPasswordsStore) Authenticate(_ context.Context, name, password string) (bool, error) {
	m.authCalls++
	m.authSeen = [2]string{name, password}
	return m.authOK, m.authErr
}

func (m *mockPasswordsStore) SetPassword(name, password string) error {
	m.updateCalls++
	m.updatedName = name
	m.updatedPass = password
	return m.setErr
}

func TestChangePasswordHandlerUpdatesOwnPasswordWithValidCurrentPassword(t *testing.T) {
	t.Parallel()

	store := &mockPasswordsStore{authOK: true}
	rr := httptest.NewRecorder()

	serveChangePasswordRequest(t, store, rr, "alice", false, "/accounts/alice/password", `{"current_password":"old-password","new_password":"new-password"}`)

	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if store.authCalls != 1 || store.authSeen != [2]string{"alice", "old-password"} {
		t.Fatalf("Authenticate calls=%d seen=%v, want 1/alice old-password", store.authCalls, store.authSeen)
	}
	if store.updateCalls != 1 || store.updatedName != "alice" || store.updatedPass != "new-password" {
		t.Fatalf("SetPassword calls=%d name=%q pass=%q, want 1/alice/new-password", store.updateCalls, store.updatedName, store.updatedPass)
	}

	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if body["message"] != "password updated" {
		t.Fatalf("response body = %#v, want password updated message", body)
	}
}

func TestChangePasswordSelfChecksCurrent(t *testing.T) {
	t.Parallel()

	store := &mockPasswordsStore{authOK: false}
	rr := httptest.NewRecorder()

	serveChangePasswordRequest(t, store, rr, "alice", false, "/accounts/alice/password", `{"current_password":"wrong-password","new_password":"new-password"}`)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
	if store.updateCalls != 0 {
		t.Fatalf("SetPassword calls = %d, want 0", store.updateCalls)
	}
}

func TestChangePasswordHandlerReturnsServerErrorWhenCheckFails(t *testing.T) {
	t.Parallel()

	store := &mockPasswordsStore{authErr: errors.New("stalwart down")}
	rr := httptest.NewRecorder()

	serveChangePasswordRequest(t, store, rr, "alice", false, "/accounts/alice/password", `{"current_password":"old-password","new_password":"new-password"}`)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
	if store.updateCalls != 0 {
		t.Fatalf("SetPassword calls = %d, want 0", store.updateCalls)
	}
}

func TestChangePasswordWeakPassword(t *testing.T) {
	t.Parallel()

	store := &mockPasswordsStore{setErr: fmt.Errorf("update account: %w", stalwart.ErrInvalid{Description: "Password is too weak"})}
	rr := httptest.NewRecorder()

	serveChangePasswordRequest(t, store, rr, "admin", true, "/accounts/alice/password", `{"new_password":"weak"}`)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusBadRequest, rr.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if body["error"] != "Password is too weak" {
		t.Fatalf("error = %q, want Stalwart's description", body["error"])
	}
}

func TestChangePasswordHandlerAllowsAdminResetWithoutCurrentPassword(t *testing.T) {
	t.Parallel()

	store := &mockPasswordsStore{}
	rr := httptest.NewRecorder()

	serveChangePasswordRequest(t, store, rr, "admin", true, "/accounts/alice/password", `{"new_password":"new-password"}`)

	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if store.authCalls != 0 {
		t.Fatalf("Authenticate calls = %d, want 0", store.authCalls)
	}
	if store.updateCalls != 1 || store.updatedName != "alice" || store.updatedPass != "new-password" {
		t.Fatalf("SetPassword calls=%d name=%q, want 1/alice", store.updateCalls, store.updatedName)
	}
}

func TestChangePasswordHandlerRejectsNonAdminChangingAnotherUser(t *testing.T) {
	t.Parallel()

	store := &mockPasswordsStore{}
	rr := httptest.NewRecorder()

	serveChangePasswordRequest(t, store, rr, "alice", false, "/accounts/bob/password", `{"current_password":"old-password","new_password":"new-password"}`)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusForbidden)
	}
	if store.authCalls != 0 || store.updateCalls != 0 {
		t.Fatalf("store calls = get:%d update:%d, want 0/0", store.authCalls, store.updateCalls)
	}
}

func TestChangePasswordHandlerLetsDomainAdminsResetWithoutCurrentPassword(t *testing.T) {
	t.Parallel()

	store := &mockPasswordsStore{}
	rr := httptest.NewRecorder()

	serveDomainAdminPasswordRequest(store, rr, "bob@client.fi", `{"new_password":"new-password"}`)

	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if store.authCalls != 0 {
		t.Fatalf("Authenticate calls = %d, want 0", store.authCalls)
	}
	if store.updateCalls != 1 || store.updatedName != "bob@client.fi" {
		t.Fatalf("SetPassword calls=%d name=%q, want 1/bob@client.fi", store.updateCalls, store.updatedName)
	}
}

func TestChangePasswordHandlerRequiresCurrentPasswordForDomainAdminsOwnAccount(t *testing.T) {
	t.Parallel()

	store := &mockPasswordsStore{}
	rr := httptest.NewRecorder()

	serveDomainAdminPasswordRequest(store, rr, "dora@client.fi", `{"new_password":"new-password"}`)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	if store.updateCalls != 0 {
		t.Fatalf("SetPassword calls = %d, want 0", store.updateCalls)
	}
}

func TestChangePasswordHandlerTreatsMixedCaseOwnAccountAsSelf(t *testing.T) {
	t.Parallel()

	store := &mockPasswordsStore{}
	rr := httptest.NewRecorder()

	serveDomainAdminPasswordRequest(store, rr, "Dora@Client.fi", `{"new_password":"new-password"}`)

	assertError(t, rr, http.StatusBadRequest, "current_password is required")
	if store.updateCalls != 0 {
		t.Fatalf("SetPassword calls = %d, want 0", store.updateCalls)
	}
}

func TestChangePasswordHandlerRejectsDomainAdminsOutsideTheirDomains(t *testing.T) {
	t.Parallel()

	store := &mockPasswordsStore{}
	rr := httptest.NewRecorder()

	serveDomainAdminPasswordRequest(store, rr, "eve@other.fi", `{"new_password":"new-password"}`)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusForbidden)
	}
	if store.updateCalls != 0 {
		t.Fatalf("SetPassword calls = %d, want 0", store.updateCalls)
	}
}

func serveDomainAdminPasswordRequest(store passwordsStore, rr *httptest.ResponseRecorder, name, body string) {
	req := asDomainAdmin(httptest.NewRequest(http.MethodPut, "/accounts/"+name+"/password", strings.NewReader(body)), "client.fi")
	req.SetPathValue("name", name)

	newChangePasswordHandler(store).ServeHTTP(rr, req)
}

func TestChangePasswordHandlerReturnsNotFoundWhenAccountMissing(t *testing.T) {
	t.Parallel()

	store := &mockPasswordsStore{setErr: errAccountNotFound}
	rr := httptest.NewRecorder()

	serveChangePasswordRequest(t, store, rr, "admin", true, "/accounts/alice/password", `{"new_password":"new-password"}`)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestChangePasswordHandlerReturnsInternalServerErrorOnUpdateFailure(t *testing.T) {
	t.Parallel()

	store := &mockPasswordsStore{setErr: errors.New("boom")}
	rr := httptest.NewRecorder()

	serveChangePasswordRequest(t, store, rr, "admin", true, "/accounts/alice/password", `{"new_password":"new-password"}`)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func serveChangePasswordRequest(t *testing.T, store passwordsStore, rr *httptest.ResponseRecorder, username string, isAdmin bool, targetURL, body string) {
	t.Helper()

	tokens, err := auth.NewTokenManager(passwordTestJWTSecret)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}

	token, err := tokens.GenerateToken(username, isAdmin)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPut, targetURL, strings.NewReader(body))
	req.SetPathValue("name", strings.TrimPrefix(strings.TrimSuffix(targetURL, "/password"), "/accounts/"))
	req.AddCookie(&http.Cookie{Name: "token", Value: token})

	tokens.Middleware(newChangePasswordHandler(store)).ServeHTTP(rr, req)
}
