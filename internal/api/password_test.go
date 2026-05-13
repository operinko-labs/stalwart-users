package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/operinko-labs/stalwart-users/internal/auth"
)

const passwordTestJWTSecret = "0123456789abcdef0123456789abcdef"

type mockPasswordsStore struct {
	getAccountSecretResult string
	getAccountSecretErr    error
	updateAccountErr       error

	getAccountSecretName string
	updatedName          string
	updatedSecret        string
	getSecretCalls       int
	updateCalls          int
}

func (m *mockPasswordsStore) GetAccountSecret(name string) (string, error) {
	m.getSecretCalls++
	m.getAccountSecretName = name
	return m.getAccountSecretResult, m.getAccountSecretErr
}

func (m *mockPasswordsStore) UpdateAccountPassword(name, secret string) error {
	m.updateCalls++
	m.updatedName = name
	m.updatedSecret = secret
	return m.updateAccountErr
}

func TestChangePasswordHandlerUpdatesOwnPasswordWithValidCurrentPassword(t *testing.T) {
	t.Parallel()

	currentSecret, err := auth.HashSSHA512("old-password")
	if err != nil {
		t.Fatalf("HashSSHA512() error = %v", err)
	}

	store := &mockPasswordsStore{getAccountSecretResult: currentSecret}
	rr := httptest.NewRecorder()

	serveChangePasswordRequest(t, store, rr, "alice", false, "/accounts/alice/password", `{"current_password":"old-password","new_password":"new-password"}`)

	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if store.getSecretCalls != 1 || store.getAccountSecretName != "alice" {
		t.Fatalf("GetAccountSecret calls=%d name=%q, want 1/alice", store.getSecretCalls, store.getAccountSecretName)
	}
	if store.updateCalls != 1 || store.updatedName != "alice" {
		t.Fatalf("UpdateAccountPassword calls=%d name=%q, want 1/alice", store.updateCalls, store.updatedName)
	}
	if !auth.VerifyPassword("new-password", store.updatedSecret) {
		t.Fatal("updated secret does not verify new password")
	}

	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if body["message"] != "password updated" {
		t.Fatalf("response body = %#v, want password updated message", body)
	}
}

func TestChangePasswordHandlerRejectsInvalidCurrentPassword(t *testing.T) {
	t.Parallel()

	currentSecret, err := auth.HashSSHA512("old-password")
	if err != nil {
		t.Fatalf("HashSSHA512() error = %v", err)
	}

	store := &mockPasswordsStore{getAccountSecretResult: currentSecret}
	rr := httptest.NewRecorder()

	serveChangePasswordRequest(t, store, rr, "alice", false, "/accounts/alice/password", `{"current_password":"wrong-password","new_password":"new-password"}`)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
	if store.updateCalls != 0 {
		t.Fatalf("UpdateAccountPassword calls = %d, want 0", store.updateCalls)
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
	if store.getSecretCalls != 0 {
		t.Fatalf("GetAccountSecret calls = %d, want 0", store.getSecretCalls)
	}
	if store.updateCalls != 1 || store.updatedName != "alice" {
		t.Fatalf("UpdateAccountPassword calls=%d name=%q, want 1/alice", store.updateCalls, store.updatedName)
	}
	if !auth.VerifyPassword("new-password", store.updatedSecret) {
		t.Fatal("updated secret does not verify new password")
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
	if store.getSecretCalls != 0 || store.updateCalls != 0 {
		t.Fatalf("store calls = get:%d update:%d, want 0/0", store.getSecretCalls, store.updateCalls)
	}
}

func TestChangePasswordHandlerReturnsNotFoundWhenAccountMissing(t *testing.T) {
	t.Parallel()

	store := &mockPasswordsStore{getAccountSecretErr: errAccountNotFound}
	rr := httptest.NewRecorder()

	serveChangePasswordRequest(t, store, rr, "alice", false, "/accounts/alice/password", `{"current_password":"old-password","new_password":"new-password"}`)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusNotFound)
	}
	if store.updateCalls != 0 {
		t.Fatalf("UpdateAccountPassword calls = %d, want 0", store.updateCalls)
	}
}

func TestChangePasswordHandlerReturnsInternalServerErrorOnUpdateFailure(t *testing.T) {
	t.Parallel()

	store := &mockPasswordsStore{updateAccountErr: errors.New("boom")}
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
