package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/operinko-labs/stalwart-users/internal/auth"
	"github.com/operinko-labs/stalwart-users/internal/model"
)

type mockAccountsStore struct {
	listAccountsResult []model.Account
	listAccountsErr    error
	getAccountResult   *model.Account
	getAccountErr      error
	createAccountErr   error
	insertEmailErr     error
	updateAccountErr   error
	deleteAccountErr   error

	createdName        string
	createdSecret      string
	createdDescription string
	createdType        string
	createdQuota       int

	insertedName    string
	insertedAddress string
	insertedType    string

	updatedName        string
	updatedDescription *string
	updatedQuota       *int
	updatedActive      *bool

	deletedName string
	insertCalls int
	createCalls int
	updateCalls int
	deleteCalls int
}

func (m *mockAccountsStore) ListAccounts() ([]model.Account, error) {
	return m.listAccountsResult, m.listAccountsErr
}

func (m *mockAccountsStore) GetAccount(name string) (*model.Account, error) {
	if m.getAccountResult != nil {
		copy := *m.getAccountResult
		return &copy, m.getAccountErr
	}
	return nil, m.getAccountErr
}

func (m *mockAccountsStore) CreateAccount(name, secret, description, accountType string, quota int) error {
	m.createCalls++
	m.createdName = name
	m.createdSecret = secret
	m.createdDescription = description
	m.createdType = accountType
	m.createdQuota = quota
	return m.createAccountErr
}

func (m *mockAccountsStore) InsertEmail(name, address, emailType string) error {
	m.insertCalls++
	m.insertedName = name
	m.insertedAddress = address
	m.insertedType = emailType
	return m.insertEmailErr
}

func (m *mockAccountsStore) UpdateAccount(name string, description *string, quota *int, active *bool) error {
	m.updateCalls++
	m.updatedName = name
	m.updatedDescription = description
	m.updatedQuota = quota
	m.updatedActive = active
	return m.updateAccountErr
}

func (m *mockAccountsStore) DeleteAccount(name string) error {
	m.deleteCalls++
	m.deletedName = name
	return m.deleteAccountErr
}

func TestAccountsHandlerListsAccounts(t *testing.T) {
	t.Parallel()

	store := &mockAccountsStore{listAccountsResult: []model.Account{{Name: "alice", Description: "Alice", Type: "individual", Quota: 10, Active: true}}}
	req := httptest.NewRequest(http.MethodGet, "/accounts", nil)
	rr := httptest.NewRecorder()

	newAccountsHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusOK)
	}

	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want %q", got, "application/json")
	}

	var accounts []model.Account
	if err := json.Unmarshal(rr.Body.Bytes(), &accounts); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if len(accounts) != 1 || accounts[0].Name != "alice" {
		t.Fatalf("accounts = %#v, want alice", accounts)
	}
	if strings.Contains(rr.Body.String(), "secret") {
		t.Fatal("response should not include secret")
	}
}

func TestAccountsHandlerReturnsServerErrorWhenListFails(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/accounts", nil)
	rr := httptest.NewRecorder()

	newAccountsHandler(&mockAccountsStore{listAccountsErr: errors.New("boom")}).ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestAccountHandlerGetsAccount(t *testing.T) {
	t.Parallel()

	store := &mockAccountsStore{getAccountResult: &model.Account{Name: "alice", Description: "Alice", Type: "individual", Quota: 10, Active: true}}
	req := httptest.NewRequest(http.MethodGet, "/accounts/alice", nil)
	req.SetPathValue("name", "alice")
	rr := httptest.NewRecorder()

	newAccountHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusOK)
	}

	var account model.Account
	if err := json.Unmarshal(rr.Body.Bytes(), &account); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if account.Name != "alice" {
		t.Fatalf("name = %q, want %q", account.Name, "alice")
	}
}

func TestAccountHandlerReturnsNotFoundWhenMissing(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/accounts/missing", nil)
	req.SetPathValue("name", "missing")
	rr := httptest.NewRecorder()

	newAccountHandler(&mockAccountsStore{}).ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestCreateAccountHandlerValidatesRequiredFields(t *testing.T) {
	t.Parallel()

	body := strings.NewReader(`{"name":"","password":""}`)
	req := httptest.NewRequest(http.MethodPost, "/accounts", body)
	rr := httptest.NewRecorder()

	newCreateAccountHandler(&mockAccountsStore{}).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestCreateAccountHandlerCreatesAccountWithDefaultTypeAndHash(t *testing.T) {
	t.Parallel()

	store := &mockAccountsStore{}
	body := strings.NewReader(`{"name":"alice","password":"secret","description":"Alice","quota":25}`)
	req := httptest.NewRequest(http.MethodPost, "/accounts", body)
	rr := httptest.NewRecorder()

	newCreateAccountHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusCreated, rr.Body.String())
	}
	if store.createCalls != 1 {
		t.Fatalf("CreateAccount calls = %d, want 1", store.createCalls)
	}
	if store.createdType != "individual" {
		t.Fatalf("type = %q, want %q", store.createdType, "individual")
	}
	if store.createdSecret == "secret" {
		t.Fatal("password was not hashed")
	}
	if !auth.VerifyPassword("secret", store.createdSecret) {
		t.Fatal("stored secret does not verify")
	}
	if store.insertCalls != 0 {
		t.Fatalf("InsertEmail calls = %d, want 0", store.insertCalls)
	}
}

func TestCreateAccountHandlerAddsPrimaryEmailForAddressNames(t *testing.T) {
	t.Parallel()

	store := &mockAccountsStore{}
	body := strings.NewReader(`{"name":"alice@example.com","password":"secret"}`)
	req := httptest.NewRequest(http.MethodPost, "/accounts", body)
	rr := httptest.NewRecorder()

	newCreateAccountHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusCreated)
	}
	if store.insertCalls != 1 {
		t.Fatalf("InsertEmail calls = %d, want 1", store.insertCalls)
	}
	if store.insertedName != "alice@example.com" || store.insertedAddress != "alice@example.com" || store.insertedType != "primary" {
		t.Fatalf("inserted email = (%q, %q, %q), want primary self address", store.insertedName, store.insertedAddress, store.insertedType)
	}
}

func TestAccountHandlerPatchesAccount(t *testing.T) {
	t.Parallel()

	body := strings.NewReader(`{"description":"Updated","quota":42,"active":false}`)
	req := httptest.NewRequest(http.MethodPatch, "/accounts/alice", body)
	req.SetPathValue("name", "alice")
	rr := httptest.NewRecorder()
	store := &mockAccountsStore{}

	newAccountHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	if store.updateCalls != 1 {
		t.Fatalf("UpdateAccount calls = %d, want 1", store.updateCalls)
	}
	if store.updatedName != "alice" {
		t.Fatalf("updated name = %q, want %q", store.updatedName, "alice")
	}
	if store.updatedDescription == nil || *store.updatedDescription != "Updated" {
		t.Fatalf("description = %#v, want Updated", store.updatedDescription)
	}
	if store.updatedQuota == nil || *store.updatedQuota != 42 {
		t.Fatalf("quota = %#v, want 42", store.updatedQuota)
	}
	if store.updatedActive == nil || *store.updatedActive != false {
		t.Fatalf("active = %#v, want false", store.updatedActive)
	}
}

func TestAccountHandlerRejectsInvalidPatchJSON(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPatch, "/accounts/alice", strings.NewReader(`{"description":`))
	req.SetPathValue("name", "alice")
	rr := httptest.NewRecorder()

	newAccountHandler(&mockAccountsStore{}).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestAccountHandlerDeletesAccount(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodDelete, "/accounts/alice", nil)
	req.SetPathValue("name", "alice")
	rr := httptest.NewRecorder()
	store := &mockAccountsStore{}

	newAccountHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusNoContent)
	}
	if store.deleteCalls != 1 || store.deletedName != "alice" {
		t.Fatalf("DeleteAccount calls=%d name=%q, want 1/alice", store.deleteCalls, store.deletedName)
	}
}

func TestAccountHandlerDeleteReturnsNotFound(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodDelete, "/accounts/alice", nil)
	req.SetPathValue("name", "alice")
	rr := httptest.NewRecorder()

	newAccountHandler(&mockAccountsStore{deleteAccountErr: errAccountNotFound}).ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusNotFound)
	}
}
