package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/operinko-labs/stalwart-users/internal/auth"
	"github.com/operinko-labs/stalwart-users/internal/directory"
	"github.com/operinko-labs/stalwart-users/internal/model"
	"github.com/operinko-labs/stalwart-users/internal/stalwart"
)

type mockAccountsStore struct {
	listAccountsResult []model.Account
	listAccountsErr    error
	getAccountResult   *model.Account
	getAccountErr      error
	createAccountErr   error
	updateAccountErr   error
	deleteAccountErr   error
	addressInUse       bool

	createdName        string
	createdPassword    string
	createdDescription string
	createdType        string
	createdQuota       int

	updatedName        string
	updatedDescription *string
	updatedQuota       *int
	updatedActive      *bool

	deletedName string
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

func (m *mockAccountsStore) CreateAccount(name, password, description, accountType string, quota int) error {
	m.createCalls++
	m.createdName = name
	m.createdPassword = password
	m.createdDescription = description
	m.createdType = accountType
	m.createdQuota = quota
	return m.createAccountErr
}

func (m *mockAccountsStore) AddressInUse(address string) (bool, error) {
	return m.addressInUse, nil
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

func asFullAdmin(req *http.Request) *http.Request {
	return req.WithContext(auth.WithUser(req.Context(), "admin@example.com", true))
}

func asDomainAdmin(req *http.Request, domains ...string) *http.Request {
	ctx := auth.WithUser(req.Context(), "dora@client.fi", false)
	return req.WithContext(auth.WithAdminDomains(ctx, domains))
}

func TestAccountsHandlerListsOnlyManagedDomainsForDomainAdmins(t *testing.T) {
	t.Parallel()

	store := &mockAccountsStore{listAccountsResult: []model.Account{
		{Name: "admin"},
		{Name: "boss@client.fi", IsAdmin: true},
		{Name: "bob@client.fi"},
		{Name: "carl@Client2.fi"},
		{Name: "eve@other.fi"},
	}}
	req := asDomainAdmin(httptest.NewRequest(http.MethodGet, "/accounts", nil), "client.fi", "client2.fi")
	rr := httptest.NewRecorder()

	newAccountsHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	var accounts []model.Account
	if err := json.Unmarshal(rr.Body.Bytes(), &accounts); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if len(accounts) != 2 || accounts[0].Name != "bob@client.fi" || accounts[1].Name != "carl@Client2.fi" {
		t.Fatalf("accounts = %#v, want bob@client.fi and carl@Client2.fi", accounts)
	}
}

func TestCreateAccountHandlerAllowsDomainAdminsOnTheirDomains(t *testing.T) {
	t.Parallel()

	for _, accountType := range []string{"", "individual", "group"} {
		t.Run("type "+accountType, func(t *testing.T) {
			t.Parallel()

			store := &mockAccountsStore{}
			body := strings.NewReader(`{"name":"bob@client.fi","password":"secret","type":"` + accountType + `"}`)
			req := asDomainAdmin(httptest.NewRequest(http.MethodPost, "/accounts", body), "client.fi")
			rr := httptest.NewRecorder()

			newCreateAccountHandler(store).ServeHTTP(rr, req)

			if rr.Code != http.StatusCreated {
				t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusCreated, rr.Body.String())
			}
			if store.createCalls != 1 || store.createdName != "bob@client.fi" {
				t.Fatalf("CreateAccount calls=%d name=%q, want 1/bob@client.fi", store.createCalls, store.createdName)
			}
		})
	}
}

func TestCreateAccountHandlerRejectsDomainAdminRequestsOutsideTheirRights(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{name: "other domain", body: `{"name":"eve@other.fi","password":"secret"}`},
		{name: "no domain", body: `{"name":"eve","password":"secret"}`},
		{name: "quota", body: `{"name":"bob@client.fi","password":"secret","quota":1024}`},
		{name: "admin type", body: `{"name":"bob@client.fi","password":"secret","type":"admin"}`},
		{name: "domain type", body: `{"name":"bob@client.fi","password":"secret","type":"domain"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := &mockAccountsStore{}
			req := asDomainAdmin(httptest.NewRequest(http.MethodPost, "/accounts", strings.NewReader(tt.body)), "client.fi")
			rr := httptest.NewRecorder()

			newCreateAccountHandler(store).ServeHTTP(rr, req)

			if rr.Code != http.StatusForbidden {
				t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusForbidden, rr.Body.String())
			}
			if store.createCalls != 0 {
				t.Fatalf("CreateAccount calls = %d, want none", store.createCalls)
			}
		})
	}
}

func TestCreateAccountHandlerRejectsAddressesInUseForDomainAdmins(t *testing.T) {
	t.Parallel()

	store := &mockAccountsStore{addressInUse: true}
	body := strings.NewReader(`{"name":"ceo@client.fi","password":"secret"}`)
	req := asDomainAdmin(httptest.NewRequest(http.MethodPost, "/accounts", body), "client.fi")
	rr := httptest.NewRecorder()

	newCreateAccountHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusConflict)
	}
	if store.createCalls != 0 {
		t.Fatalf("CreateAccount calls = %d, want none", store.createCalls)
	}
}

func TestAccountHandlerRejectsQuotaChangesFromNonAdmins(t *testing.T) {
	t.Parallel()

	store := &mockAccountsStore{}
	req := asDomainAdmin(httptest.NewRequest(http.MethodPatch, "/accounts/bob@client.fi", strings.NewReader(`{"quota":0}`)), "client.fi")
	req.SetPathValue("name", "bob@client.fi")
	rr := httptest.NewRecorder()

	newAccountHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusForbidden)
	}
	if store.updateCalls != 0 {
		t.Fatalf("UpdateAccount calls = %d, want 0", store.updateCalls)
	}
}

func TestAccountHandlerLetsNonAdminsPatchWithoutQuota(t *testing.T) {
	t.Parallel()

	store := &mockAccountsStore{}
	req := asDomainAdmin(httptest.NewRequest(http.MethodPatch, "/accounts/bob@client.fi", strings.NewReader(`{"description":"Bob","active":false}`)), "client.fi")
	req.SetPathValue("name", "bob@client.fi")
	rr := httptest.NewRecorder()

	newAccountHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	if store.updateCalls != 1 {
		t.Fatalf("UpdateAccount calls = %d, want 1", store.updateCalls)
	}
}

func TestAccountsHandlerListsAccounts(t *testing.T) {
	t.Parallel()

	store := &mockAccountsStore{listAccountsResult: []model.Account{{Name: "alice", Description: "Alice", Type: "individual", Quota: 10, Active: true}}}
	req := asFullAdmin(httptest.NewRequest(http.MethodGet, "/accounts", nil))
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

	req := asFullAdmin(httptest.NewRequest(http.MethodGet, "/accounts", nil))
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
	req := asFullAdmin(httptest.NewRequest(http.MethodPost, "/accounts", body))
	rr := httptest.NewRecorder()

	newCreateAccountHandler(&mockAccountsStore{}).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestCreateAccountHandlerCreatesAccountWithDefaultType(t *testing.T) {
	t.Parallel()

	store := &mockAccountsStore{}
	body := strings.NewReader(`{"name":"alice@example.com","password":"secret","description":"Alice","quota":25}`)
	req := asFullAdmin(httptest.NewRequest(http.MethodPost, "/accounts", body))
	rr := httptest.NewRecorder()

	newCreateAccountHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusCreated, rr.Body.String())
	}
	if store.createCalls != 1 {
		t.Fatalf("CreateAccount calls = %d, want 1", store.createCalls)
	}
	if store.createdName != "alice@example.com" || store.createdPassword != "secret" || store.createdDescription != "Alice" || store.createdQuota != 25 {
		t.Fatalf("created = (%q, %q, %q, %d), want request fields with plaintext password", store.createdName, store.createdPassword, store.createdDescription, store.createdQuota)
	}
	if store.createdType != "individual" {
		t.Fatalf("type = %q, want %q", store.createdType, "individual")
	}
}

func TestCreateAccountWeakPassword(t *testing.T) {
	t.Parallel()

	store := &mockAccountsStore{createAccountErr: fmt.Errorf("create account: %w", stalwart.ErrInvalid{Description: "Password is too weak"})}
	body := strings.NewReader(`{"name":"alice@example.com","password":"weak"}`)
	req := asFullAdmin(httptest.NewRequest(http.MethodPost, "/accounts", body))
	rr := httptest.NewRecorder()

	newCreateAccountHandler(store).ServeHTTP(rr, req)

	assertError(t, rr, http.StatusBadRequest, "Password is too weak")
}

func TestCreateAccountGroupUnsupported(t *testing.T) {
	t.Parallel()

	store := &mockAccountsStore{createAccountErr: fmt.Errorf("%w: groups can't be created", directory.ErrUnsupported)}
	body := strings.NewReader(`{"name":"team@example.com","password":"secret","type":"group"}`)
	req := asFullAdmin(httptest.NewRequest(http.MethodPost, "/accounts", body))
	rr := httptest.NewRecorder()

	newCreateAccountHandler(store).ServeHTTP(rr, req)

	assertError(t, rr, http.StatusBadRequest, "not supported by Stalwart 1.0: groups can't be created")
}

func TestCreateAccountHandlerReturnsServerErrorWhenStoreFails(t *testing.T) {
	t.Parallel()

	store := &mockAccountsStore{createAccountErr: errors.New("stalwart unavailable")}
	body := strings.NewReader(`{"name":"alice@example.com","password":"secret"}`)
	req := asFullAdmin(httptest.NewRequest(http.MethodPost, "/accounts", body))
	rr := httptest.NewRecorder()

	newCreateAccountHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestAccountHandlerPatchesAccount(t *testing.T) {
	t.Parallel()

	body := strings.NewReader(`{"description":"Updated","quota":42,"active":false}`)
	req := asFullAdmin(httptest.NewRequest(http.MethodPatch, "/accounts/alice", body))
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

func TestPatchAccountDeactivate400(t *testing.T) {
	t.Parallel()

	store := &mockAccountsStore{updateAccountErr: fmt.Errorf("%w: accounts can't be disabled", directory.ErrUnsupported)}
	req := asFullAdmin(httptest.NewRequest(http.MethodPatch, "/accounts/alice", strings.NewReader(`{"active":false}`)))
	req.SetPathValue("name", "alice")
	rr := httptest.NewRecorder()

	newAccountHandler(store).ServeHTTP(rr, req)

	assertError(t, rr, http.StatusBadRequest, "not supported by Stalwart 1.0: accounts can't be disabled")
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

func assertError(t *testing.T, rr *httptest.ResponseRecorder, status int, message string) {
	t.Helper()

	if rr.Code != status {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, status, rr.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if body["error"] != message {
		t.Fatalf("error = %q, want %q", body["error"], message)
	}
}
