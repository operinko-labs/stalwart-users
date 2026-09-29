package api

import (
	"context"
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
	addressInUse       bool

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
	callOrder   *[]string
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
	if m.callOrder != nil {
		*m.callOrder = append(*m.callOrder, "db.create")
	}
	return m.createAccountErr
}

func (m *mockAccountsStore) InsertEmail(name, address, emailType string) error {
	m.insertCalls++
	m.insertedName = name
	m.insertedAddress = address
	m.insertedType = emailType
	if m.callOrder != nil {
		*m.callOrder = append(*m.callOrder, "db.insert_email")
	}
	return m.insertEmailErr
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
	if m.callOrder != nil {
		*m.callOrder = append(*m.callOrder, "db.delete")
	}
	return m.deleteAccountErr
}

type mockStalwartClient struct {
	createErr   error
	deleteErr   error
	createdName string
	createdPass string
	createdDesc string
	deletedName string
	createCalls int
	deleteCalls int
	callOrder   *[]string
}

func (m *mockStalwartClient) CreateAccount(_ context.Context, name, password, description string) error {
	m.createCalls++
	m.createdName = name
	m.createdPass = password
	m.createdDesc = description
	if m.callOrder != nil {
		*m.callOrder = append(*m.callOrder, "stalwart.create")
	}
	return m.createErr
}

func (m *mockStalwartClient) DeleteAccount(_ context.Context, name string) error {
	m.deleteCalls++
	m.deletedName = name
	if m.callOrder != nil {
		*m.callOrder = append(*m.callOrder, "stalwart.delete")
	}
	return m.deleteErr
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

			newCreateAccountHandler(store, nil).ServeHTTP(rr, req)

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
			stalwart := &mockStalwartClient{}
			req := asDomainAdmin(httptest.NewRequest(http.MethodPost, "/accounts", strings.NewReader(tt.body)), "client.fi")
			rr := httptest.NewRecorder()

			newCreateAccountHandler(store, stalwart).ServeHTTP(rr, req)

			if rr.Code != http.StatusForbidden {
				t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusForbidden, rr.Body.String())
			}
			if store.createCalls != 0 || stalwart.createCalls != 0 {
				t.Fatalf("create calls db=%d stalwart=%d, want none", store.createCalls, stalwart.createCalls)
			}
		})
	}
}

func TestCreateAccountHandlerRejectsAddressesInUseForDomainAdmins(t *testing.T) {
	t.Parallel()

	store := &mockAccountsStore{addressInUse: true}
	stalwart := &mockStalwartClient{}
	body := strings.NewReader(`{"name":"ceo@client.fi","password":"secret"}`)
	req := asDomainAdmin(httptest.NewRequest(http.MethodPost, "/accounts", body), "client.fi")
	rr := httptest.NewRecorder()

	newCreateAccountHandler(store, stalwart).ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusConflict)
	}
	if store.createCalls != 0 || stalwart.createCalls != 0 {
		t.Fatalf("create calls db=%d stalwart=%d, want none", store.createCalls, stalwart.createCalls)
	}
}

func TestAccountHandlerRejectsQuotaChangesFromNonAdmins(t *testing.T) {
	t.Parallel()

	store := &mockAccountsStore{}
	req := asDomainAdmin(httptest.NewRequest(http.MethodPatch, "/accounts/bob@client.fi", strings.NewReader(`{"quota":0}`)), "client.fi")
	req.SetPathValue("name", "bob@client.fi")
	rr := httptest.NewRecorder()

	newAccountHandler(store, nil).ServeHTTP(rr, req)

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

	newAccountHandler(store, nil).ServeHTTP(rr, req)

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

	newAccountHandler(store, nil).ServeHTTP(rr, req)

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

	newAccountHandler(&mockAccountsStore{}, nil).ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestCreateAccountHandlerValidatesRequiredFields(t *testing.T) {
	t.Parallel()

	body := strings.NewReader(`{"name":"","password":""}`)
	req := asFullAdmin(httptest.NewRequest(http.MethodPost, "/accounts", body))
	rr := httptest.NewRecorder()

	newCreateAccountHandler(&mockAccountsStore{}, nil).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestCreateAccountHandlerCreatesAccountWithDefaultTypeAndHash(t *testing.T) {
	t.Parallel()

	store := &mockAccountsStore{}
	body := strings.NewReader(`{"name":"alice","password":"secret","description":"Alice","quota":25}`)
	req := asFullAdmin(httptest.NewRequest(http.MethodPost, "/accounts", body))
	rr := httptest.NewRecorder()

	newCreateAccountHandler(store, nil).ServeHTTP(rr, req)

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
	req := asFullAdmin(httptest.NewRequest(http.MethodPost, "/accounts", body))
	rr := httptest.NewRecorder()

	newCreateAccountHandler(store, nil).ServeHTTP(rr, req)

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
	req := asFullAdmin(httptest.NewRequest(http.MethodPatch, "/accounts/alice", body))
	req.SetPathValue("name", "alice")
	rr := httptest.NewRecorder()
	store := &mockAccountsStore{}

	newAccountHandler(store, nil).ServeHTTP(rr, req)

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

	newAccountHandler(&mockAccountsStore{}, nil).ServeHTTP(rr, req)

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

	newAccountHandler(store, nil).ServeHTTP(rr, req)

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

	newAccountHandler(&mockAccountsStore{deleteAccountErr: errAccountNotFound}, nil).ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestCreateAccountHandlerCallsJMAP(t *testing.T) {
	t.Parallel()

	order := []string{}
	store := &mockAccountsStore{callOrder: &order}
	stalwart := &mockStalwartClient{callOrder: &order}
	body := strings.NewReader(`{"name":"alice@example.com","password":"secret"}`)
	req := asFullAdmin(httptest.NewRequest(http.MethodPost, "/accounts", body))
	rr := httptest.NewRecorder()

	newCreateAccountHandler(store, stalwart).ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusCreated)
	}
	if stalwart.createCalls != 1 {
		t.Fatalf("CreateAccount calls = %d, want 1", stalwart.createCalls)
	}
	if stalwart.createdName != "alice@example.com" || stalwart.createdPass != "secret" {
		t.Fatalf("created account = %#v, want propagated request fields", stalwart)
	}
	if len(order) < 2 || order[0] != "stalwart.create" || order[1] != "db.create" {
		t.Fatalf("call order = %#v, want stalwart create before db create", order)
	}
}

func TestCreateAccountHandlerReturnsErrorWhenJMAPFails(t *testing.T) {
	t.Parallel()

	store := &mockAccountsStore{}
	stalwart := &mockStalwartClient{createErr: errors.New("stalwart unavailable")}
	body := strings.NewReader(`{"name":"alice@example.com","password":"secret"}`)
	req := asFullAdmin(httptest.NewRequest(http.MethodPost, "/accounts", body))
	rr := httptest.NewRecorder()

	newCreateAccountHandler(store, stalwart).ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
	if store.createCalls != 0 {
		t.Fatalf("CreateAccount calls = %d, want 0", store.createCalls)
	}
	if stalwart.createCalls != 1 {
		t.Fatalf("CreateAccount calls = %d, want 1", stalwart.createCalls)
	}
}

func TestCreateAccountHandlerRollsBackOnDBFailure(t *testing.T) {
	t.Parallel()

	order := []string{}
	store := &mockAccountsStore{createAccountErr: errors.New("db unavailable"), callOrder: &order}
	stalwart := &mockStalwartClient{callOrder: &order}
	body := strings.NewReader(`{"name":"alice@example.com","password":"secret"}`)
	req := asFullAdmin(httptest.NewRequest(http.MethodPost, "/accounts", body))
	rr := httptest.NewRecorder()

	newCreateAccountHandler(store, stalwart).ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
	if stalwart.createCalls != 1 {
		t.Fatalf("CreateAccount calls = %d, want 1", stalwart.createCalls)
	}
	if store.createCalls != 1 {
		t.Fatalf("CreateAccount calls = %d, want 1", store.createCalls)
	}
	if stalwart.deleteCalls != 1 || stalwart.deletedName != "alice@example.com" {
		t.Fatalf("DeleteAccount calls=%d name=%q, want 1/alice@example.com", stalwart.deleteCalls, stalwart.deletedName)
	}
	if store.insertCalls != 0 {
		t.Fatalf("InsertEmail calls = %d, want 0", store.insertCalls)
	}
	if len(order) != 3 || order[0] != "stalwart.create" || order[1] != "db.create" || order[2] != "stalwart.delete" {
		t.Fatalf("call order = %#v, want create then rollback delete", order)
	}
}

func TestDeleteAccountHandlerCallsJMAP(t *testing.T) {
	t.Parallel()

	order := []string{}
	store := &mockAccountsStore{callOrder: &order}
	stalwart := &mockStalwartClient{callOrder: &order}
	req := httptest.NewRequest(http.MethodDelete, "/accounts/alice", nil)
	req.SetPathValue("name", "alice")
	rr := httptest.NewRecorder()

	newAccountHandler(store, stalwart).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusNoContent)
	}
	if stalwart.deleteCalls != 1 || stalwart.deletedName != "alice" {
		t.Fatalf("DeleteAccount calls=%d name=%q, want 1/alice", stalwart.deleteCalls, stalwart.deletedName)
	}
	if len(order) != 2 || order[0] != "db.delete" || order[1] != "stalwart.delete" {
		t.Fatalf("call order = %#v, want db delete before stalwart delete", order)
	}
	if store.deleteCalls != 1 || store.deletedName != "alice" {
		t.Fatalf("DeleteAccount calls=%d name=%q, want 1/alice", store.deleteCalls, store.deletedName)
	}
}

func TestDeleteAccountHandlerContinuesWhenJMAPFails(t *testing.T) {
	t.Parallel()

	store := &mockAccountsStore{}
	stalwart := &mockStalwartClient{deleteErr: errors.New("stalwart unavailable")}
	req := httptest.NewRequest(http.MethodDelete, "/accounts/alice", nil)
	req.SetPathValue("name", "alice")
	rr := httptest.NewRecorder()

	newAccountHandler(store, stalwart).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusNoContent)
	}
	if store.deleteCalls != 1 {
		t.Fatalf("DeleteAccount calls = %d, want 1", store.deleteCalls)
	}
	if stalwart.deleteCalls != 1 {
		t.Fatalf("Stalwart DeleteAccount calls = %d, want 1", stalwart.deleteCalls)
	}
}
