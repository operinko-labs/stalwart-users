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

	"github.com/operinko-labs/stalwart-users/internal/directory"
	"github.com/operinko-labs/stalwart-users/internal/model"
	"github.com/operinko-labs/stalwart-users/internal/stalwart"
)

type mockAliasesStore struct {
	listEmailsResult []model.Email
	listEmailsErr    error
	insertEmailErr   error
	getEmailTypeErr  error
	deleteEmailErr   error
	getAccountResult *model.Account
	getAccountErr    error
	addressInUse     bool

	insertedName    string
	insertedAddress string
	insertedType    string
	deletedName     string
	deletedAddress  string
	getTypeName     string
	getTypeAddress  string
	insertCalls     int
	deleteCalls     int
	getTypeCalls    int
	getAccountCalls int
	getEmailType    string
}

func (m *mockAliasesStore) ListEmails(name string) ([]model.Email, error) {
	return m.listEmailsResult, m.listEmailsErr
}

func (m *mockAliasesStore) InsertEmail(name, address, emailType string) error {
	m.insertCalls++
	m.insertedName = name
	m.insertedAddress = address
	m.insertedType = emailType
	return m.insertEmailErr
}

func (m *mockAliasesStore) GetEmailType(name, address string) (string, error) {
	m.getTypeCalls++
	m.getTypeName = name
	m.getTypeAddress = address
	return m.getEmailType, m.getEmailTypeErr
}

func (m *mockAliasesStore) DeleteEmail(name, address string) error {
	m.deleteCalls++
	m.deletedName = name
	m.deletedAddress = address
	return m.deleteEmailErr
}

func (m *mockAliasesStore) AddressInUse(address string) (bool, error) {
	return m.addressInUse, nil
}

func (m *mockAliasesStore) GetAccount(name string) (*model.Account, error) {
	m.getAccountCalls++
	if m.getAccountResult != nil {
		copy := *m.getAccountResult
		return &copy, m.getAccountErr
	}
	return nil, m.getAccountErr
}

func TestListEmailsHandlerReturnsArray(t *testing.T) {
	t.Parallel()

	store := &mockAliasesStore{
		getAccountResult: &model.Account{Name: "alice"},
		listEmailsResult: []model.Email{
			{Name: "alice", Address: "alice@example.com", Type: "primary"},
			{Name: "alice", Address: "alias@example.com", Type: "alias"},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/accounts/alice/emails", nil)
	req.SetPathValue("name", "alice")
	rr := httptest.NewRecorder()

	newListEmailsHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusOK)
	}

	var emails []model.Email
	if err := json.Unmarshal(rr.Body.Bytes(), &emails); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if len(emails) != 2 || emails[0].Address != "alice@example.com" || emails[1].Address != "alias@example.com" {
		t.Fatalf("emails = %#v, want primary and alias", emails)
	}
}

func TestCreateEmailHandlerCreatesAliasWithDefaultType(t *testing.T) {
	t.Parallel()

	store := &mockAliasesStore{getAccountResult: &model.Account{Name: "alice"}}
	req := asFullAdmin(httptest.NewRequest(http.MethodPost, "/accounts/alice/emails", strings.NewReader(`{"address":"alias@example.com"}`)))
	req.SetPathValue("name", "alice")
	rr := httptest.NewRecorder()

	newCreateEmailHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusCreated, rr.Body.String())
	}
	if store.insertCalls != 1 {
		t.Fatalf("InsertEmail calls = %d, want 1", store.insertCalls)
	}
	if store.insertedName != "alice" || store.insertedAddress != "alias@example.com" || store.insertedType != "alias" {
		t.Fatalf("inserted email = (%q, %q, %q), want alias insert", store.insertedName, store.insertedAddress, store.insertedType)
	}
}

func TestCreateEmailHandlerMapsStoreErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		err     error
		status  int
		message string
	}{
		{name: "in use", err: directory.ErrAddressInUse, status: http.StatusConflict, message: "address already in use"},
		{name: "unhosted domain", err: fmt.Errorf("%w: domain nowhere.fi is not hosted here", directory.ErrUnsupported), status: http.StatusBadRequest, message: "not supported by Stalwart 1.0: domain nowhere.fi is not hosted here"},
		{name: "invalid", err: fmt.Errorf("update account: %w", stalwart.ErrInvalid{Description: "Invalid alias"}), status: http.StatusBadRequest, message: "Invalid alias"},
		{name: "unexpected", err: errors.New("boom"), status: http.StatusInternalServerError, message: "internal error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := &mockAliasesStore{getAccountResult: &model.Account{Name: "alice"}, insertEmailErr: tt.err}
			req := asFullAdmin(httptest.NewRequest(http.MethodPost, "/accounts/alice/emails", strings.NewReader(`{"address":"alias@example.com","type":"alias"}`)))
			req.SetPathValue("name", "alice")
			rr := httptest.NewRecorder()

			newCreateEmailHandler(store).ServeHTTP(rr, req)

			assertError(t, rr, tt.status, tt.message)
		})
	}
}

func TestDeleteEmailHandlerMapsUnsupported(t *testing.T) {
	t.Parallel()

	store := &mockAliasesStore{
		getAccountResult: &model.Account{Name: "alice"},
		getEmailType:     "alias",
		deleteEmailErr:   fmt.Errorf("%w: the primary address can not be removed", directory.ErrUnsupported),
	}
	req := httptest.NewRequest(http.MethodDelete, "/accounts/alice/emails/alias@example.com", nil)
	req.SetPathValue("name", "alice")
	req.SetPathValue("address", "alias@example.com")
	rr := httptest.NewRecorder()

	newDeleteEmailHandler(store).ServeHTTP(rr, req)

	assertError(t, rr, http.StatusBadRequest, "not supported by Stalwart 1.0: the primary address can not be removed")
}

func TestDeleteEmailHandlerDeletesAlias(t *testing.T) {
	t.Parallel()

	store := &mockAliasesStore{
		getAccountResult: &model.Account{Name: "alice"},
		getEmailType:     "alias",
	}
	req := httptest.NewRequest(http.MethodDelete, "/accounts/alice/emails/alias@example.com", nil)
	req.SetPathValue("name", "alice")
	req.SetPathValue("address", "alias@example.com")
	rr := httptest.NewRecorder()

	newDeleteEmailHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusNoContent)
	}
	if store.deleteCalls != 1 || store.deletedName != "alice" || store.deletedAddress != "alias@example.com" {
		t.Fatalf("DeleteEmail calls=%d name=%q address=%q, want 1/alice/alias@example.com", store.deleteCalls, store.deletedName, store.deletedAddress)
	}
}

func TestDeleteEmailHandlerCannotDeletePrimaryEmail(t *testing.T) {
	t.Parallel()

	store := &mockAliasesStore{
		getAccountResult: &model.Account{Name: "alice"},
		getEmailType:     "primary",
	}
	req := httptest.NewRequest(http.MethodDelete, "/accounts/alice/emails/alice@example.com", nil)
	req.SetPathValue("name", "alice")
	req.SetPathValue("address", "alice@example.com")
	rr := httptest.NewRecorder()

	newDeleteEmailHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	if store.deleteCalls != 0 {
		t.Fatalf("DeleteEmail calls = %d, want 0", store.deleteCalls)
	}
}

func TestEmailHandlersReturnNotFoundForMissingAccount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		url     string
		body    string
		address string
	}{
		{name: "list", handler: newListEmailsHandler(&mockAliasesStore{}), method: http.MethodGet, url: "/accounts/missing/emails"},
		{name: "create", handler: newCreateEmailHandler(&mockAliasesStore{}), method: http.MethodPost, url: "/accounts/missing/emails", body: `{"address":"alias@example.com"}`},
		{name: "delete", handler: newDeleteEmailHandler(&mockAliasesStore{}), method: http.MethodDelete, url: "/accounts/missing/emails/alias@example.com", address: "alias@example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(tt.method, tt.url, strings.NewReader(tt.body))
			req.SetPathValue("name", "missing")
			if tt.address != "" {
				req.SetPathValue("address", tt.address)
			}
			rr := httptest.NewRecorder()

			tt.handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusNotFound {
				t.Fatalf("status code = %d, want %d", rr.Code, http.StatusNotFound)
			}
		})
	}
}

func TestCreateEmailHandlerLetsDomainAdminsAddAddressesOnTheirDomains(t *testing.T) {
	t.Parallel()

	store := &mockAliasesStore{getAccountResult: &model.Account{Name: "bob@client.fi"}}
	req := asDomainAdmin(httptest.NewRequest(http.MethodPost, "/accounts/bob@client.fi/emails", strings.NewReader(`{"address":"Sales@Client.fi"}`)), "client.fi")
	req.SetPathValue("name", "bob@client.fi")
	rr := httptest.NewRecorder()

	newCreateEmailHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusCreated, rr.Body.String())
	}
	if store.insertCalls != 1 {
		t.Fatalf("InsertEmail calls = %d, want 1", store.insertCalls)
	}
}

func TestCreateEmailHandlerRejectsAddressesOutsideManagedDomains(t *testing.T) {
	t.Parallel()

	for _, address := range []string{"postmaster@other.fi", "postmaster"} {
		t.Run(address, func(t *testing.T) {
			t.Parallel()

			store := &mockAliasesStore{getAccountResult: &model.Account{Name: "bob@client.fi"}}
			req := asDomainAdmin(httptest.NewRequest(http.MethodPost, "/accounts/bob@client.fi/emails", strings.NewReader(`{"address":"`+address+`"}`)), "client.fi")
			req.SetPathValue("name", "bob@client.fi")
			rr := httptest.NewRecorder()

			newCreateEmailHandler(store).ServeHTTP(rr, req)

			if rr.Code != http.StatusForbidden {
				t.Fatalf("status code = %d, want %d", rr.Code, http.StatusForbidden)
			}
			if store.insertCalls != 0 {
				t.Fatalf("InsertEmail calls = %d, want 0", store.insertCalls)
			}
		})
	}
}

func TestCreateEmailHandlerLimitsDomainAdminsToAliases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		emailType string
		want      int
	}{
		{emailType: "", want: http.StatusCreated},
		{emailType: "alias", want: http.StatusCreated},
		{emailType: "list", want: http.StatusForbidden},
		{emailType: "primary", want: http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run("type "+tt.emailType, func(t *testing.T) {
			t.Parallel()

			store := &mockAliasesStore{getAccountResult: &model.Account{Name: "bob@client.fi"}}
			body := `{"address":"sales@client.fi","type":"` + tt.emailType + `"}`
			req := asDomainAdmin(httptest.NewRequest(http.MethodPost, "/accounts/bob@client.fi/emails", strings.NewReader(body)), "client.fi")
			req.SetPathValue("name", "bob@client.fi")
			rr := httptest.NewRecorder()

			newCreateEmailHandler(store).ServeHTTP(rr, req)

			if tt.want == http.StatusForbidden {
				assertError(t, rr, tt.want, "you can only add alias addresses")
			} else if rr.Code != tt.want {
				t.Fatalf("status code = %d, want %d; body=%s", rr.Code, tt.want, rr.Body.String())
			}
		})
	}
}

func TestCreateEmailHandlerRejectsAddressesInUseForDomainAdmins(t *testing.T) {
	t.Parallel()

	store := &mockAliasesStore{getAccountResult: &model.Account{Name: "bob@client.fi"}, addressInUse: true}
	req := asDomainAdmin(httptest.NewRequest(http.MethodPost, "/accounts/bob@client.fi/emails", strings.NewReader(`{"address":"ceo@client.fi"}`)), "client.fi")
	req.SetPathValue("name", "bob@client.fi")
	rr := httptest.NewRecorder()

	newCreateEmailHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusConflict)
	}
	if store.insertCalls != 0 {
		t.Fatalf("InsertEmail calls = %d, want 0", store.insertCalls)
	}
}

// sharedAddressStalwart is a Stalwart where team@client.fi is already carol's
// alias, for running the handlers against the real directory.Store.
type sharedAddressStalwart struct{ updateCalls int }

func (*sharedAddressStalwart) ListAccounts(context.Context) ([]stalwart.Account, error) {
	return []stalwart.Account{
		{ID: "b", Type: "User", Name: "bob", DomainID: "c", Email: "bob@client.fi", Aliases: map[string]stalwart.Alias{}},
		{ID: "k", Type: "User", Name: "carol", DomainID: "c", Email: "carol@client.fi", Aliases: map[string]stalwart.Alias{"0": {Name: "team", DomainID: "c"}}},
	}, nil
}
func (*sharedAddressStalwart) ListDomains(context.Context) ([]stalwart.Domain, error) {
	return []stalwart.Domain{{ID: "c", Name: "client.fi"}}, nil
}
func (*sharedAddressStalwart) CreateAccount(context.Context, string, string, string, int64) error {
	return nil
}
func (f *sharedAddressStalwart) UpdateAccount(context.Context, string, map[string]any) error {
	f.updateCalls++
	return nil
}
func (*sharedAddressStalwart) DeleteAccount(context.Context, string) error { return nil }
func (*sharedAddressStalwart) Authenticate(context.Context, string, string) (bool, error) {
	return false, nil
}
func (*sharedAddressStalwart) SetPassword(context.Context, stalwart.Account, string) error {
	return nil
}

type noAdminDomains struct{}

func (noAdminDomains) ListAdminDomains(string) ([]string, error) { return nil, nil }
func (noAdminDomains) SetAdminDomains(string, []string) error    { return nil }
func (noAdminDomains) DeleteAdminDomains(string) error           { return nil }

// Full admins can't share addresses either: an address already on any account
// is 409, and list addresses are not supported.
func TestCreateEmailHandlerFullAdminsCannotShareAddressesOrAddLists(t *testing.T) {
	t.Parallel()

	tests := []struct {
		body    string
		status  int
		message string
	}{
		{body: `{"address":"team@client.fi","type":"alias"}`, status: http.StatusConflict, message: "address already in use"},
		{body: `{"address":"news@client.fi","type":"list"}`, status: http.StatusBadRequest, message: "not supported by Stalwart 1.0: only alias addresses can be added"},
	}

	for _, tt := range tests {
		client := &sharedAddressStalwart{}
		store := directory.New(client, noAdminDomains{})
		req := asFullAdmin(httptest.NewRequest(http.MethodPost, "/accounts/bob@client.fi/emails", strings.NewReader(tt.body)))
		req.SetPathValue("name", "bob@client.fi")
		rr := httptest.NewRecorder()

		newCreateEmailHandler(store).ServeHTTP(rr, req)

		assertError(t, rr, tt.status, tt.message)
		if client.updateCalls != 0 {
			t.Fatalf("%s: Stalwart was updated", tt.body)
		}
	}
}

func TestCreateEmailHandlerValidatesAddressRequired(t *testing.T) {
	t.Parallel()

	store := &mockAliasesStore{getAccountResult: &model.Account{Name: "alice"}}
	req := httptest.NewRequest(http.MethodPost, "/accounts/alice/emails", strings.NewReader(`{"address":""}`))
	req.SetPathValue("name", "alice")
	rr := httptest.NewRecorder()

	newCreateEmailHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	if store.insertCalls != 0 {
		t.Fatalf("InsertEmail calls = %d, want 0", store.insertCalls)
	}
}
