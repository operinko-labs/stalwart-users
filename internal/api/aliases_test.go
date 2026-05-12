package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lib/pq"
	"github.com/operinko-labs/stalwart-users/internal/model"
)

type mockAliasesStore struct {
	listEmailsResult []model.Email
	listEmailsErr    error
	insertEmailErr   error
	getEmailTypeErr  error
	deleteEmailErr   error
	getAccountResult *model.Account
	getAccountErr    error

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
	req := httptest.NewRequest(http.MethodPost, "/accounts/alice/emails", strings.NewReader(`{"address":"alias@example.com"}`))
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

func TestCreateEmailHandlerReturnsConflictOnDuplicate(t *testing.T) {
	t.Parallel()

	store := &mockAliasesStore{
		getAccountResult: &model.Account{Name: "alice"},
		insertEmailErr:   &pq.Error{Code: "23505"},
	}
	req := httptest.NewRequest(http.MethodPost, "/accounts/alice/emails", strings.NewReader(`{"address":"alias@example.com","type":"alias"}`))
	req.SetPathValue("name", "alice")
	rr := httptest.NewRecorder()

	newCreateEmailHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusConflict)
	}
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
