package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/operinko-labs/stalwart-users/internal/model"
)

type mockGroupsStore struct {
	listGroupsResult []string
	listGroupsErr    error
	addGroupErr      error
	removeGroupErr   error
	getAccountResult *model.Account
	getAccountErr    error

	listedName      string
	addedName       string
	addedMemberOf   string
	removedName     string
	removedMemberOf string
	listCalls       int
	addCalls        int
	removeCalls     int
	getAccountCalls int
}

func (m *mockGroupsStore) ListGroups(name string) ([]string, error) {
	m.listCalls++
	m.listedName = name
	return m.listGroupsResult, m.listGroupsErr
}

func (m *mockGroupsStore) AddGroup(name, memberOf string) error {
	m.addCalls++
	m.addedName = name
	m.addedMemberOf = memberOf
	return m.addGroupErr
}

func (m *mockGroupsStore) RemoveGroup(name, memberOf string) error {
	m.removeCalls++
	m.removedName = name
	m.removedMemberOf = memberOf
	return m.removeGroupErr
}

func (m *mockGroupsStore) GetAccount(name string) (*model.Account, error) {
	m.getAccountCalls++
	if m.getAccountResult != nil {
		copy := *m.getAccountResult
		return &copy, m.getAccountErr
	}
	return nil, m.getAccountErr
}

func TestListGroupsHandlerReturnsArray(t *testing.T) {
	t.Parallel()

	store := &mockGroupsStore{
		getAccountResult: &model.Account{Name: "alice"},
		listGroupsResult: []string{"admins", "editors"},
	}
	req := httptest.NewRequest(http.MethodGet, "/accounts/alice/groups", nil)
	req.SetPathValue("name", "alice")
	rr := httptest.NewRecorder()

	newListGroupsHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusOK)
	}

	var groups []string
	if err := json.Unmarshal(rr.Body.Bytes(), &groups); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if len(groups) != 2 || groups[0] != "admins" || groups[1] != "editors" {
		t.Fatalf("groups = %#v, want admins and editors", groups)
	}
	if store.listCalls != 1 || store.listedName != "alice" {
		t.Fatalf("ListGroups calls=%d name=%q, want 1/alice", store.listCalls, store.listedName)
	}
}

func TestCreateGroupHandlerCreatesMembership(t *testing.T) {
	t.Parallel()

	store := &mockGroupsStore{getAccountResult: &model.Account{Name: "alice"}}
	req := httptest.NewRequest(http.MethodPost, "/accounts/alice/groups", strings.NewReader(`{"member_of":"admins"}`))
	req.SetPathValue("name", "alice")
	rr := httptest.NewRecorder()

	newCreateGroupHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusCreated, rr.Body.String())
	}
	if store.addCalls != 1 {
		t.Fatalf("AddGroup calls = %d, want 1", store.addCalls)
	}
	if store.addedName != "alice" || store.addedMemberOf != "admins" {
		t.Fatalf("added group = (%q, %q), want (alice, admins)", store.addedName, store.addedMemberOf)
	}
}

func TestCreateGroupHandlerValidatesMemberOfRequired(t *testing.T) {
	t.Parallel()

	store := &mockGroupsStore{getAccountResult: &model.Account{Name: "alice"}}
	req := httptest.NewRequest(http.MethodPost, "/accounts/alice/groups", strings.NewReader(`{"member_of":""}`))
	req.SetPathValue("name", "alice")
	rr := httptest.NewRecorder()

	newCreateGroupHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	if store.addCalls != 0 {
		t.Fatalf("AddGroup calls = %d, want 0", store.addCalls)
	}
}

func TestDeleteGroupHandlerRemovesMembership(t *testing.T) {
	t.Parallel()

	store := &mockGroupsStore{getAccountResult: &model.Account{Name: "alice"}}
	req := httptest.NewRequest(http.MethodDelete, "/accounts/alice/groups/admins", nil)
	req.SetPathValue("name", "alice")
	req.SetPathValue("group", "admins")
	rr := httptest.NewRecorder()

	newDeleteGroupHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusNoContent)
	}
	if store.removeCalls != 1 || store.removedName != "alice" || store.removedMemberOf != "admins" {
		t.Fatalf("RemoveGroup calls=%d name=%q memberOf=%q, want 1/alice/admins", store.removeCalls, store.removedName, store.removedMemberOf)
	}
}

func TestDeleteGroupHandlerReturnsNotFoundWhenMembershipMissing(t *testing.T) {
	t.Parallel()

	store := &mockGroupsStore{
		getAccountResult: &model.Account{Name: "alice"},
		removeGroupErr:   errGroupMembershipNotFound,
	}
	req := httptest.NewRequest(http.MethodDelete, "/accounts/alice/groups/admins", nil)
	req.SetPathValue("name", "alice")
	req.SetPathValue("group", "admins")
	rr := httptest.NewRecorder()

	newDeleteGroupHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestGroupHandlersReturnNotFoundForMissingAccount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		url     string
		body    string
		group   string
	}{
		{name: "list", handler: newListGroupsHandler(&mockGroupsStore{}), method: http.MethodGet, url: "/accounts/missing/groups"},
		{name: "create", handler: newCreateGroupHandler(&mockGroupsStore{}), method: http.MethodPost, url: "/accounts/missing/groups", body: `{"member_of":"admins"}`},
		{name: "delete", handler: newDeleteGroupHandler(&mockGroupsStore{}), method: http.MethodDelete, url: "/accounts/missing/groups/admins", group: "admins"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(tt.method, tt.url, strings.NewReader(tt.body))
			req.SetPathValue("name", "missing")
			if tt.group != "" {
				req.SetPathValue("group", tt.group)
			}
			rr := httptest.NewRecorder()

			tt.handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusNotFound {
				t.Fatalf("status code = %d, want %d", rr.Code, http.StatusNotFound)
			}
		})
	}
}

func TestDeleteGroupHandlerReturnsInternalServerErrorOnUnexpectedError(t *testing.T) {
	t.Parallel()

	store := &mockGroupsStore{
		getAccountResult: &model.Account{Name: "alice"},
		removeGroupErr:   errors.New("boom"),
	}
	req := httptest.NewRequest(http.MethodDelete, "/accounts/alice/groups/admins", nil)
	req.SetPathValue("name", "alice")
	req.SetPathValue("group", "admins")
	rr := httptest.NewRecorder()

	newDeleteGroupHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}
