package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/operinko-labs/stalwart-users/internal/model"
)

type mockAdminDomainsStore struct {
	getAccountResult *model.Account
	domains          []string
	setErr           error

	setCalls   int
	setName    string
	setDomains []string
}

func (m *mockAdminDomainsStore) GetAccount(name string) (*model.Account, error) {
	return m.getAccountResult, nil
}

func (m *mockAdminDomainsStore) ListAdminDomains(name string) ([]string, error) {
	return m.domains, nil
}

func (m *mockAdminDomainsStore) SetAdminDomains(name string, domains []string) error {
	m.setCalls++
	m.setName = name
	m.setDomains = domains
	return m.setErr
}

func serveAdminDomainsRequest(store adminDomainsStore, method, body string) *httptest.ResponseRecorder {
	req := asFullAdmin(httptest.NewRequest(method, "/accounts/dora@client.fi/admin-domains", strings.NewReader(body)))
	req.SetPathValue("name", "dora@client.fi")
	rr := httptest.NewRecorder()

	newAdminDomainsHandler(store).ServeHTTP(rr, req)
	return rr
}

func decodeDomains(t *testing.T, rr *httptest.ResponseRecorder) []string {
	t.Helper()

	var body struct {
		Domains []string `json:"domains"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	return body.Domains
}

func TestAdminDomainsHandlerListsDomains(t *testing.T) {
	t.Parallel()

	store := &mockAdminDomainsStore{getAccountResult: &model.Account{Name: "dora@client.fi"}, domains: []string{"client.fi"}}

	rr := serveAdminDomainsRequest(store, http.MethodGet, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	if got := decodeDomains(t, rr); !slices.Equal(got, []string{"client.fi"}) {
		t.Fatalf("domains = %#v, want [client.fi]", got)
	}
}

func TestAdminDomainsHandlerReplacesNormalizedDomains(t *testing.T) {
	t.Parallel()

	store := &mockAdminDomainsStore{getAccountResult: &model.Account{Name: "dora@client.fi"}}

	rr := serveAdminDomainsRequest(store, http.MethodPut, `{"domains":[" Client2.FI ","@client.fi","client.fi"]}`)

	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	want := []string{"client.fi", "client2.fi"}
	if store.setCalls != 1 || store.setName != "dora@client.fi" || !slices.Equal(store.setDomains, want) {
		t.Fatalf("SetAdminDomains calls=%d name=%q domains=%#v, want 1/dora@client.fi/%#v", store.setCalls, store.setName, store.setDomains, want)
	}
	if got := decodeDomains(t, rr); !slices.Equal(got, want) {
		t.Fatalf("response domains = %#v, want %#v", got, want)
	}
}

func TestAdminDomainsHandlerClearsDomains(t *testing.T) {
	t.Parallel()

	store := &mockAdminDomainsStore{getAccountResult: &model.Account{Name: "dora@client.fi"}}

	rr := serveAdminDomainsRequest(store, http.MethodPut, `{"domains":[]}`)

	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	if store.setCalls != 1 || len(store.setDomains) != 0 {
		t.Fatalf("SetAdminDomains calls=%d domains=%#v, want 1/empty", store.setCalls, store.setDomains)
	}
}

func TestAdminDomainsHandlerRejectsInvalidDomains(t *testing.T) {
	t.Parallel()

	for _, domain := range []string{"", "localhost", "bob@client.fi", "client .fi", "client.fi."} {
		t.Run(domain, func(t *testing.T) {
			t.Parallel()

			store := &mockAdminDomainsStore{getAccountResult: &model.Account{Name: "dora@client.fi"}}

			rr := serveAdminDomainsRequest(store, http.MethodPut, `{"domains":["`+domain+`"]}`)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status code = %d, want %d", rr.Code, http.StatusBadRequest)
			}
			if store.setCalls != 0 {
				t.Fatalf("SetAdminDomains calls = %d, want 0", store.setCalls)
			}
		})
	}
}

func TestAdminDomainsHandlerReturnsNotFoundForMissingAccount(t *testing.T) {
	t.Parallel()

	for _, method := range []string{http.MethodGet, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			store := &mockAdminDomainsStore{}

			rr := serveAdminDomainsRequest(store, method, `{"domains":["client.fi"]}`)

			if rr.Code != http.StatusNotFound {
				t.Fatalf("status code = %d, want %d", rr.Code, http.StatusNotFound)
			}
			if store.setCalls != 0 {
				t.Fatalf("SetAdminDomains calls = %d, want 0", store.setCalls)
			}
		})
	}
}

func TestAdminDomainsHandlerMapsStoreErrors(t *testing.T) {
	t.Parallel()

	store := &mockAdminDomainsStore{getAccountResult: &model.Account{Name: "dora@client.fi"}, setErr: errAccountNotFound}

	rr := serveAdminDomainsRequest(store, http.MethodPut, `{"domains":["client.fi"]}`)

	assertError(t, rr, http.StatusNotFound, "account not found")
}
