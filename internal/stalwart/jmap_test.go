package stalwart

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

type testJMAPRequest struct {
	Using       []string             `json:"using"`
	MethodCalls []testJMAPMethodCall `json:"methodCalls"`
}

type testJMAPMethodCall []json.RawMessage

func TestCreateAccountSuccess(t *testing.T) {
	t.Parallel()

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		assertJMAPRequest(t, r)

		request := decodeTestJMAPRequest(t, r)
		method, args := decodeTestMethodCall(t, request.MethodCalls[0])

		switch requestCount {
		case 1:
			if method != "x:Domain/query" {
				t.Fatalf("method = %q, want x:Domain/query", method)
			}
			filter := args["filter"].(map[string]any)
			if filter["name"] != "vaderrp.com" {
				t.Fatalf("domain filter = %#v, want vaderrp.com", filter)
			}
			_, _ = w.Write([]byte(`{"methodResponses":[["x:Domain/query",{"ids":["domain-1"]},"c1"]]}`))
		case 2:
			if method != "x:Account/set" {
				t.Fatalf("method = %q, want x:Account/set", method)
			}
			create := args["create"].(map[string]any)
			new1 := create["new1"].(map[string]any)
			if new1["name"] != "alice" || new1["domainId"] != "domain-1" {
				t.Fatalf("create payload = %#v, want alice/domain-1", new1)
			}
			credentials := new1["credentials"].(map[string]any)
			first, ok := credentials["0"].(map[string]any)
			if len(credentials) != 1 || !ok || first["@type"] != "Password" || first["secret"] != "plaintext-password" {
				t.Fatalf("credentials = %#v, want one Password credential at key 0", credentials)
			}
			quotas := new1["quotas"].(map[string]any)
			if len(quotas) != 1 || quotas["maxDiskQuota"] != float64(5) {
				t.Fatalf("quotas = %#v, want maxDiskQuota 5", quotas)
			}
			memberGroupIDs := new1["memberGroupIds"].(map[string]any)
			if len(memberGroupIDs) != 0 {
				t.Fatalf("memberGroupIds = %#v, want empty object", memberGroupIDs)
			}
			aliases := new1["aliases"].(map[string]any)
			if len(aliases) != 0 {
				t.Fatalf("aliases = %#v, want empty object", aliases)
			}
			_, _ = w.Write([]byte(`{"methodResponses":[["x:Account/set",{"created":{"new1":{"id":"account-1"}}},"c1"]]}`))
		default:
			t.Fatalf("unexpected request count %d", requestCount)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	client.httpClient = server.Client()

	if err := client.CreateAccount(context.Background(), "alice@vaderrp.com", "plaintext-password", "Alice User", 5); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}
	if requestCount != 2 {
		t.Fatalf("request count = %d, want 2", requestCount)
	}
}

func TestDeleteAccountSuccess(t *testing.T) {
	t.Parallel()

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		assertJMAPRequest(t, r)

		request := decodeTestJMAPRequest(t, r)
		method, args := decodeTestMethodCall(t, request.MethodCalls[0])

		switch requestCount {
		case 1:
			if method != "x:Domain/query" {
				t.Fatalf("method = %q, want x:Domain/query", method)
			}
			_, _ = w.Write([]byte(`{"methodResponses":[["x:Domain/query",{"ids":["domain-1"]},"c1"]]}`))
		case 2:
			if method != "x:Account/query" {
				t.Fatalf("method = %q, want x:Account/query", method)
			}
			filter := args["filter"].(map[string]any)
			if filter["name"] != "alice" || filter["domainId"] != "domain-1" {
				t.Fatalf("account filter = %#v, want alice/domain-1", filter)
			}
			_, _ = w.Write([]byte(`{"methodResponses":[["x:Account/query",{"ids":["account-1"]},"c1"]]}`))
		case 3:
			if method != "x:Account/set" {
				t.Fatalf("method = %q, want x:Account/set", method)
			}
			destroy := args["destroy"].([]any)
			if len(destroy) != 1 || destroy[0] != "account-1" {
				t.Fatalf("destroy payload = %#v, want account-1", destroy)
			}
			_, _ = w.Write([]byte(`{"methodResponses":[["x:Account/set",{"destroyed":["account-1"]},"c1"]]}`))
		default:
			t.Fatalf("unexpected request count %d", requestCount)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	client.httpClient = server.Client()

	if err := client.DeleteAccount(context.Background(), "alice@vaderrp.com"); err != nil {
		t.Fatalf("DeleteAccount() error = %v", err)
	}
	if requestCount != 3 {
		t.Fatalf("request count = %d, want 3", requestCount)
	}
}

func TestCreateAccountDomainNotFound(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertJMAPRequest(t, r)
		_, _ = w.Write([]byte(`{"methodResponses":[["x:Domain/query",{"ids":[]},"c1"]]}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	client.httpClient = server.Client()

	err := client.CreateAccount(context.Background(), "alice@vaderrp.com", "plaintext-password", "Alice User", 0)
	if err == nil {
		t.Fatal("CreateAccount() error = nil, want error")
	}
	if got := err.Error(); got != "create account alice@vaderrp.com: query domain vaderrp.com: domain not found" {
		t.Fatalf("error = %q, want domain not found", got)
	}
}

func TestDeleteAccountNotFoundIsNotError(t *testing.T) {
	t.Parallel()

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		assertJMAPRequest(t, r)

		switch requestCount {
		case 1:
			_, _ = w.Write([]byte(`{"methodResponses":[["x:Domain/query",{"ids":["domain-1"]},"c1"]]}`))
		case 2:
			_, _ = w.Write([]byte(`{"methodResponses":[["x:Account/query",{"ids":[]},"c1"]]}`))
		default:
			t.Fatalf("unexpected request count %d", requestCount)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	client.httpClient = server.Client()

	if err := client.DeleteAccount(context.Background(), "alice@vaderrp.com"); err != nil {
		t.Fatalf("DeleteAccount() error = %v", err)
	}
	if requestCount != 2 {
		t.Fatalf("request count = %d, want 2", requestCount)
	}
}

func assertJMAPRequest(t *testing.T, r *http.Request) {
	t.Helper()

	if r.Method != http.MethodPost {
		t.Fatalf("method = %s, want %s", r.Method, http.MethodPost)
	}
	if r.URL.Path != "/jmap/" {
		t.Fatalf("path = %s, want /jmap/", r.URL.Path)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
		t.Fatalf("Authorization = %q, want bearer token", got)
	}
	if got := r.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
}

func decodeTestJMAPRequest(t *testing.T, r *http.Request) testJMAPRequest {
	t.Helper()

	var request testJMAPRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(request.Using) != 2 || request.Using[0] != jmapCoreCapability || request.Using[1] != jmapStalwartCapability {
		t.Fatalf("using = %#v, want JMAP capabilities", request.Using)
	}
	if len(request.MethodCalls) != 1 {
		t.Fatalf("methodCalls len = %d, want 1", len(request.MethodCalls))
	}

	return request
}

func decodeTestMethodCall(t *testing.T, call testJMAPMethodCall) (string, map[string]any) {
	t.Helper()

	if len(call) != 3 {
		t.Fatalf("method call len = %d, want 3", len(call))
	}

	var method string
	if err := json.Unmarshal(call[0], &method); err != nil {
		t.Fatalf("Unmarshal(method) error = %v", err)
	}

	var args map[string]any
	if err := json.Unmarshal(call[1], &args); err != nil {
		t.Fatalf("Unmarshal(args) error = %v", err)
	}

	return method, args
}

func TestListAccountsMapsFields(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertJMAPRequest(t, r)

		method, args := decodeTestMethodCall(t, decodeTestJMAPRequest(t, r).MethodCalls[0])
		if method != "x:Account/get" {
			t.Fatalf("method = %q, want x:Account/get", method)
		}
		if ids, ok := args["ids"]; !ok || ids != nil {
			t.Fatalf("ids = %#v, want explicit null", args["ids"])
		}

		_, _ = w.Write([]byte(`{"methodResponses":[["x:Account/get",{"accountId":"d333333","list":[
			{"id":"cv","@type":"User","name":"olli","domainId":"h","emailAddress":"olli@erinko.fi","description":"Olli",
			 "roles":{"@type":"Admin"},"permissions":{"@type":"Inherit"},"quotas":{"maxDiskQuota":1048576},
			 "aliases":{"0":{"enable":true,"name":"olli","domainId":"d","description":null},"1":{"enable":true,"name":"olli","domainId":"b","description":null}},
			 "memberGroupIds":{"g1":true},
			 "credentials":{"0":{"credentialId":"a","expiresAt":null,"allowedIps":{},"@type":"Password"},"1":{"credentialId":"c","description":"Stalwart Admin API","@type":"ApiKey"}},
			 "locale":"fi-FI"},
			{"id":"g1","@type":"Group","name":"staff","domainId":"h","emailAddress":"staff@erinko.fi","roles":{"@type":"User"},"quotas":{},"aliases":{},"memberGroupIds":{},"credentials":{}}
		],"notFound":[]},"c1"]]}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	client.httpClient = server.Client()

	accounts, err := client.ListAccounts(context.Background())
	if err != nil {
		t.Fatalf("ListAccounts() error = %v", err)
	}
	if len(accounts) != 2 {
		t.Fatalf("accounts len = %d, want 2", len(accounts))
	}

	olli := accounts[0]
	if olli.ID != "cv" || olli.Type != "User" || olli.Name != "olli" || olli.DomainID != "h" ||
		olli.Email != "olli@erinko.fi" || olli.Description != "Olli" {
		t.Fatalf("account = %#v, want olli fields mapped", olli)
	}
	if !olli.IsAdmin {
		t.Fatal("IsAdmin = false, want true")
	}
	if olli.DiskQuota != 1048576 {
		t.Fatalf("DiskQuota = %d, want 1048576", olli.DiskQuota)
	}
	if olli.PasswordKey != "0" {
		t.Fatalf("PasswordKey = %q, want 0", olli.PasswordKey)
	}
	if len(olli.Aliases) != 2 || olli.Aliases["0"] != (Alias{Name: "olli", DomainID: "d"}) || olli.Aliases["1"] != (Alias{Name: "olli", DomainID: "b"}) {
		t.Fatalf("Aliases = %#v, want two aliases keyed by list key", olli.Aliases)
	}
	if len(olli.MemberGroupIDs) != 1 || olli.MemberGroupIDs[0] != "g1" {
		t.Fatalf("MemberGroupIDs = %#v, want [g1]", olli.MemberGroupIDs)
	}

	group := accounts[1]
	if group.Type != "Group" || group.IsAdmin || group.DiskQuota != 0 {
		t.Fatalf("group = %#v, want non-admin Group without quota", group)
	}
}

func TestListAccountsNoPassword(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertJMAPRequest(t, r)
		_, _ = w.Write([]byte(`{"methodResponses":[["x:Account/get",{"accountId":"d333333","list":[
			{"id":"u1","@type":"User","name":"bob","domainId":"h","emailAddress":"bob@erinko.fi","roles":{"@type":"User"},"quotas":{},"aliases":{},"memberGroupIds":{},"credentials":{}}
		],"notFound":[]},"c1"]]}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	client.httpClient = server.Client()

	accounts, err := client.ListAccounts(context.Background())
	if err != nil {
		t.Fatalf("ListAccounts() error = %v", err)
	}
	if len(accounts) != 1 || accounts[0].PasswordKey != "" {
		t.Fatalf("accounts = %#v, want one account with empty PasswordKey", accounts)
	}
}

func TestListDomains(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertJMAPRequest(t, r)

		method, args := decodeTestMethodCall(t, decodeTestJMAPRequest(t, r).MethodCalls[0])
		if method != "x:Domain/get" {
			t.Fatalf("method = %q, want x:Domain/get", method)
		}
		if ids, ok := args["ids"]; !ok || ids != nil {
			t.Fatalf("ids = %#v, want explicit null", args["ids"])
		}
		properties, _ := args["properties"].([]any)
		if len(properties) != 1 || properties[0] != "name" {
			t.Fatalf("properties = %#v, want [name]", args["properties"])
		}

		_, _ = w.Write([]byte(`{"methodResponses":[["x:Domain/get",{"accountId":"d333333","list":[{"id":"h","name":"erinko.fi"},{"id":"d","name":"vaderrp.com"}],"notFound":[]},"c1"]]}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	client.httpClient = server.Client()

	domains, err := client.ListDomains(context.Background())
	if err != nil {
		t.Fatalf("ListDomains() error = %v", err)
	}
	if len(domains) != 2 || domains[0] != (Domain{ID: "h", Name: "erinko.fi"}) || domains[1] != (Domain{ID: "d", Name: "vaderrp.com"}) {
		t.Fatalf("domains = %#v, want erinko.fi and vaderrp.com", domains)
	}
}

func TestAuthenticate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		status  int
		want    bool
		wantErr bool
	}{
		{name: "valid", status: http.StatusOK, want: true},
		{name: "invalid", status: http.StatusUnauthorized, want: false},
		{name: "server error", status: http.StatusInternalServerError, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/jmap/session" {
					t.Fatalf("request = %s %s, want GET /jmap/session", r.Method, r.URL.Path)
				}
				user, pass, ok := r.BasicAuth()
				if !ok || user != "olli@erinko.fi" || pass != "s3cret" {
					t.Fatalf("basic auth = %q/%q/%v, want olli@erinko.fi/s3cret", user, pass, ok)
				}
				if got := r.Header.Get("Authorization"); strings.Contains(got, "Bearer") || !strings.HasPrefix(got, "Basic ") {
					t.Fatalf("Authorization = %q, want Basic and no bearer token", got)
				}
				w.WriteHeader(tt.status)
			}))
			defer server.Close()

			client := NewClient(server.URL, "test-token")
			client.httpClient = server.Client()

			got, err := client.Authenticate(context.Background(), "olli@erinko.fi", "s3cret")
			if (err != nil) != tt.wantErr {
				t.Fatalf("Authenticate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("Authenticate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateAccountZeroQuotaSendsEmptyQuotas(t *testing.T) {
	t.Parallel()

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		assertJMAPRequest(t, r)
		request := decodeTestJMAPRequest(t, r)
		_, args := decodeTestMethodCall(t, request.MethodCalls[0])

		if requestCount == 1 {
			_, _ = w.Write([]byte(`{"methodResponses":[["x:Domain/query",{"ids":["domain-1"]},"c1"]]}`))
			return
		}
		new1 := args["create"].(map[string]any)["new1"].(map[string]any)
		quotas := new1["quotas"].(map[string]any)
		if len(quotas) != 0 {
			t.Fatalf("quotas = %#v, want empty object", quotas)
		}
		_, _ = w.Write([]byte(`{"methodResponses":[["x:Account/set",{"created":{"new1":{"id":"account-1"}}},"c1"]]}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	client.httpClient = server.Client()

	if err := client.CreateAccount(context.Background(), "alice@vaderrp.com", "pw", "Alice", 0); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}
}

func TestCreateAccountInvalidPropertiesIsErrInvalid(t *testing.T) {
	t.Parallel()

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			_, _ = w.Write([]byte(`{"methodResponses":[["x:Domain/query",{"ids":["domain-1"]},"c1"]]}`))
			return
		}
		_, _ = w.Write([]byte(`{"methodResponses":[["x:Account/set",{"notCreated":{"new1":{"type":"invalidProperties","description":"Password is too weak","properties":["credentials/0/secret"]}}},"c1"]]}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	client.httpClient = server.Client()

	err := client.CreateAccount(context.Background(), "alice@vaderrp.com", "pw", "Alice", 0)
	var invalid ErrInvalid
	if !errors.As(err, &invalid) {
		t.Fatalf("CreateAccount() error = %v, want ErrInvalid", err)
	}
	if invalid.Description != "Password is too weak" {
		t.Fatalf("Description = %q, want Password is too weak", invalid.Description)
	}
}

func TestUpdateAccountPatch(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertJMAPRequest(t, r)
		request := decodeTestJMAPRequest(t, r)
		method, args := decodeTestMethodCall(t, request.MethodCalls[0])
		if method != "x:Account/set" {
			t.Fatalf("method = %q, want x:Account/set", method)
		}
		patch := args["update"].(map[string]any)["cv"].(map[string]any)
		if patch["description"] != "New" || patch["quotas/maxDiskQuota"] != float64(7) {
			t.Fatalf("patch = %#v, want description and quota keys", patch)
		}
		_, _ = w.Write([]byte(`{"methodResponses":[["x:Account/set",{"accountId":"d333333","updated":{"cv":null}},"c1"]]}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	client.httpClient = server.Client()

	err := client.UpdateAccount(context.Background(), "cv", map[string]any{"description": "New", "quotas/maxDiskQuota": 7})
	if err != nil {
		t.Fatalf("UpdateAccount() error = %v", err)
	}
}

func TestSetPasswordPatchesExisting(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertJMAPRequest(t, r)
		request := decodeTestJMAPRequest(t, r)
		_, args := decodeTestMethodCall(t, request.MethodCalls[0])
		patch := args["update"].(map[string]any)["cv"].(map[string]any)
		if len(patch) != 1 || patch["credentials/0/secret"] != "newpw" {
			t.Fatalf("patch = %#v, want only credentials/0/secret", patch)
		}
		_, _ = w.Write([]byte(`{"methodResponses":[["x:Account/set",{"accountId":"d333333","updated":{"cv":null}},"c1"]]}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	client.httpClient = server.Client()

	if err := client.SetPassword(context.Background(), Account{ID: "cv", PasswordKey: "0"}, "newpw"); err != nil {
		t.Fatalf("SetPassword() error = %v", err)
	}
}

func TestSetPasswordCreatesCredential(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertJMAPRequest(t, r)
		request := decodeTestJMAPRequest(t, r)
		_, args := decodeTestMethodCall(t, request.MethodCalls[0])
		patch := args["update"].(map[string]any)["cv"].(map[string]any)
		credential, ok := patch["credentials/0"].(map[string]any)
		if len(patch) != 1 || !ok || credential["@type"] != "Password" || credential["secret"] != "newpw" {
			t.Fatalf("patch = %#v, want credentials/0 Password credential", patch)
		}
		_, _ = w.Write([]byte(`{"methodResponses":[["x:Account/set",{"accountId":"d333333","updated":{"cv":null}},"c1"]]}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	client.httpClient = server.Client()

	if err := client.SetPassword(context.Background(), Account{ID: "cv"}, "newpw"); err != nil {
		t.Fatalf("SetPassword() error = %v", err)
	}
}

func TestSetPasswordInvalidProperties(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"methodResponses":[["x:Account/set",{"notUpdated":{"cv":{"type":"invalidProperties","description":"Password is too weak","properties":["credentials/0/secret"]}}},"c1"]]}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	client.httpClient = server.Client()

	err := client.SetPassword(context.Background(), Account{ID: "cv", PasswordKey: "0"}, "x")
	var invalid ErrInvalid
	if !errors.As(err, &invalid) {
		t.Fatalf("SetPassword() error = %v, want ErrInvalid", err)
	}
	if invalid.Description != "Password is too weak" || invalid.Error() != "Password is too weak" {
		t.Fatalf("Description = %q, Error() = %q, want Password is too weak", invalid.Description, invalid.Error())
	}
}

func TestUpdateAccountOtherFailureIsNotErrInvalid(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"methodResponses":[["x:Account/set",{"notUpdated":{"cv":{"type":"notFound"}}},"c1"]]}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	client.httpClient = server.Client()

	err := client.UpdateAccount(context.Background(), "cv", map[string]any{"description": "x"})
	if err == nil {
		t.Fatal("UpdateAccount() error = nil, want error")
	}
	var invalid ErrInvalid
	if errors.As(err, &invalid) {
		t.Fatalf("error = %v, want not ErrInvalid", err)
	}
}

func TestSetPasswordCreatesCredentialAtFirstUnusedKey(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertJMAPRequest(t, r)
		request := decodeTestJMAPRequest(t, r)
		_, args := decodeTestMethodCall(t, request.MethodCalls[0])
		patch := args["update"].(map[string]any)["cv"].(map[string]any)
		credential, ok := patch["credentials/10"].(map[string]any)
		if len(patch) != 1 || !ok || credential["@type"] != "Password" || credential["secret"] != "newpw" {
			t.Fatalf("patch = %#v, want only a credentials/10 Password credential", patch)
		}
		_, _ = w.Write([]byte(`{"methodResponses":[["x:Account/set",{"accountId":"d333333","updated":{"cv":null}},"c1"]]}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	client.httpClient = server.Client()

	// An ApiKey at 0 and a non-numeric key must not be overwritten; the largest
	// numeric key is 9, so the new credential goes to 10.
	account := Account{ID: "cv", CredentialKeys: []string{"0", "9", "x"}}
	if err := client.SetPassword(context.Background(), account, "newpw"); err != nil {
		t.Fatalf("SetPassword() error = %v", err)
	}
}

func TestSetPasswordDoesNotOverwriteApiKeyAtZero(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := decodeTestJMAPRequest(t, r)
		_, args := decodeTestMethodCall(t, request.MethodCalls[0])
		patch := args["update"].(map[string]any)["cv"].(map[string]any)
		if _, ok := patch["credentials/1"].(map[string]any); len(patch) != 1 || !ok {
			t.Fatalf("patch = %#v, want only credentials/1", patch)
		}
		_, _ = w.Write([]byte(`{"methodResponses":[["x:Account/set",{"accountId":"d333333","updated":{"cv":null}},"c1"]]}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	client.httpClient = server.Client()

	account := Account{ID: "cv", CredentialKeys: []string{"0"}}
	if err := client.SetPassword(context.Background(), account, "newpw"); err != nil {
		t.Fatalf("SetPassword() error = %v", err)
	}
}

func TestListAccountsCredentialKeysAndNumericPasswordKey(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"methodResponses":[["x:Account/get",{"accountId":"d333333","list":[
			{"id":"u1","@type":"User","name":"bob","domainId":"h","emailAddress":"bob@erinko.fi","roles":{"@type":"User"},"quotas":{},"aliases":{},"memberGroupIds":{},
			 "credentials":{"0":{"@type":"ApiKey"},"10":{"@type":"Password"},"9":{"@type":"Password"}}},
			{"id":"u2","@type":"User","name":"amy","domainId":"h","emailAddress":"amy@erinko.fi","roles":{"@type":"User"},"quotas":{},"aliases":{},"memberGroupIds":{},
			 "credentials":{"0":{"@type":"ApiKey"}}}
		],"notFound":[]},"c1"]]}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	client.httpClient = server.Client()

	accounts, err := client.ListAccounts(context.Background())
	if err != nil {
		t.Fatalf("ListAccounts() error = %v", err)
	}
	if accounts[0].PasswordKey != "9" {
		t.Fatalf("PasswordKey = %q, want 9 (numeric order, not string order)", accounts[0].PasswordKey)
	}
	if !reflect.DeepEqual(accounts[0].CredentialKeys, []string{"0", "9", "10"}) {
		t.Fatalf("CredentialKeys = %#v, want [0 9 10]", accounts[0].CredentialKeys)
	}
	if accounts[1].PasswordKey != "" || !reflect.DeepEqual(accounts[1].CredentialKeys, []string{"0"}) {
		t.Fatalf("account = %#v, want no PasswordKey and CredentialKeys [0]", accounts[1])
	}
}

func TestCreateAccountAlreadyExists(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, _ := decodeTestMethodCall(t, decodeTestJMAPRequest(t, r).MethodCalls[0])
		if method == "x:Domain/query" {
			_, _ = w.Write([]byte(`{"methodResponses":[["x:Domain/query",{"ids":["h"]},"c1"]]}`))
			return
		}
		_, _ = w.Write([]byte(`{"methodResponses":[["x:Account/set",{"notCreated":{"new1":{"type":"alreadyExists","description":"An account with this name already exists"}}},"c1"]]}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	client.httpClient = server.Client()

	err := client.CreateAccount(context.Background(), "bob@erinko.fi", "pw", "", 0)
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("CreateAccount() error = %v, want ErrAlreadyExists", err)
	}
}

// Authenticate drains the session response so the keep-alive connection is
// reused; an undrained body makes the transport close it.
func TestAuthenticateDrainsBodyForConnectionReuse(t *testing.T) {
	t.Parallel()

	var newConns atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); !ok {
			t.Error("request without basic auth")
		}
		_, _ = w.Write([]byte(`{"capabilities":{},"accounts":{},"username":"bob@erinko.fi"}`))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConns.Add(1)
		}
	}
	server.Start()
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	client.httpClient = server.Client()

	for range 2 {
		if ok, err := client.Authenticate(context.Background(), "bob@erinko.fi", "pw"); err != nil || !ok {
			t.Fatalf("Authenticate() = %v, %v; want true", ok, err)
		}
	}
	if n := newConns.Load(); n != 1 {
		t.Fatalf("connections = %d, want 1 (body drained, connection reused)", n)
	}
}
