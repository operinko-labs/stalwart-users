package stalwart

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
			if len(credentials) != 0 {
				t.Fatalf("credentials = %#v, want empty object", credentials)
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

	if err := client.CreateAccount(context.Background(), "alice@vaderrp.com", "plaintext-password"); err != nil {
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

	err := client.CreateAccount(context.Background(), "alice@vaderrp.com", "plaintext-password")
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
