package stalwart

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// oauthStep is one expected JMAP call and the raw answer to it. status 0 means
// 200.
type oauthStep struct {
	method string
	status int
	reply  string
}

// oauthRecorder serves steps in order and records each call's arguments.
type oauthRecorder struct {
	mu    sync.Mutex
	calls []map[string]any
}

func (r *oauthRecorder) args(i int) map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[i]
}

func (r *oauthRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func newOAuthClientServer(t *testing.T, steps ...oauthStep) (*Client, *oauthRecorder) {
	t.Helper()

	rec := &oauthRecorder{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertJMAPRequest(t, r)
		method, args := decodeTestMethodCall(t, decodeTestJMAPRequest(t, r).MethodCalls[0])
		rec.mu.Lock()
		i := len(rec.calls)
		rec.calls = append(rec.calls, args)
		rec.mu.Unlock()
		if i >= len(steps) {
			t.Errorf("unexpected request %d: %s", i+1, method)
			http.Error(w, "unexpected", http.StatusInternalServerError)
			return
		}
		if method != steps[i].method {
			t.Errorf("request %d method = %q, want %q", i+1, method, steps[i].method)
		}
		if steps[i].status != 0 {
			w.WriteHeader(steps[i].status)
		}
		_, _ = w.Write([]byte(steps[i].reply))
	}))
	t.Cleanup(server.Close)

	client := NewClient(server.URL, "test-token")
	client.httpClient = server.Client()
	return client, rec
}

var testOAuthSpec = OAuthClientSpec{
	ClientID:    "stalwart-users",
	Secret:      "super-secret-value",
	RedirectURI: "https://users.example.com/api/auth/callback",
	Description: "stalwart-users",
}

var (
	queryNone     = oauthStep{method: "x:OAuthClient/query", reply: `{"methodResponses":[["x:OAuthClient/query",{"ids":[]},"c1"]]}`}
	wantQueryArgs = map[string]any{"filter": map[string]any{"clientId": "stalwart-users"}}
)

func queryIDs(ids string) oauthStep {
	return oauthStep{method: "x:OAuthClient/query", reply: `{"methodResponses":[["x:OAuthClient/query",{"ids":[` + ids + `]},"c1"]]}`}
}

func getList(list string) oauthStep {
	return oauthStep{method: "x:OAuthClient/get", reply: `{"methodResponses":[["x:OAuthClient/get",{"list":[` + list + `]},"c1"]]}`}
}

func setReply(body string) oauthStep {
	return oauthStep{method: "x:OAuthClient/set", reply: `{"methodResponses":[["x:OAuthClient/set",` + body + `,"c1"]]}`}
}

var wantCreateArgs = map[string]any{"create": map[string]any{"new1": map[string]any{
	"clientId":               "stalwart-users",
	"description":            "stalwart-users",
	"contacts":               map[string]any{},
	"secret":                 "super-secret-value",
	"redirectUris":           map[string]any{"https://users.example.com/api/auth/callback": true},
	"postLogoutRedirectUris": map[string]any{},
	"logo":                   nil,
	"firstParty":             true,
	"scopes":                 map[string]any{},
	"grantTypes":             map[string]any{"authorizationCode": true, "refreshToken": true},
}}}

func wantUpdateArgs(id string) map[string]any {
	return map[string]any{"update": map[string]any{id: map[string]any{
		"secret":       "super-secret-value",
		"redirectUris": map[string]any{"https://users.example.com/api/auth/callback": true},
		"firstParty":   true,
		"grantTypes":   map[string]any{"authorizationCode": true, "refreshToken": true},
		"description":  "stalwart-users",
	}}}
}

func TestEnsureOAuthClientCreates(t *testing.T) {
	t.Parallel()

	client, rec := newOAuthClientServer(t, queryNone, setReply(`{"created":{"new1":{"id":"c9"}}}`))

	created, err := client.EnsureOAuthClient(context.Background(), testOAuthSpec)
	if err != nil || !created {
		t.Fatalf("EnsureOAuthClient() = %v, %v; want true, nil", created, err)
	}
	if !reflect.DeepEqual(rec.args(0), wantQueryArgs) {
		t.Fatalf("query args = %#v, want %#v", rec.args(0), wantQueryArgs)
	}
	if !reflect.DeepEqual(rec.args(1), wantCreateArgs) {
		t.Fatalf("create args = %#v, want %#v", rec.args(1), wantCreateArgs)
	}
}

func TestEnsureOAuthClientUpdatesExisting(t *testing.T) {
	t.Parallel()

	client, rec := newOAuthClientServer(t,
		queryIDs(`"b"`),
		getList(`{"id":"b","clientId":"stalwart-users"}`),
		setReply(`{"updated":{"b":null}}`))

	created, err := client.EnsureOAuthClient(context.Background(), testOAuthSpec)
	if err != nil || created {
		t.Fatalf("EnsureOAuthClient() = %v, %v; want false, nil", created, err)
	}
	wantGet := map[string]any{"ids": []any{"b"}, "properties": []any{"clientId"}}
	if !reflect.DeepEqual(rec.args(1), wantGet) {
		t.Fatalf("get args = %#v, want %#v", rec.args(1), wantGet)
	}
	if !reflect.DeepEqual(rec.args(2), wantUpdateArgs("b")) {
		t.Fatalf("update args = %#v, want %#v", rec.args(2), wantUpdateArgs("b"))
	}
}

// The query filter may match more than the exact clientId; a client that
// merely came back from the query must never be touched.
func TestEnsureOAuthClientCreatesWhenQueryReturnsOnlyOtherClients(t *testing.T) {
	t.Parallel()

	client, rec := newOAuthClientServer(t,
		queryIDs(`"x"`),
		getList(`{"id":"x","clientId":"stalwart-users-staging"}`),
		setReply(`{"created":{"new1":{"id":"c9"}}}`))

	created, err := client.EnsureOAuthClient(context.Background(), testOAuthSpec)
	if err != nil || !created {
		t.Fatalf("EnsureOAuthClient() = %v, %v; want true, nil", created, err)
	}
	if !reflect.DeepEqual(rec.args(2), wantCreateArgs) {
		t.Fatalf("set args = %#v, want the create payload", rec.args(2))
	}
}

func TestEnsureOAuthClientUpdatesOnlyTheExactMatch(t *testing.T) {
	t.Parallel()

	client, rec := newOAuthClientServer(t,
		queryIDs(`"x","b","y"`),
		getList(`{"id":"x","clientId":"stalwart-users-staging"},{"id":"b","clientId":"stalwart-users"},{"id":"y","clientId":"Stalwart-Users"}`),
		setReply(`{"updated":{"b":null}}`))

	created, err := client.EnsureOAuthClient(context.Background(), testOAuthSpec)
	if err != nil || created {
		t.Fatalf("EnsureOAuthClient() = %v, %v; want false, nil", created, err)
	}
	if !reflect.DeepEqual(rec.args(2), wantUpdateArgs("b")) {
		t.Fatalf("update args = %#v, want only b updated", rec.args(2))
	}
}

func TestEnsureOAuthClientRefusesAmbiguousMatch(t *testing.T) {
	t.Parallel()

	client, rec := newOAuthClientServer(t,
		queryIDs(`"a","b"`),
		getList(`{"id":"a","clientId":"stalwart-users"},{"id":"b","clientId":"stalwart-users"}`))

	if _, err := client.EnsureOAuthClient(context.Background(), testOAuthSpec); err == nil {
		t.Fatal("EnsureOAuthClient() error = nil, want one for two exact matches")
	}
	if n := rec.count(); n != 2 {
		t.Fatalf("requests = %d, want 2 (query and get, no set)", n)
	}
}

func TestEnsureOAuthClientErrorHasNoSecret(t *testing.T) {
	t.Parallel()

	secret := testOAuthSpec.Secret
	echo := secret + " is not allowed"
	tests := map[string][]oauthStep{
		"notCreated description echoes the secret": {
			queryNone,
			setReply(`{"notCreated":{"new1":{"type":"invalidProperties","description":"` + echo + `"}}}`),
		},
		"notUpdated description echoes the secret": {
			queryIDs(`"b"`),
			getList(`{"id":"b","clientId":"stalwart-users"}`),
			setReply(`{"notUpdated":{"b":{"type":"forbidden","description":"` + echo + `"}}}`),
		},
		"jmap error echoes the secret": {
			queryNone,
			{method: "x:OAuthClient/set", reply: `{"methodResponses":[["error",{"type":"serverFail","description":"` + echo + `"},"c1"]]}`},
		},
		"non-200 body echoes the secret": {
			queryNone,
			{method: "x:OAuthClient/set", status: http.StatusBadRequest, reply: "bad request: " + echo},
		},
	}
	for name, steps := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client, _ := newOAuthClientServer(t, steps...)
			_, err := client.EnsureOAuthClient(context.Background(), testOAuthSpec)
			if err == nil {
				t.Fatal("EnsureOAuthClient() error = nil")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error leaks the secret: %v", err)
			}
			if !strings.Contains(err.Error(), "[redacted]") {
				t.Fatalf("error = %v, want the secret masked as [redacted]", err)
			}
		})
	}
}

func TestEnsureOAuthClientRedactedErrorKeepsErrorsIs(t *testing.T) {
	t.Parallel()

	client, _ := newOAuthClientServer(t, queryNone,
		setReply(`{"notCreated":{"new1":{"type":"alreadyExists","description":"x"}}}`))
	_, err := client.EnsureOAuthClient(context.Background(), testOAuthSpec)
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("err = %v, want errors.Is ErrAlreadyExists", err)
	}
}

func TestNon200BodyInErrorIsTruncated(t *testing.T) {
	t.Parallel()

	client, _ := newOAuthClientServer(t, oauthStep{
		method: "x:OAuthClient/query", status: http.StatusBadGateway, reply: strings.Repeat("A", 5000),
	})
	_, err := client.EnsureOAuthClient(context.Background(), testOAuthSpec)
	if err == nil {
		t.Fatal("EnsureOAuthClient() error = nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, strings.Repeat("A", maxErrorBodyBytes)) || strings.Contains(msg, strings.Repeat("A", maxErrorBodyBytes+1)) {
		t.Fatalf("error carries %d bytes, want the body cut at %d", len(msg), maxErrorBodyBytes)
	}
}
