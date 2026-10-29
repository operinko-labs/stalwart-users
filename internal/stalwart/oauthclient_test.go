package stalwart

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func newOAuthClientServer(t *testing.T, queryReply, setReply string, onSet func(args map[string]any)) *Client {
	t.Helper()

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		assertJMAPRequest(t, r)
		method, args := decodeTestMethodCall(t, decodeTestJMAPRequest(t, r).MethodCalls[0])
		switch requestCount {
		case 1:
			if method != "x:OAuthClient/query" {
				t.Errorf("method = %q, want x:OAuthClient/query", method)
			}
			if want := map[string]any{"filter": map[string]any{"clientId": "stalwart-users"}}; !reflect.DeepEqual(args, want) {
				t.Errorf("query args = %#v, want %#v", args, want)
			}
			_, _ = w.Write([]byte(queryReply))
		case 2:
			if method != "x:OAuthClient/set" {
				t.Errorf("method = %q, want x:OAuthClient/set", method)
			}
			onSet(args)
			_, _ = w.Write([]byte(setReply))
		default:
			t.Errorf("unexpected request %d", requestCount)
		}
	}))
	t.Cleanup(server.Close)

	client := NewClient(server.URL, "test-token")
	client.httpClient = server.Client()
	return client
}

var testOAuthSpec = OAuthClientSpec{
	ClientID:    "stalwart-users",
	Secret:      "super-secret-value",
	RedirectURI: "https://users.example.com/api/auth/callback",
	Description: "stalwart-users",
}

func TestEnsureOAuthClientCreates(t *testing.T) {
	t.Parallel()

	var got map[string]any
	client := newOAuthClientServer(t,
		`{"methodResponses":[["x:OAuthClient/query",{"ids":[]},"c1"]]}`,
		`{"methodResponses":[["x:OAuthClient/set",{"created":{"new1":{"id":"c9"}}},"c1"]]}`,
		func(args map[string]any) { got = args })

	created, err := client.EnsureOAuthClient(context.Background(), testOAuthSpec)
	if err != nil || !created {
		t.Fatalf("EnsureOAuthClient() = %v, %v; want true, nil", created, err)
	}

	want := map[string]any{"create": map[string]any{"new1": map[string]any{
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
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("create args = %#v, want %#v", got, want)
	}
}

func TestEnsureOAuthClientUpdatesExisting(t *testing.T) {
	t.Parallel()

	var got map[string]any
	client := newOAuthClientServer(t,
		`{"methodResponses":[["x:OAuthClient/query",{"ids":["b"]},"c1"]]}`,
		`{"methodResponses":[["x:OAuthClient/set",{"updated":{"b":null}},"c1"]]}`,
		func(args map[string]any) { got = args })

	created, err := client.EnsureOAuthClient(context.Background(), testOAuthSpec)
	if err != nil || created {
		t.Fatalf("EnsureOAuthClient() = %v, %v; want false, nil", created, err)
	}

	want := map[string]any{"update": map[string]any{"b": map[string]any{
		"secret":       "super-secret-value",
		"redirectUris": map[string]any{"https://users.example.com/api/auth/callback": true},
		"firstParty":   true,
		"grantTypes":   map[string]any{"authorizationCode": true, "refreshToken": true},
		"description":  "stalwart-users",
	}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("update args = %#v, want %#v", got, want)
	}
}

func TestEnsureOAuthClientErrorHasNoSecret(t *testing.T) {
	t.Parallel()

	tests := map[string]struct{ query, set string }{
		"notCreated": {
			`{"methodResponses":[["x:OAuthClient/query",{"ids":[]},"c1"]]}`,
			`{"methodResponses":[["x:OAuthClient/set",{"notCreated":{"new1":{"type":"invalidProperties","description":"bad secret"}}},"c1"]]}`,
		},
		"emptyCreate": {
			`{"methodResponses":[["x:OAuthClient/query",{"ids":[]},"c1"]]}`,
			`{"methodResponses":[["x:OAuthClient/set",{},"c1"]]}`,
		},
		"notUpdated": {
			`{"methodResponses":[["x:OAuthClient/query",{"ids":["b"]},"c1"]]}`,
			`{"methodResponses":[["x:OAuthClient/set",{"notUpdated":{"b":{"type":"forbidden","description":"nope"}}},"c1"]]}`,
		},
		"emptyUpdate": {
			`{"methodResponses":[["x:OAuthClient/query",{"ids":["b"]},"c1"]]}`,
			`{"methodResponses":[["x:OAuthClient/set",{},"c1"]]}`,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client := newOAuthClientServer(t, tt.query, tt.set, func(map[string]any) {})
			_, err := client.EnsureOAuthClient(context.Background(), testOAuthSpec)
			if err == nil {
				t.Fatal("EnsureOAuthClient() error = nil")
			}
			if strings.Contains(err.Error(), testOAuthSpec.Secret) {
				t.Fatalf("error leaks the secret: %v", err)
			}
		})
	}
}
