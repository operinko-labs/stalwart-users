package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStalwartAdminClientDetectsAdminRole(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/principal/alice@example.com" {
			t.Fatalf("path = %q, want /api/principal/alice@example.com", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer admin-token" {
			t.Fatalf("Authorization = %q, want Bearer admin-token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"roles":["user","admin"]}`))
	}))
	defer server.Close()

	client := NewStalwartAdminClient(server.URL, "admin-token")
	if !client.IsAdmin(context.Background(), "alice@example.com") {
		t.Fatal("expected admin role")
	}
}

func TestStalwartAdminClientReturnsFalseOnMissingRoleOrFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{name: "missing role", handler: func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"roles":["user"]}`)) }},
		{name: "missing user", handler: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }},
		{name: "bad json", handler: func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"roles":`)) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(tt.handler)
			defer server.Close()

			client := NewStalwartAdminClient(server.URL, "admin-token")
			if client.IsAdmin(context.Background(), "alice@example.com") {
				t.Fatal("expected non-admin result")
			}
		})
	}
}

func TestRolesContainAdminSupportsStringAndArray(t *testing.T) {
	t.Parallel()

	if !rolesContainAdmin([]byte(`"admin"`)) {
		t.Fatal("expected string admin to match")
	}
	if !rolesContainAdmin([]byte(`["user","admin"]`)) {
		t.Fatal("expected admin in array to match")
	}
	if rolesContainAdmin([]byte(`["user"]`)) {
		t.Fatal("expected no admin match")
	}
}
