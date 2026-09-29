package auth

import (
	"context"
	"testing"
)

func TestDomainOf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "address", in: "alice@client.fi", want: "client.fi"},
		{name: "mixed case", in: "Alice@Client.FI", want: "client.fi"},
		{name: "no at sign", in: "admin", want: ""},
		{name: "empty domain", in: "alice@", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := DomainOf(tt.in); got != tt.want {
				t.Fatalf("DomainOf(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestManagesDomain(t *testing.T) {
	t.Parallel()

	ctx := WithAdminDomains(context.Background(), []string{"client.fi"})

	if !ManagesDomain(ctx, "client.fi") {
		t.Fatal("expected client.fi to be managed")
	}
	if ManagesDomain(ctx, "other.fi") {
		t.Fatal("expected other.fi not to be managed")
	}
	if ManagesDomain(ctx, "") {
		t.Fatal("expected the empty domain not to be managed")
	}
	if ManagesDomain(context.Background(), "client.fi") {
		t.Fatal("expected no domains without admin domains in context")
	}
}

func TestAdminDomainsFromContext(t *testing.T) {
	t.Parallel()

	ctx := WithAdminDomains(context.Background(), []string{"a.fi", "b.fi"})

	got := AdminDomainsFromContext(ctx)
	if len(got) != 2 || got[0] != "a.fi" || got[1] != "b.fi" {
		t.Fatalf("AdminDomainsFromContext() = %#v, want [a.fi b.fi]", got)
	}
	if got := AdminDomainsFromContext(context.Background()); len(got) != 0 {
		t.Fatalf("AdminDomainsFromContext() = %#v, want empty", got)
	}
}

func TestWithUserSetsIdentity(t *testing.T) {
	t.Parallel()

	ctx := WithUser(context.Background(), "alice@client.fi", true)

	if got := UsernameFromContext(ctx); got != "alice@client.fi" {
		t.Fatalf("UsernameFromContext() = %q, want alice@client.fi", got)
	}
	if !IsAdminFromContext(ctx) {
		t.Fatal("expected admin")
	}
}
