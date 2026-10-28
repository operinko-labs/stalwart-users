package auth

import (
	"context"
	"slices"
	"strings"
)

const adminDomainsKey contextKey = "adminDomains"

// CanonicalName is the form account names and addresses are stored and
// compared in: trimmed and lower-cased.
func CanonicalName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// DomainOf returns the lowercased domain of an account name or address, or ""
// when it has none.
func DomainOf(name string) string {
	i := strings.LastIndex(name, "@")
	if i < 0 {
		return ""
	}
	return strings.ToLower(name[i+1:])
}

// WithUser returns ctx carrying the authenticated user's identity.
func WithUser(ctx context.Context, username string, isAdmin bool) context.Context {
	ctx = context.WithValue(ctx, usernameKey, username)
	return context.WithValue(ctx, isAdminKey, isAdmin)
}

// WithAdminDomains returns ctx carrying the domains the user administers.
func WithAdminDomains(ctx context.Context, domains []string) context.Context {
	return context.WithValue(ctx, adminDomainsKey, domains)
}

func AdminDomainsFromContext(ctx context.Context) []string {
	domains, _ := ctx.Value(adminDomainsKey).([]string)
	return domains
}

// ManagesDomain reports whether the user in ctx is a domain admin for domain.
func ManagesDomain(ctx context.Context, domain string) bool {
	return domain != "" && slices.Contains(AdminDomainsFromContext(ctx), domain)
}
