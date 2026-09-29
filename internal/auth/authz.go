package auth

import (
	"context"
	"net/http"
	"slices"
	"strings"
)

const errForbidden = "forbidden"

// AccessStore looks up the permissions of non-admin users.
type AccessStore interface {
	ListAdminDomains(name string) ([]string, error)
	IsAdmin(name string) (bool, error)
}

// selfServiceRoutes are allowed for every user on their own account.
var selfServiceRoutes = []string{
	"GET /accounts/{name}",
	"PATCH /accounts/{name}",
	"PUT /accounts/{name}/password",
	"GET /accounts/{name}/emails",
	"GET /accounts/{name}/groups",
}

// domainAdminRoutes are allowed for domain admins on accounts in their domains.
var domainAdminRoutes = append([]string{
	"DELETE /accounts/{name}",
	"POST /accounts/{name}/emails",
	"DELETE /accounts/{name}/emails/{address}",
	"POST /accounts/{name}/groups",
	"DELETE /accounts/{name}/groups/{group}",
}, selfServiceRoutes...)

func AuthorizationMiddleware(mux *http.ServeMux, store AccessStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSONHeader(w)

		handler, pattern := mux.Handler(r)
		if pattern == "" {
			handler.ServeHTTP(w, r)
			return
		}

		if IsAdminFromContext(r.Context()) {
			handler.ServeHTTP(w, withMatchedRoute(r, pattern))
			return
		}

		username := UsernameFromContext(r.Context())
		var domains []string
		if store != nil && username != "" {
			var err error
			if domains, err = store.ListAdminDomains(username); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "failed to load permissions")
				return
			}
		}

		matched := withMatchedRoute(r.WithContext(WithAdminDomains(r.Context(), domains)), pattern)

		allowed, err := isAuthorizedRequest(matched, username, store)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to load permissions")
			return
		}
		if !allowed {
			writeJSONError(w, http.StatusForbidden, errForbidden)
			return
		}

		handler.ServeHTTP(w, matched)
	})
}

func isAuthorizedRequest(r *http.Request, username string, store AccessStore) (bool, error) {
	if username == "" {
		return false, nil
	}

	switch {
	case r.Pattern == "GET /accounts" || r.Pattern == "POST /accounts":
		return len(AdminDomainsFromContext(r.Context())) > 0, nil
	case slices.Contains(selfServiceRoutes, r.Pattern) && r.PathValue("name") == username:
		return true, nil
	case slices.Contains(domainAdminRoutes, r.Pattern):
		return canManageAccount(r, store)
	default:
		return false, nil
	}
}

// canManageAccount reports whether a domain admin may act on the account in the
// path, and whether any address or group in the path is in their domains.
func canManageAccount(r *http.Request, store AccessStore) (bool, error) {
	ctx := r.Context()
	for _, key := range []string{"address", "group"} {
		if value := r.PathValue(key); value != "" && !ManagesDomain(ctx, DomainOf(value)) {
			return false, nil
		}
	}

	return CanManageAccount(ctx, store, r.PathValue("name"))
}

// CanManageAccount reports whether the domain admin in ctx may act on the
// account called name. It must be in one of their domains and must not be a
// full admin. If it is a domain admin itself, the actor must manage every one
// of its domains, so a domain admin can't take over a peer to reach more
// domains.
func CanManageAccount(ctx context.Context, store AccessStore, name string) (bool, error) {
	if !ManagesDomain(ctx, DomainOf(name)) {
		return false, nil
	}

	isAdmin, err := store.IsAdmin(name)
	if err != nil || isAdmin {
		return false, err
	}

	domains, err := store.ListAdminDomains(name)
	if err != nil {
		return false, err
	}
	for _, domain := range domains {
		if !ManagesDomain(ctx, domain) {
			return false, nil
		}
	}

	return true, nil
}

// withMatchedRoute stamps the matched pattern and its path values onto a clone
// of r, because the mux only fills them in when it dispatches.
func withMatchedRoute(r *http.Request, pattern string) *http.Request {
	matched := r.Clone(r.Context())
	matched.Pattern = pattern

	patternPath := pattern
	if _, path, ok := strings.Cut(pattern, " "); ok {
		patternPath = path
	}

	parts := splitPath(r.URL.Path)
	for i, segment := range splitPath(patternPath) {
		if i < len(parts) && strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			matched.SetPathValue(strings.Trim(segment, "{}"), parts[i])
		}
	}

	return matched
}

func splitPath(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}

	return strings.Split(trimmed, "/")
}
