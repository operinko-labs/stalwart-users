package auth

import (
	"net/http"
	"strings"
)

const errForbidden = "forbidden"

func AuthorizationMiddleware(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSONHeader(w)

		handler, pattern := mux.Handler(r)
		if pattern == "" {
			handler.ServeHTTP(w, r)
			return
		}

		matched := withMatchedRoute(r, pattern)

		if IsAdminFromContext(matched.Context()) {
			handler.ServeHTTP(w, matched)
			return
		}

		if !isAuthorizedRequest(matched, UsernameFromContext(matched.Context())) {
			writeJSONError(w, http.StatusForbidden, errForbidden)
			return
		}

		handler.ServeHTTP(w, matched)
	})
}

func isAuthorizedRequest(r *http.Request, username string) bool {
	if username == "" {
		return false
	}

	switch r.Pattern {
	case "GET /accounts/{name}", "PATCH /accounts/{name}", "GET /accounts/{name}/emails", "POST /accounts/{name}/emails", "DELETE /accounts/{name}/emails/{address}", "GET /accounts/{name}/groups":
		return r.PathValue("name") == username
	default:
		return false
	}
}

func withMatchedRoute(r *http.Request, pattern string) *http.Request {
	matched := r.Clone(r.Context())
	matched.Pattern = pattern

	parts := splitPath(r.URL.Path)
	switch pattern {
	case "GET /accounts/{name}", "PATCH /accounts/{name}", "DELETE /accounts/{name}", "GET /accounts/{name}/emails", "POST /accounts/{name}/emails", "GET /accounts/{name}/groups", "POST /accounts/{name}/groups":
		if len(parts) >= 2 {
			matched.SetPathValue("name", parts[1])
		}
	case "DELETE /accounts/{name}/emails/{address}":
		if len(parts) >= 4 {
			matched.SetPathValue("name", parts[1])
			matched.SetPathValue("address", parts[3])
		}
	case "DELETE /accounts/{name}/groups/{group}":
		if len(parts) >= 4 {
			matched.SetPathValue("name", parts[1])
			matched.SetPathValue("group", parts[3])
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
