package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"
)

type contextKey string

const usernameKey contextKey = "username"

// UsernameFromContext extracts the username from the request context.
func UsernameFromContext(ctx context.Context) string {
	username, ok := ctx.Value(usernameKey).(string)
	if !ok {
		return ""
	}
	return username
}

// JMAPAuthMiddleware returns a middleware that validates JMAP tokens via Stalwart's /jmap/session endpoint.
// If authBypass is true, all validation is skipped and the next handler is called immediately.
func JMAPAuthMiddleware(stalwartURL string, adminUsers []string, authBypass bool) func(http.Handler) http.Handler {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Bypass all validation if AUTH_BYPASS is enabled
			if authBypass {
				next.ServeHTTP(w, r)
				return
			}

			// Extract Bearer token
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				writeJSONError(w, http.StatusUnauthorized, "authorization required")
				return
			}

			const bearerPrefix = "Bearer "
			if !strings.HasPrefix(authHeader, bearerPrefix) {
				writeJSONError(w, http.StatusUnauthorized, "authorization required")
				return
			}

			token := strings.TrimPrefix(authHeader, bearerPrefix)
			if token == "" {
				writeJSONError(w, http.StatusUnauthorized, "authorization required")
				return
			}

			// Forward token to Stalwart's /jmap/session endpoint
			sessionURL := stalwartURL + "/jmap/session"
			req, err := http.NewRequest("GET", sessionURL, nil)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "internal error")
				return
			}

			req.Header.Set("Authorization", "Bearer "+token)

			resp, err := client.Do(req)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "invalid token")
				return
			}
			defer resp.Body.Close()

			// If Stalwart returns non-200, token is invalid
			if resp.StatusCode != http.StatusOK {
				writeJSONError(w, http.StatusUnauthorized, "invalid token")
				return
			}

			// Parse JMAP session response to extract username
			var sessionData struct {
				Username string `json:"username"`
			}

			if err := json.NewDecoder(resp.Body).Decode(&sessionData); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "internal error")
				return
			}

			// Check if user is an admin
			if !isAdmin(sessionData.Username, adminUsers) {
				writeJSONError(w, http.StatusForbidden, "admin access required")
				return
			}

			// Store username in context and call next handler
			ctx := context.WithValue(r.Context(), usernameKey, sessionData.Username)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// isAdmin checks if the username is in the admin users list.
func isAdmin(username string, adminUsers []string) bool {
	return slices.Contains(adminUsers, username)
}

// writeJSONError writes a JSON error response.
func writeJSONError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
