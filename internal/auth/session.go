package auth

import (
	"encoding/json"
	"net/http"
)

func MeHandler(tokens *TokenManager, store AccessStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSONHeader(w)

		if tokens == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "authentication unavailable")
			return
		}

		session, err := tokens.ReadSession(r)
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, "invalid session")
			return
		}

		domains := []string{}
		if !session.IsAdmin && store != nil {
			found, err := store.ListAdminDomains(session.Username)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "failed to load permissions")
				return
			}
			domains = append(domains, found...)
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(meResponse{Session: *session, AdminDomains: domains})
	}
}

type meResponse struct {
	Session
	AdminDomains []string `json:"adminDomains"`
}

// LogoutHandler ends the stalwart-users session and forgets its OAuth tokens. It
// doesn't end the user's Stalwart login session.
func LogoutHandler(tokens *TokenManager, store *TokenStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSONHeader(w)

		if tokens == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "authentication unavailable")
			return
		}

		if session, err := tokens.ReadSession(r); err == nil && session.ID != "" {
			store.Delete(session.ID)
		}
		tokens.ClearCookie(w)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "logged out"})
	}
}
