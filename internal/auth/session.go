package auth

import (
	"encoding/json"
	"net/http"
)

func MeHandler(tokens *TokenManager) http.HandlerFunc {
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

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(session)
	}
}

func LogoutHandler(tokens *TokenManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSONHeader(w)

		if tokens == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "authentication unavailable")
			return
		}

		tokens.ClearCookie(w)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "logged out"})
	}
}
