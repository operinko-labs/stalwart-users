package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type AuthenticatedUser struct {
	Username string
	IsAdmin  bool
}

type CredentialAuthenticator interface {
	Authenticate(ctx context.Context, username, password string) (*AuthenticatedUser, error)
}

type credentialChecker interface {
	Authenticate(ctx context.Context, username, password string) (bool, error)
}

// StalwartAuthenticator checks credentials against Stalwart and takes the
// admin flag from the access store.
type StalwartAuthenticator struct {
	checker credentialChecker
	admins  AccessStore
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func NewStalwartAuthenticator(checker credentialChecker, admins AccessStore) *StalwartAuthenticator {
	return &StalwartAuthenticator{checker: checker, admins: admins}
}

func (a *StalwartAuthenticator) Authenticate(ctx context.Context, username, password string) (*AuthenticatedUser, error) {
	username = strings.ToLower(strings.TrimSpace(username))

	ok, err := a.checker.Authenticate(ctx, username, password)
	if err != nil || !ok {
		return nil, err
	}

	isAdmin, err := a.admins.IsAdmin(username)
	if err != nil {
		return nil, err
	}

	return &AuthenticatedUser{Username: username, IsAdmin: isAdmin}, nil
}

func LoginHandler(authenticator CredentialAuthenticator, tokens *TokenManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSONHeader(w)

		if authenticator == nil || tokens == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "authentication unavailable")
			return
		}

		var req loginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		if req.Email == "" || req.Password == "" {
			writeJSONError(w, http.StatusBadRequest, "email and password are required")
			return
		}

		user, err := authenticator.Authenticate(r.Context(), req.Email, req.Password)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "authentication failed")
			return
		}
		if user == nil {
			writeJSONError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		token, err := tokens.GenerateToken(user.Username, user.IsAdmin)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to create session")
			return
		}

		tokens.SetCookie(w, token)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(Session{Username: user.Username, IsAdmin: user.IsAdmin})
	}
}
