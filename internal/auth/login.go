package auth

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/operinko-labs/stalwart-users/internal/model"
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

// LoginStore resolves login names to User accounts and holds their access.
type LoginStore interface {
	AccessStore
	// GetAccount returns the User whose primary address is name (exact
	// canonical match), or nil when there is none.
	GetAccount(name string) (*model.Account, error)
}

// StalwartAuthenticator checks credentials against Stalwart and takes the
// admin flag from the access store.
type StalwartAuthenticator struct {
	checker credentialChecker
	admins  LoginStore
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func NewStalwartAuthenticator(checker credentialChecker, admins LoginStore) *StalwartAuthenticator {
	return &StalwartAuthenticator{checker: checker, admins: admins}
}

func (a *StalwartAuthenticator) Authenticate(ctx context.Context, username, password string) (*AuthenticatedUser, error) {
	username = CanonicalName(username)

	ok, err := a.checker.Authenticate(ctx, username, password)
	if err != nil || !ok {
		return nil, err
	}

	// Stalwart also accepts aliases and bare principal names. The session must
	// name a User's primary address, so any other name is invalid credentials.
	account, err := a.admins.GetAccount(username)
	if err != nil {
		return nil, err
	}
	if account == nil || CanonicalName(account.Name) != username {
		return nil, nil
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
