package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

type AuthenticatedUser struct {
	Username string
	IsAdmin  bool
}

type CredentialAuthenticator interface {
	Authenticate(ctx context.Context, username, password string) (*AuthenticatedUser, error)
}

type SQLDirectoryAuthenticator struct {
	db      *sql.DB
	timeout time.Duration
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

var passwordVerifier = VerifyPassword

var dummyPasswordHash = func() string {
	hash, err := HashSSHA512("dummy-password")
	if err != nil {
		panic(err)
	}

	return hash
}()

func NewSQLDirectoryAuthenticator(database *sql.DB) *SQLDirectoryAuthenticator {
	return &SQLDirectoryAuthenticator{
		db:      database,
		timeout: 5 * time.Second,
	}
}

func (a *SQLDirectoryAuthenticator) Authenticate(ctx context.Context, username, password string) (*AuthenticatedUser, error) {
	if a == nil || a.db == nil {
		return nil, errors.New("database not configured")
	}

	queryCtx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	var name string
	var secret string
	var active bool
	var isAdmin bool
	err := a.db.QueryRowContext(queryCtx, `SELECT name, secret, active, is_admin FROM directory.accounts WHERE name = $1`, username).
		Scan(&name, &secret, &active, &isAdmin)
	if errors.Is(err, sql.ErrNoRows) {
		passwordVerifier(password, dummyPasswordHash)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if !active {
		passwordVerifier(password, dummyPasswordHash)
		return nil, nil
	}

	if !passwordVerifier(password, secret) {
		return nil, nil
	}

	return &AuthenticatedUser{Username: name, IsAdmin: isAdmin}, nil
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
