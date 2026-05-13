package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

const loginTestJWTSecret = testJWTSecret

type stubAuthenticator struct {
	user *AuthenticatedUser
	err  error
	seen struct {
		username string
		password string
	}
}

func (s *stubAuthenticator) Authenticate(_ context.Context, username, password string) (*AuthenticatedUser, error) {
	s.seen.username = username
	s.seen.password = password
	return s.user, s.err
}

type stubAdminChecker struct {
	isAdmin bool
	seen    string
}

func (s *stubAdminChecker) IsAdmin(_ context.Context, username string) bool {
	s.seen = username
	return s.isAdmin
}

func TestSQLDirectoryAuthenticatorAuthenticatesActiveUser(t *testing.T) {
	t.Parallel()

	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer func() { _ = database.Close() }()

	hash, err := HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	rows := sqlmock.NewRows([]string{"name", "secret", "active"}).AddRow("alice@example.com", hash, true)
	mock.ExpectQuery(`SELECT name, secret, active FROM directory.accounts WHERE name = \$1`).WithArgs("alice@example.com").WillReturnRows(rows)

	authenticator := NewSQLDirectoryAuthenticator(database)
	user, err := authenticator.Authenticate(context.Background(), "alice@example.com", "secret")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if user == nil || user.Username != "alice@example.com" {
		t.Fatalf("user = %#v, want alice@example.com", user)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("ExpectationsWereMet() error = %v", err)
	}
}

func TestSQLDirectoryAuthenticatorRejectsInactiveOrInvalidUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		rows     *sqlmock.Rows
		password string
	}{
		{name: "inactive", rows: sqlmock.NewRows([]string{"name", "secret", "active"}).AddRow("alice@example.com", mustHash(t, "secret"), false), password: "secret"},
		{name: "wrong password", rows: sqlmock.NewRows([]string{"name", "secret", "active"}).AddRow("alice@example.com", mustHash(t, "secret"), true), password: "wrong"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			database, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New() error = %v", err)
			}
			defer func() { _ = database.Close() }()

			mock.ExpectQuery(`SELECT name, secret, active FROM directory.accounts WHERE name = \$1`).WithArgs("alice@example.com").WillReturnRows(tt.rows)

			authenticator := NewSQLDirectoryAuthenticator(database)
			user, err := authenticator.Authenticate(context.Background(), "alice@example.com", tt.password)
			if err != nil {
				t.Fatalf("Authenticate() error = %v", err)
			}
			if user != nil {
				t.Fatalf("user = %#v, want nil", user)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("ExpectationsWereMet() error = %v", err)
			}
		})
	}
}

func TestSQLDirectoryAuthenticatorReturnsNilForMissingUser(t *testing.T) {
	t.Parallel()

	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer func() { _ = database.Close() }()

	mock.ExpectQuery(`SELECT name, secret, active FROM directory.accounts WHERE name = \$1`).WithArgs("missing@example.com").WillReturnError(sql.ErrNoRows)

	authenticator := NewSQLDirectoryAuthenticator(database)
	user, err := authenticator.Authenticate(context.Background(), "missing@example.com", "secret")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if user != nil {
		t.Fatalf("user = %#v, want nil", user)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("ExpectationsWereMet() error = %v", err)
	}
}

func TestSQLDirectoryAuthenticatorUsesDummyVerificationForMissingOrInactiveUser(t *testing.T) {
	// Not parallel: this test replaces the global passwordVerifier
	originalVerifier := passwordVerifier
	defer func() { passwordVerifier = originalVerifier }()

	var calls []string
	passwordVerifier = func(password, encoded string) bool {
		calls = append(calls, encoded)
		return false
	}

	missingDB, missingMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer func() { _ = missingDB.Close() }()
	missingMock.ExpectQuery(`SELECT name, secret, active FROM directory.accounts WHERE name = \$1`).WithArgs("missing@example.com").WillReturnError(sql.ErrNoRows)

	missingAuthenticator := NewSQLDirectoryAuthenticator(missingDB)
	missingUser, err := missingAuthenticator.Authenticate(context.Background(), "missing@example.com", "secret")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if missingUser != nil {
		t.Fatalf("user = %#v, want nil", missingUser)
	}

	inactiveDB, inactiveMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer func() { _ = inactiveDB.Close() }()
	inactiveRows := sqlmock.NewRows([]string{"name", "secret", "active"}).AddRow("alice@example.com", mustHash(t, "stored-secret"), false)
	inactiveMock.ExpectQuery(`SELECT name, secret, active FROM directory.accounts WHERE name = \$1`).WithArgs("alice@example.com").WillReturnRows(inactiveRows)

	inactiveAuthenticator := NewSQLDirectoryAuthenticator(inactiveDB)
	inactiveUser, err := inactiveAuthenticator.Authenticate(context.Background(), "alice@example.com", "secret")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if inactiveUser != nil {
		t.Fatalf("user = %#v, want nil", inactiveUser)
	}

	if err := missingMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("missing ExpectationsWereMet() error = %v", err)
	}
	if err := inactiveMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("inactive ExpectationsWereMet() error = %v", err)
	}

	if len(calls) != 2 {
		t.Fatalf("passwordVerifier call count = %d, want 2", len(calls))
	}
	if calls[0] != dummyPasswordHash || calls[1] != dummyPasswordHash {
		t.Fatalf("passwordVerifier hashes = %#v, want dummy hash for both missing and inactive users", calls)
	}
}

func TestLoginHandlerCreatesSessionCookieAndReturnsSession(t *testing.T) {
	t.Parallel()

	tokens, err := NewTokenManager(loginTestJWTSecret)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}

	authenticator := &stubAuthenticator{user: &AuthenticatedUser{Username: "alice@example.com"}}
	adminChecker := &stubAdminChecker{isAdmin: true}
	handler := LoginHandler(authenticator, tokens, adminChecker)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"email":"alice@example.com","password":"secret"}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if authenticator.seen.username != "alice@example.com" || authenticator.seen.password != "secret" {
		t.Fatalf("authenticator saw (%q, %q), want alice@example.com/secret", authenticator.seen.username, authenticator.seen.password)
	}
	if adminChecker.seen != "alice@example.com" {
		t.Fatalf("adminChecker saw %q, want alice@example.com", adminChecker.seen)
	}

	var body Session
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if body.Username != "alice@example.com" || !body.IsAdmin {
		t.Fatalf("body = %#v, want alice@example.com admin", body)
	}

	result := rr.Result()
	defer result.Body.Close()
	if len(result.Cookies()) != 1 || result.Cookies()[0].Name != tokenCookieName {
		t.Fatalf("cookies = %#v, want token cookie", result.Cookies())
	}
}

func TestLoginHandlerRejectsInvalidCredentials(t *testing.T) {
	t.Parallel()

	tokens, err := NewTokenManager(loginTestJWTSecret)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}

	handler := LoginHandler(&stubAuthenticator{}, tokens, &stubAdminChecker{})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"email":"alice@example.com","password":"wrong"}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestLoginHandlerHandlesAuthenticatorFailure(t *testing.T) {
	t.Parallel()

	tokens, err := NewTokenManager(loginTestJWTSecret)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}

	handler := LoginHandler(&stubAuthenticator{err: errors.New("boom")}, tokens, &stubAdminChecker{})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"email":"alice@example.com","password":"secret"}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestLoginHandlerValidatesRequestBody(t *testing.T) {
	t.Parallel()

	tokens, err := NewTokenManager(loginTestJWTSecret)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}

	handler := LoginHandler(&stubAuthenticator{}, tokens, &stubAdminChecker{})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"email":""}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func mustHash(t *testing.T, password string) string {
	t.Helper()

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	return hash
}
