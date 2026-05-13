package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	tokenCookieName = "token"
	tokenTTL        = 24 * time.Hour
	minJWTSecretLen = 32
)

type contextKey string

const (
	usernameKey contextKey = "username"
	isAdminKey  contextKey = "isAdmin"
)

var ErrMissingJWTSecret = errors.New("JWT_SECRET is required")

type Session struct {
	Username string `json:"username"`
	IsAdmin  bool   `json:"isAdmin"`
}

type SessionClaims struct {
	IsAdmin bool `json:"isAdmin"`
	jwt.RegisteredClaims
}

type TokenManager struct {
	secret     []byte
	cookieName string
	now        func() time.Time
	secure     bool
}

func NewTokenManager(secret string) (*TokenManager, error) {
	if secret == "" {
		return nil, ErrMissingJWTSecret
	}
	if len(secret) < minJWTSecretLen {
		return nil, fmt.Errorf("JWT secret must be at least 32 bytes")
	}

	return &TokenManager{
		secret:     []byte(secret),
		cookieName: tokenCookieName,
		now:        time.Now,
		secure:     true,
	}, nil
}

func (m *TokenManager) GenerateToken(username string, isAdmin bool) (string, error) {
	now := m.now()
	claims := SessionClaims{
		IsAdmin: isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenTTL)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secret)
}

func (m *TokenManager) ParseToken(tokenString string) (*Session, error) {
	claims := &SessionClaims{}
	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(token *jwt.Token) (any, error) {
			if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
				return nil, errors.New("unexpected signing method")
			}
			return m.secret, nil
		},
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(m.now),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
	)
	if err != nil || !token.Valid || claims.Subject == "" {
		return nil, errors.New("invalid session")
	}

	return &Session{
		Username: claims.Subject,
		IsAdmin:  claims.IsAdmin,
	}, nil
}

func (m *TokenManager) ReadSession(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(m.cookieName)
	if err != nil || cookie.Value == "" {
		return nil, errors.New("invalid session")
	}

	return m.ParseToken(cookie.Value)
}

func (m *TokenManager) SetCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(tokenTTL.Seconds()),
		Expires:  m.now().Add(tokenTTL),
	})
}

func (m *TokenManager) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func (m *TokenManager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSONHeader(w)

		session, err := m.ReadSession(r)
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, "invalid session")
			return
		}

		ctx := context.WithValue(r.Context(), usernameKey, session.Username)
		ctx = context.WithValue(ctx, isAdminKey, session.IsAdmin)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func UsernameFromContext(ctx context.Context) string {
	username, ok := ctx.Value(usernameKey).(string)
	if !ok {
		return ""
	}
	return username
}

func IsAdminFromContext(ctx context.Context) bool {
	isAdmin, ok := ctx.Value(isAdminKey).(bool)
	if !ok {
		return false
	}
	return isAdmin
}

func writeJSONHeader(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
}

func writeJSONError(w http.ResponseWriter, statusCode int, message string) {
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
