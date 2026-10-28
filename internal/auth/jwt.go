package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	usernameKey  contextKey = "username"
	isAdminKey   contextKey = "isAdmin"
	sessionIDKey contextKey = "sessionID"
)

var ErrMissingJWTSecret = errors.New("JWT_SECRET is required")

type Session struct {
	Username string `json:"username"`
	IsAdmin  bool   `json:"isAdmin"`
	// ID keys the session's OAuth tokens in the TokenStore; it stays
	// server-side.
	ID string `json:"-"`
}

// SessionClaims carries the session id as the JWT ID (jti).
type SessionClaims struct {
	IsAdmin bool `json:"isAdmin"`
	jwt.RegisteredClaims
}

type TokenManager struct {
	secret     []byte
	cookieName string
	now        func() time.Time
	secure     bool

	// stateKey signs the su_oidc cookie; it is derived from secret so the raw
	// JWT secret isn't reused for a second purpose.
	stateKey []byte
	// appRoot is PATH_PREFIX, authPath where the auth routes are mounted.
	appRoot, authPath string
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
		stateKey:   deriveKey([]byte(secret), stateKeyLabel),
		authPath:   "/api/auth",
	}, nil
}

func deriveKey(secret []byte, label string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(label))
	return mac.Sum(nil)
}

// SetPaths tells the manager where the app is mounted: appRoot is PATH_PREFIX
// ("" at the host root) and apiBase the API mount below it ("/api"). Sign-in
// redirects and the su_oidc cookie path are built from these, never from the
// request.
func (m *TokenManager) SetPaths(appRoot, apiBase string) {
	m.appRoot = appRoot
	m.authPath = appRoot + apiBase + "/auth"
}

// GenerateToken signs a session for username with a fresh random session id
// and returns both.
func (m *TokenManager) GenerateToken(username string, isAdmin bool) (token, sessionID string, err error) {
	sessionID, err = randomToken()
	if err != nil {
		return "", "", err
	}

	now := m.now()
	claims := SessionClaims{
		IsAdmin: isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        sessionID,
			Subject:   username,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenTTL)),
		},
	}

	token, err = jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
	if err != nil {
		return "", "", err
	}
	return token, sessionID, nil
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
		ID:       claims.ID,
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

		ctx := WithUser(r.Context(), session.Username, session.IsAdmin)
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, sessionIDKey, session.ID)))
	})
}

func UsernameFromContext(ctx context.Context) string {
	username, ok := ctx.Value(usernameKey).(string)
	if !ok {
		return ""
	}
	return username
}

// SessionIDFromContext returns the session id that keys the user's OAuth
// tokens in the TokenStore, or "" when there is none.
func SessionIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(sessionIDKey).(string)
	return id
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

// randomToken returns 32 random bytes, base64url without padding.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
