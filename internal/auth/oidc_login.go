package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/operinko-labs/stalwart-users/internal/model"
	"github.com/operinko-labs/stalwart-users/internal/oidc"
)

const (
	stateCookieName = "su_oidc"
	stateTTL        = 10 * time.Minute
	stateKeyLabel   = "stalwart-users oidc state"
	callbackTimeout = 15 * time.Second
)

type oidcStarter interface {
	AuthCodeURL(ctx context.Context, state, codeChallenge string) (string, error)
}

type oidcFinisher interface {
	Exchange(ctx context.Context, code, codeVerifier string) (oidc.Tokens, error)
	UserInfo(ctx context.Context, accessToken string) (oidc.UserInfo, error)
}

// accountResolver maps a sign-in address to a User account.
type accountResolver interface {
	// GetAccount returns the User whose primary address is name (exact
	// canonical match), or nil when there is none.
	GetAccount(name string) (*model.Account, error)
	IsAdmin(name string) (bool, error)
}

// LoginStartHandler sends the browser to Stalwart's login page. The state and
// PKCE verifier travel in the signed su_oidc cookie; nothing from the request
// is used.
func LoginStartHandler(oc oidcStarter, tokens *TokenManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, err := randomToken()
		if err != nil {
			log.Printf("oidc login: %v", err)
			tokens.redirectToApp(w, r, "/login?error=signin")
			return
		}
		verifier, challenge, err := oidc.NewPKCE()
		if err != nil {
			log.Printf("oidc login: %v", err)
			tokens.redirectToApp(w, r, "/login?error=signin")
			return
		}
		target, err := oc.AuthCodeURL(r.Context(), state, challenge)
		if err != nil {
			log.Printf("oidc login: %v", err)
			tokens.redirectToApp(w, r, "/login?error=signin")
			return
		}

		tokens.setStateCookie(w, state, verifier)
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, target, http.StatusFound)
	}
}

// CallbackHandler finishes the sign-in Stalwart redirected back with. The
// identity is the userinfo email, which must be a User's primary address.
func CallbackHandler(oc oidcFinisher, accounts accountResolver, tokens *TokenManager, store *TokenStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The state cookie is good for one callback, whatever its outcome.
		tokens.clearStateCookie(w)

		q := r.URL.Query()
		if q.Get("error") != "" {
			tokens.redirectToApp(w, r, "/login?error=denied")
			return
		}

		state, verifier, ok := tokens.readStateCookie(r)
		if !ok || !hmac.Equal([]byte(q.Get("state")), []byte(state)) {
			tokens.redirectToApp(w, r, "/login?error=state")
			return
		}

		code := q.Get("code")
		if code == "" {
			tokens.redirectToApp(w, r, "/login?error=signin")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), callbackTimeout)
		defer cancel()

		oauthTokens, err := oc.Exchange(ctx, code, verifier)
		if err != nil {
			log.Printf("oidc callback: %v", err)
			tokens.redirectToApp(w, r, "/login?error=signin")
			return
		}
		info, err := oc.UserInfo(ctx, oauthTokens.AccessToken)
		if err != nil {
			log.Printf("oidc callback: %v", err)
			tokens.redirectToApp(w, r, "/login?error=signin")
			return
		}

		email := CanonicalName(info.Email)
		if email == "" {
			tokens.redirectToApp(w, r, "/login?error=no_mailbox")
			return
		}
		account, err := accounts.GetAccount(email)
		if err != nil {
			log.Printf("oidc callback: account lookup: %v", err)
			tokens.redirectToApp(w, r, "/login?error=signin")
			return
		}
		if account == nil || CanonicalName(account.Name) != email {
			tokens.redirectToApp(w, r, "/login?error=no_mailbox")
			return
		}
		isAdmin, err := accounts.IsAdmin(email)
		if err != nil {
			log.Printf("oidc callback: admin lookup: %v", err)
			tokens.redirectToApp(w, r, "/login?error=signin")
			return
		}

		session, sessionID, err := tokens.GenerateToken(email, isAdmin)
		if err != nil {
			log.Printf("oidc callback: %v", err)
			tokens.redirectToApp(w, r, "/login?error=signin")
			return
		}
		store.Put(sessionID, oauthTokens)
		tokens.SetCookie(w, session)
		tokens.redirectToApp(w, r, "/")
	}
}

// redirectToApp sends the browser to path below the app root.
func (m *TokenManager) redirectToApp(w http.ResponseWriter, r *http.Request, path string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, m.appRoot+path, http.StatusFound)
}

// The su_oidc value is state|verifier|expiry|mac: state and verifier are
// base64url and the expiry a unix time, so none of them contains "|"; mac is
// the base64url HMAC-SHA256 of the first three fields under stateKey.
func (m *TokenManager) setStateCookie(w http.ResponseWriter, state, verifier string) {
	expires := m.now().Add(stateTTL)
	payload := state + "|" + verifier + "|" + strconv.FormatInt(expires.Unix(), 10)
	http.SetCookie(w, m.stateCookie(payload+"|"+m.stateMAC(payload), int(stateTTL.Seconds()), expires))
}

func (m *TokenManager) clearStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, m.stateCookie("", -1, time.Unix(0, 0)))
}

func (m *TokenManager) stateCookie(value string, maxAge int, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     stateCookieName,
		Value:    value,
		Path:     m.authPath,
		HttpOnly: true,
		Secure:   m.secure,
		// Lax, not Strict: the callback is a top-level redirect from Stalwart.
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
		Expires:  expires,
	}
}

// readStateCookie returns the state and verifier from a genuine, unexpired
// su_oidc cookie.
func (m *TokenManager) readStateCookie(r *http.Request) (state, verifier string, ok bool) {
	c, err := r.Cookie(stateCookieName)
	if err != nil {
		return "", "", false
	}
	parts := strings.Split(c.Value, "|")
	if len(parts) != 4 {
		return "", "", false
	}
	payload := strings.Join(parts[:3], "|")
	if !hmac.Equal([]byte(parts[3]), []byte(m.stateMAC(payload))) {
		return "", "", false
	}
	expiry, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || !m.now().Before(time.Unix(expiry, 0)) {
		return "", "", false
	}
	if parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func (m *TokenManager) stateMAC(payload string) string {
	mac := hmac.New(sha256.New, m.stateKey)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
