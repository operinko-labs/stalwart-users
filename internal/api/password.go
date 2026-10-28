package api

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/operinko-labs/stalwart-users/internal/auth"
	"github.com/operinko-labs/stalwart-users/internal/directory"
	"github.com/operinko-labs/stalwart-users/internal/model"
	"github.com/operinko-labs/stalwart-users/internal/oidc"
	"github.com/operinko-labs/stalwart-users/internal/stalwart"
)

// refreshMargin is how close to expiry a stored access token is refreshed
// before it is used.
const refreshMargin = 30 * time.Second

// passwordsStore sets a password through the admin API.
type passwordsStore interface {
	SetPassword(name, password string) error
}

// sessionTokens holds each session's OAuth tokens.
type sessionTokens interface {
	Get(sessionID string) (oidc.Tokens, bool)
	Put(sessionID string, t oidc.Tokens)
}

type tokenRefresher interface {
	Refresh(ctx context.Context, refreshToken string) (oidc.Tokens, error)
}

type ownPasswordChanger interface {
	ChangeOwnPassword(ctx context.Context, userAccessToken, current, next, otpCode string) error
}

type passwordHandler struct {
	store     passwordsStore
	tokens    sessionTokens
	refresher tokenRefresher
	stalwart  ownPasswordChanger
	now       func() time.Time
}

func ChangePasswordHandler(store *directory.Store, tokens *auth.TokenStore, refresher *oidc.Client, client *stalwart.Client) http.HandlerFunc {
	h := &passwordHandler{store: store, tokens: tokens, refresher: refresher, stalwart: client, now: time.Now}
	return h.ServeHTTP
}

func (h *passwordHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	writeJSONHeader(w)

	name := r.PathValue("name")
	username := auth.UsernameFromContext(r.Context())
	isAdmin := auth.IsAdminFromContext(r.Context())

	isSelf := auth.CanonicalName(username) == auth.CanonicalName(name)
	if !isAdmin && !isSelf && !auth.ManagesDomain(r.Context(), auth.DomainOf(name)) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	var req model.ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "new_password is required")
		return
	}

	if !isAdmin && isSelf {
		if req.CurrentPassword == "" {
			writeError(w, http.StatusBadRequest, "current_password is required")
			return
		}
		h.changeOwn(w, r, req)
		return
	}

	if err := h.store.SetPassword(name, req.NewPassword); err != nil {
		writeStoreError(w, err)
		return
	}

	writePasswordUpdated(w)
}

// changeOwn changes the signed-in user's password as that user, so Stalwart
// checks the current password and 2FA code itself.
func (h *passwordHandler) changeOwn(w http.ResponseWriter, r *http.Request, req model.ChangePasswordRequest) {
	ctx := r.Context()
	sessionID := auth.SessionIDFromContext(ctx)

	tokens, ok := h.tokens.Get(sessionID)
	if sessionID == "" || !ok || tokens.AccessToken == "" {
		writeReauthRequired(w)
		return
	}

	refreshed := false
	if !h.now().Add(refreshMargin).Before(tokens.ExpiresAt) {
		if tokens, ok = h.refresh(ctx, sessionID, tokens); !ok {
			writeReauthRequired(w)
			return
		}
		refreshed = true
	}

	err := h.stalwart.ChangeOwnPassword(ctx, tokens.AccessToken, req.CurrentPassword, req.NewPassword, req.OTPCode)
	if errors.Is(err, stalwart.ErrUnauthorized) && !refreshed {
		if tokens, ok = h.refresh(ctx, sessionID, tokens); !ok {
			writeReauthRequired(w)
			return
		}
		err = h.stalwart.ChangeOwnPassword(ctx, tokens.AccessToken, req.CurrentPassword, req.NewPassword, req.OTPCode)
	}

	var invalid stalwart.ErrInvalid
	switch {
	case err == nil:
		writePasswordUpdated(w)
	case errors.Is(err, stalwart.ErrUnauthorized):
		writeReauthRequired(w)
	case errors.Is(err, stalwart.ErrCurrentPasswordIncorrect):
		writeError(w, http.StatusUnauthorized, "invalid current password")
	case errors.Is(err, stalwart.ErrOTPRequired):
		writeError(w, http.StatusBadRequest, "otp_required")
	case errors.Is(err, stalwart.ErrPasswordChangeNotAllowed):
		log.Printf("password change for %s refused: %v", auth.CanonicalName(r.PathValue("name")), err)
		writeError(w, http.StatusForbidden, "password change not allowed")
	case errors.As(err, &invalid):
		writeError(w, http.StatusBadRequest, invalid.Description)
	default:
		// Client errors carry method names, statuses and Stalwart's answer,
		// never the request's secrets.
		log.Printf("password change for %s failed: %v", auth.CanonicalName(r.PathValue("name")), err)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

// refresh swaps tokens for fresh ones and stores them. It reports false when
// there is no refresh token or the refresh fails, i.e. the user must sign in
// again.
func (h *passwordHandler) refresh(ctx context.Context, sessionID string, tokens oidc.Tokens) (oidc.Tokens, bool) {
	if tokens.RefreshToken == "" {
		return oidc.Tokens{}, false
	}
	fresh, err := h.refresher.Refresh(ctx, tokens.RefreshToken)
	if err != nil {
		// oidc errors carry only the HTTP status and OAuth error code.
		log.Printf("token refresh failed: %v", err)
		return oidc.Tokens{}, false
	}
	h.tokens.Put(sessionID, fresh)
	return fresh, true
}

func writePasswordUpdated(w http.ResponseWriter) {
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "password updated"})
}

func writeReauthRequired(w http.ResponseWriter) {
	writeError(w, http.StatusUnauthorized, "reauth_required")
}
