package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/operinko-labs/stalwart-users/internal/auth"
	"github.com/operinko-labs/stalwart-users/internal/db"
	"github.com/operinko-labs/stalwart-users/internal/model"
)

type passwordsStore interface {
	GetAccountSecret(name string) (string, error)
	UpdateAccountPassword(name, secret string) error
}

func ChangePasswordHandler(pool *db.Pool) http.HandlerFunc {
	if pool == nil {
		return databaseNotConfiguredHandler()
	}

	return newChangePasswordHandler(pool)
}

func newChangePasswordHandler(store passwordsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSONHeader(w)

		name := r.PathValue("name")
		username := auth.UsernameFromContext(r.Context())
		isAdmin := auth.IsAdminFromContext(r.Context())

		if !isAdmin && username != name {
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

		if !isAdmin {
			if req.CurrentPassword == "" {
				writeError(w, http.StatusBadRequest, "current_password is required")
				return
			}

			storedSecret, err := store.GetAccountSecret(name)
			if err != nil {
				if errors.Is(err, errAccountNotFound) {
					writeError(w, http.StatusNotFound, "account not found")
					return
				}
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}

			if !auth.VerifyPassword(req.CurrentPassword, storedSecret) {
				writeError(w, http.StatusUnauthorized, "invalid current password")
				return
			}
		}

		secret, err := auth.HashSSHA512(req.NewPassword)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		if err := store.UpdateAccountPassword(name, secret); err != nil {
			if errors.Is(err, errAccountNotFound) {
				writeError(w, http.StatusNotFound, "account not found")
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "password updated"})
	}
}
