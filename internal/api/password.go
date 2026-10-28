package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/operinko-labs/stalwart-users/internal/auth"
	"github.com/operinko-labs/stalwart-users/internal/directory"
	"github.com/operinko-labs/stalwart-users/internal/model"
)

type passwordsStore interface {
	Authenticate(ctx context.Context, name, password string) (bool, error)
	SetPassword(name, password string) error
}

func ChangePasswordHandler(store *directory.Store) http.HandlerFunc {
	return newChangePasswordHandler(store)
}

func newChangePasswordHandler(store passwordsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

			ok, err := store.Authenticate(r.Context(), name, req.CurrentPassword)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if !ok {
				writeError(w, http.StatusUnauthorized, "invalid current password")
				return
			}
		}

		if err := store.SetPassword(name, req.NewPassword); err != nil {
			writeStoreError(w, err)
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "password updated"})
	}
}
