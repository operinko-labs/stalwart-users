package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/lib/pq"
	"github.com/operinko-labs/stalwart-users/internal/db"
	"github.com/operinko-labs/stalwart-users/internal/model"
)

type aliasesStore interface {
	ListEmails(name string) ([]model.Email, error)
	InsertEmail(name, address, emailType string) error
	GetEmailType(name, address string) (string, error)
	DeleteEmail(name, address string) error
	GetAccount(name string) (*model.Account, error)
}

func ListEmailsHandler(pool *db.Pool) http.HandlerFunc {
	if pool == nil {
		return databaseNotConfiguredHandler()
	}
	return newListEmailsHandler(pool)
}

func CreateEmailHandler(pool *db.Pool) http.HandlerFunc {
	if pool == nil {
		return databaseNotConfiguredHandler()
	}
	return newCreateEmailHandler(pool)
}

func DeleteEmailHandler(pool *db.Pool) http.HandlerFunc {
	if pool == nil {
		return databaseNotConfiguredHandler()
	}
	return newDeleteEmailHandler(pool)
}

func newListEmailsHandler(store aliasesStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSONHeader(w)

		if !accountExists(w, r, store) {
			return
		}

		emails, err := store.ListEmails(r.PathValue("name"))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(emails)
	}
}

func newCreateEmailHandler(store aliasesStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSONHeader(w)

		if !accountExists(w, r, store) {
			return
		}

		var req model.CreateEmailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		if req.Address == "" {
			writeError(w, http.StatusBadRequest, "address is required")
			return
		}

		emailType := req.Type
		if emailType == "" {
			emailType = "alias"
		}

		if err := store.InsertEmail(r.PathValue("name"), req.Address, emailType); err != nil {
			var pqErr *pq.Error
			if errors.As(err, &pqErr) && pqErr.Code == "23505" {
				writeError(w, http.StatusConflict, "email already exists")
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "created"})
	}
}

func newDeleteEmailHandler(store aliasesStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSONHeader(w)

		if !accountExists(w, r, store) {
			return
		}

		emailType, err := store.GetEmailType(r.PathValue("name"), r.PathValue("address"))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if emailType == "primary" {
			writeError(w, http.StatusBadRequest, "cannot delete primary email")
			return
		}

		if err := store.DeleteEmail(r.PathValue("name"), r.PathValue("address")); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func accountExists(w http.ResponseWriter, r *http.Request, store aliasesStore) bool {
		account, err := store.GetAccount(r.PathValue("name"))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return false
		}
		if account == nil {
			writeError(w, http.StatusNotFound, "account not found")
			return false
		}

		return true
	}
