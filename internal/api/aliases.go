package api

import (
	"encoding/json"
	"net/http"

	"github.com/operinko-labs/stalwart-users/internal/auth"
	"github.com/operinko-labs/stalwart-users/internal/directory"
	"github.com/operinko-labs/stalwart-users/internal/model"
)

type aliasesStore interface {
	ListEmails(name string) ([]model.Email, error)
	InsertEmail(name, address, emailType string) error
	GetEmailType(name, address string) (string, error)
	DeleteEmail(name, address string) error
	GetAccount(name string) (*model.Account, error)
	AddressInUse(address string) (bool, error)
}

func ListEmailsHandler(store *directory.Store) http.HandlerFunc {
	return newListEmailsHandler(store)
}

func CreateEmailHandler(store *directory.Store) http.HandlerFunc {
	return newCreateEmailHandler(store)
}

func DeleteEmailHandler(store *directory.Store) http.HandlerFunc {
	return newDeleteEmailHandler(store)
}

func newListEmailsHandler(store aliasesStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSONHeader(w)

		if !accountExists(w, r, store) {
			return
		}

		emails, err := store.ListEmails(r.PathValue("name"))
		if err != nil {
			writeStoreError(w, err)
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

		if !auth.IsAdminFromContext(r.Context()) {
			if !auth.ManagesDomain(r.Context(), auth.DomainOf(req.Address)) {
				writeError(w, http.StatusForbidden, "you can only add addresses on domains you manage")
				return
			}
			if emailType != "alias" && emailType != "list" {
				writeError(w, http.StatusForbidden, "you can only add alias or list addresses")
				return
			}
			// A shared address delivers to every account holding it, so only
			// full admins may reuse one.
			inUse, err := store.AddressInUse(req.Address)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if inUse {
				writeError(w, http.StatusConflict, "address already in use")
				return
			}
		}

		if err := store.InsertEmail(r.PathValue("name"), req.Address, emailType); err != nil {
			writeStoreError(w, err)
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
			writeStoreError(w, err)
			return
		}
		if emailType == "primary" {
			writeError(w, http.StatusBadRequest, "cannot delete primary email")
			return
		}

		if err := store.DeleteEmail(r.PathValue("name"), r.PathValue("address")); err != nil {
			writeStoreError(w, err)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func accountExists(w http.ResponseWriter, r *http.Request, store aliasesStore) bool {
	account, err := store.GetAccount(r.PathValue("name"))
	if err != nil {
		writeStoreError(w, err)
		return false
	}
	if account == nil {
		writeError(w, http.StatusNotFound, "account not found")
		return false
	}

	return true
}
