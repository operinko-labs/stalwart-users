package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/operinko-labs/stalwart-users/internal/auth"
	"github.com/operinko-labs/stalwart-users/internal/db"
	"github.com/operinko-labs/stalwart-users/internal/directory"
	"github.com/operinko-labs/stalwart-users/internal/model"
	"github.com/operinko-labs/stalwart-users/internal/stalwart"
)

var errAccountNotFound = db.ErrAccountNotFound

type accountsStore interface {
	ListAccounts() ([]model.Account, error)
	GetAccount(name string) (*model.Account, error)
	CreateAccount(name, password, description, accountType string, quota int) error
	UpdateAccount(name string, description *string, quota *int, active *bool) error
	DeleteAccount(name string) error
	AddressInUse(address string) (bool, error)
}

func AccountsHandler(store *directory.Store) http.HandlerFunc {
	return newAccountsHandler(store)
}

func AccountHandler(store *directory.Store) http.HandlerFunc {
	return newAccountHandler(store)
}

func CreateAccountHandler(store *directory.Store) http.HandlerFunc {
	return newCreateAccountHandler(store)
}

func newAccountsHandler(store accountsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSONHeader(w)

		accounts, err := store.ListAccounts()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		if !auth.IsAdminFromContext(r.Context()) {
			managed := make([]model.Account, 0, len(accounts))
			for _, account := range accounts {
				if !account.IsAdmin && auth.ManagesDomain(r.Context(), auth.DomainOf(account.Name)) {
					managed = append(managed, account)
				}
			}
			accounts = managed
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(accounts)
	}
}

func newAccountHandler(store accountsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetAccount(w, r, store)
		case http.MethodPatch:
			handlePatchAccount(w, r, store)
		case http.MethodDelete:
			handleDeleteAccount(w, r, store)
		default:
			writeJSONHeader(w)
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func newCreateAccountHandler(store accountsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSONHeader(w)

		var req model.CreateAccountRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		if req.Name == "" || req.Password == "" {
			writeError(w, http.StatusBadRequest, "name and password are required")
			return
		}

		if !auth.IsAdminFromContext(r.Context()) {
			switch {
			case !auth.ManagesDomain(r.Context(), auth.DomainOf(req.Name)):
				writeError(w, http.StatusForbidden, "you can only create accounts on domains you manage")
				return
			case req.Quota != 0:
				writeError(w, http.StatusForbidden, "only full admins can set quota")
				return
			case req.Type != "" && req.Type != "individual" && req.Type != "group":
				writeError(w, http.StatusForbidden, "you can only create individual or group accounts")
				return
			}

			// The new account's name becomes its primary address, which must not
			// already deliver to someone else.
			inUse, err := store.AddressInUse(req.Name)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if inUse {
				writeError(w, http.StatusConflict, "address already in use")
				return
			}
		}

		accountType := req.Type
		if accountType == "" {
			accountType = "individual"
		}

		if err := store.CreateAccount(req.Name, req.Password, req.Description, accountType, req.Quota); err != nil {
			writeStoreError(w, err)
			return
		}

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "created"})
	}
}

func handleGetAccount(w http.ResponseWriter, r *http.Request, store accountsStore) {
	writeJSONHeader(w)

	account, err := store.GetAccount(r.PathValue("name"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if account == nil {
		writeError(w, http.StatusNotFound, "account not found")
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(account)
}

func handlePatchAccount(w http.ResponseWriter, r *http.Request, store accountsStore) {
	writeJSONHeader(w)

	var req model.UpdateAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Quota != nil && !auth.IsAdminFromContext(r.Context()) {
		writeError(w, http.StatusForbidden, "only full admins can change quota")
		return
	}

	if err := store.UpdateAccount(r.PathValue("name"), req.Description, req.Quota, req.Active); err != nil {
		writeStoreError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}

func handleDeleteAccount(w http.ResponseWriter, r *http.Request, store accountsStore) {
	writeJSONHeader(w)

	if err := store.DeleteAccount(r.PathValue("name")); err != nil {
		writeStoreError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func writeJSONHeader(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
}

func writeError(w http.ResponseWriter, statusCode int, message string) {
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// writeStoreError maps an account store error to its HTTP response.
func writeStoreError(w http.ResponseWriter, err error) {
	var invalid stalwart.ErrInvalid
	switch {
	case errors.Is(err, errAccountNotFound):
		writeError(w, http.StatusNotFound, "account not found")
	case errors.Is(err, errGroupMembershipNotFound):
		writeError(w, http.StatusNotFound, "group membership not found")
	case errors.Is(err, directory.ErrAddressInUse):
		writeError(w, http.StatusConflict, "address already in use")
	case errors.Is(err, directory.ErrUnsupported):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.As(err, &invalid):
		writeError(w, http.StatusBadRequest, invalid.Description)
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}
