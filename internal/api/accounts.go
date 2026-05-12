package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/operinko-labs/stalwart-users/internal/auth"
	"github.com/operinko-labs/stalwart-users/internal/db"
	"github.com/operinko-labs/stalwart-users/internal/model"
)

var errAccountNotFound = db.ErrAccountNotFound

type accountsStore interface {
	ListAccounts() ([]model.Account, error)
	GetAccount(name string) (*model.Account, error)
	CreateAccount(name, secret, description, accountType string, quota int) error
	InsertEmail(name, address, emailType string) error
	UpdateAccount(name string, description *string, quota *int, active *bool) error
	DeleteAccount(name string) error
}

func AccountsHandler(pool *db.Pool) http.HandlerFunc {
	if pool == nil {
		return databaseNotConfiguredHandler()
	}
	return newAccountsHandler(pool)
}

func AccountHandler(pool *db.Pool) http.HandlerFunc {
	if pool == nil {
		return databaseNotConfiguredHandler()
	}
	return newAccountHandler(pool)
}

func CreateAccountHandler(pool *db.Pool) http.HandlerFunc {
	if pool == nil {
		return databaseNotConfiguredHandler()
	}
	return newCreateAccountHandler(pool)
}

func newAccountsHandler(store accountsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSONHeader(w)

		accounts, err := store.ListAccounts()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
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

		secret, err := auth.HashPassword(req.Password)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		accountType := req.Type
		if accountType == "" {
			accountType = "individual"
		}

		if err := store.CreateAccount(req.Name, secret, req.Description, accountType, req.Quota); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		if strings.Contains(req.Name, "@") {
			if err := store.InsertEmail(req.Name, req.Name, "primary"); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
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

	if err := store.UpdateAccount(r.PathValue("name"), req.Description, req.Quota, req.Active); err != nil {
		if errors.Is(err, errAccountNotFound) {
			writeError(w, http.StatusNotFound, "account not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}

func handleDeleteAccount(w http.ResponseWriter, r *http.Request, store accountsStore) {
	writeJSONHeader(w)

	if err := store.DeleteAccount(r.PathValue("name")); err != nil {
		if errors.Is(err, errAccountNotFound) {
			writeError(w, http.StatusNotFound, "account not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
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

func databaseNotConfiguredHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSONHeader(w)
		writeError(w, http.StatusServiceUnavailable, "database not configured")
	}
}
