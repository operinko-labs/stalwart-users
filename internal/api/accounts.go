package api

import (
	"context"
	"encoding/json"
	"errors"
	"log"
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
	AddressInUse(address string) (bool, error)
}

type stalwartClient interface {
	CreateAccount(ctx context.Context, name, password, description string, diskQuota int64) error
	DeleteAccount(ctx context.Context, name string) error
}

func AccountsHandler(pool *db.Pool) http.HandlerFunc {
	if pool == nil {
		return databaseNotConfiguredHandler()
	}
	return newAccountsHandler(pool)
}

func AccountHandler(pool *db.Pool, jmap stalwartClient) http.HandlerFunc {
	if pool == nil {
		return databaseNotConfiguredHandler()
	}
	return newAccountHandler(pool, jmap)
}

func CreateAccountHandler(pool *db.Pool, jmap stalwartClient) http.HandlerFunc {
	if pool == nil {
		return databaseNotConfiguredHandler()
	}
	return newCreateAccountHandler(pool, jmap)
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

func newAccountHandler(store accountsStore, jmap stalwartClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetAccount(w, r, store)
		case http.MethodPatch:
			handlePatchAccount(w, r, store)
		case http.MethodDelete:
			handleDeleteAccount(w, r, store, jmap)
		default:
			writeJSONHeader(w)
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func newCreateAccountHandler(store accountsStore, jmap stalwartClient) http.HandlerFunc {
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

		secret, err := auth.HashPassword(req.Password)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		accountType := req.Type
		if accountType == "" {
			accountType = "individual"
		}

		if jmap != nil {
			if err := jmap.CreateAccount(r.Context(), req.Name, req.Password, req.Description, int64(req.Quota)); err != nil {
				log.Printf("Failed to create Stalwart account for %s: %v", req.Name, err)
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}

		if err := store.CreateAccount(req.Name, secret, req.Description, accountType, req.Quota); err != nil {
			if jmap != nil {
				if rollbackErr := jmap.DeleteAccount(r.Context(), req.Name); rollbackErr != nil {
					log.Printf("Failed to roll back Stalwart account for %s after DB create failure: %v", req.Name, rollbackErr)
				}
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		if strings.Contains(req.Name, "@") {
			if err := store.InsertEmail(req.Name, req.Name, "primary"); err != nil {
				log.Printf("Failed to insert primary email for %s: %v", req.Name, err)
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

	if req.Quota != nil && !auth.IsAdminFromContext(r.Context()) {
		writeError(w, http.StatusForbidden, "only full admins can change quota")
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

func handleDeleteAccount(w http.ResponseWriter, r *http.Request, store accountsStore, jmap stalwartClient) {
	writeJSONHeader(w)
	name := r.PathValue("name")

	if err := store.DeleteAccount(name); err != nil {
		if errors.Is(err, errAccountNotFound) {
			writeError(w, http.StatusNotFound, "account not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if jmap != nil {
		if err := jmap.DeleteAccount(r.Context(), name); err != nil {
			log.Printf("Failed to delete Stalwart account for %s: %v", name, err)
		}
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
