package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/operinko-labs/stalwart-users/internal/db"
	"github.com/operinko-labs/stalwart-users/internal/model"
)

var domainPattern = regexp.MustCompile(`^[a-z0-9-]+(\.[a-z0-9-]+)+$`)

type adminDomainsStore interface {
	GetAccount(name string) (*model.Account, error)
	ListAdminDomains(name string) ([]string, error)
	SetAdminDomains(name string, domains []string) error
}

type adminDomainsBody struct {
	Domains []string `json:"domains"`
}

// AdminDomainsHandler reads and replaces the domains an account administers.
// Only full admins reach it.
func AdminDomainsHandler(pool *db.Pool) http.HandlerFunc {
	if pool == nil {
		return databaseNotConfiguredHandler()
	}
	return newAdminDomainsHandler(pool)
}

func newAdminDomainsHandler(store adminDomainsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSONHeader(w)
		name := r.PathValue("name")

		account, err := store.GetAccount(name)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if account == nil {
			writeError(w, http.StatusNotFound, "account not found")
			return
		}

		var domains []string
		switch r.Method {
		case http.MethodGet:
			if domains, err = store.ListAdminDomains(name); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
		case http.MethodPut:
			var req adminDomainsBody
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeError(w, http.StatusBadRequest, "invalid request body")
				return
			}
			if domains, err = normalizeDomains(req.Domains); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			if err := store.SetAdminDomains(name, domains); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(adminDomainsBody{Domains: domains})
	}
}

// normalizeDomains lowercases, trims and deduplicates domains, and rejects
// anything that is not a plain domain name.
func normalizeDomains(input []string) ([]string, error) {
	domains := make([]string, 0, len(input))
	for _, raw := range input {
		domain := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(raw)), "@")
		if !domainPattern.MatchString(domain) {
			return nil, fmt.Errorf("invalid domain %q", raw)
		}
		domains = append(domains, domain)
	}

	slices.Sort(domains)
	return slices.Compact(domains), nil
}
