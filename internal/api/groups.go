package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/operinko-labs/stalwart-users/internal/db"
	"github.com/operinko-labs/stalwart-users/internal/model"
)

var errGroupMembershipNotFound = db.ErrGroupMembershipNotFound

type groupsStore interface {
	ListGroups(name string) ([]string, error)
	AddGroup(name, memberOf string) error
	RemoveGroup(name, memberOf string) error
	GetAccount(name string) (*model.Account, error)
}

type createGroupRequest struct {
	MemberOf string `json:"member_of"`
}

func ListGroupsHandler(pool *db.Pool) http.HandlerFunc {
	if pool == nil {
		return databaseNotConfiguredHandler()
	}
	return newListGroupsHandler(pool)
}

func CreateGroupHandler(pool *db.Pool) http.HandlerFunc {
	if pool == nil {
		return databaseNotConfiguredHandler()
	}
	return newCreateGroupHandler(pool)
}

func DeleteGroupHandler(pool *db.Pool) http.HandlerFunc {
	if pool == nil {
		return databaseNotConfiguredHandler()
	}
	return newDeleteGroupHandler(pool)
}

func newListGroupsHandler(store groupsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSONHeader(w)

		if !groupAccountExists(w, r, store) {
			return
		}

		groups, err := store.ListGroups(r.PathValue("name"))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(groups)
	}
}

func newCreateGroupHandler(store groupsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSONHeader(w)

		if !groupAccountExists(w, r, store) {
			return
		}

		var req createGroupRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		if req.MemberOf == "" {
			writeError(w, http.StatusBadRequest, "member_of is required")
			return
		}

		if err := store.AddGroup(r.PathValue("name"), req.MemberOf); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "created"})
	}
}

func newDeleteGroupHandler(store groupsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSONHeader(w)

		if !groupAccountExists(w, r, store) {
			return
		}

		if err := store.RemoveGroup(r.PathValue("name"), r.PathValue("group")); err != nil {
			if errors.Is(err, errGroupMembershipNotFound) {
				writeError(w, http.StatusNotFound, "group membership not found")
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func groupAccountExists(w http.ResponseWriter, r *http.Request, store groupsStore) bool {
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
