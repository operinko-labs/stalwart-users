package db

import "errors"

var (
	ErrAccountNotFound         = errors.New("account not found")
	ErrGroupMembershipNotFound = errors.New("group membership not found")
)
