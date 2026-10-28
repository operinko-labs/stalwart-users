// Package directory is the account store behind the HTTP handlers. Accounts
// live in Stalwart and are reached through its JMAP admin API; only the domain
// admin assignments stay in this app's own database.
package directory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/operinko-labs/stalwart-users/internal/auth"
	"github.com/operinko-labs/stalwart-users/internal/db"
	"github.com/operinko-labs/stalwart-users/internal/model"
	"github.com/operinko-labs/stalwart-users/internal/stalwart"
)

// ErrUnsupported marks requests Stalwart 1.0 can't fulfil. Its text is safe to
// show to users.
var ErrUnsupported = errors.New("not supported by Stalwart 1.0")

const callTimeout = 5 * time.Second

type jmapClient interface {
	ListAccounts(ctx context.Context) ([]stalwart.Account, error)
	CreateAccount(ctx context.Context, name, password, description string, diskQuota int64) error
	UpdateAccount(ctx context.Context, id string, patch map[string]any) error
	DeleteAccount(ctx context.Context, name string) error
}

type adminDomainsDB interface {
	ListAdminDomains(name string) ([]string, error)
	SetAdminDomains(name string, domains []string) error
	DeleteAdminDomains(name string) error
}

type Store struct {
	client jmapClient
	admins adminDomainsDB
}

var _ auth.AccessStore = (*Store)(nil)

func New(client jmapClient, admins adminDomainsDB) *Store {
	return &Store{client: client, admins: admins}
}

func (s *Store) ListAccounts() ([]model.Account, error) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()

	accounts, err := s.client.ListAccounts(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]model.Account, 0, len(accounts))
	for _, account := range accounts {
		if account.Type == "User" {
			result = append(result, toModel(account))
		}
	}

	return result, nil
}

// GetAccount returns nil, nil when no user has the given address.
func (s *Store) GetAccount(name string) (*model.Account, error) {
	account, err := s.find(name)
	if err != nil || account == nil {
		return nil, err
	}

	result := toModel(*account)
	return &result, nil
}

func (s *Store) CreateAccount(name, password, description, accountType string, quota int) error {
	if accountType == "group" {
		return fmt.Errorf("%w: groups can't be created", ErrUnsupported)
	}

	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()

	return s.client.CreateAccount(ctx, name, password, description, int64(quota))
}

func (s *Store) UpdateAccount(name string, description *string, quota *int, active *bool) error {
	if active != nil && !*active {
		return fmt.Errorf("%w: accounts can't be disabled", ErrUnsupported)
	}

	account, err := s.find(name)
	if err != nil {
		return err
	}
	if account == nil {
		return db.ErrAccountNotFound
	}

	patch := map[string]any{}
	if description != nil {
		patch["description"] = *description
	}
	if quota != nil {
		quotas := map[string]any{}
		if *quota > 0 {
			quotas["maxDiskQuota"] = int64(*quota)
		}
		patch["quotas"] = quotas
	}
	if len(patch) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()

	return s.client.UpdateAccount(ctx, account.ID, patch)
}

func (s *Store) DeleteAccount(name string) error {
	account, err := s.find(name)
	if err != nil {
		return err
	}
	if account == nil {
		return db.ErrAccountNotFound
	}

	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()

	if err := s.client.DeleteAccount(ctx, account.Email); err != nil {
		return err
	}

	return s.admins.DeleteAdminDomains(name)
}

// IsAdmin reports whether the account holds an admin role in Stalwart; unknown
// accounts are not admins.
func (s *Store) IsAdmin(name string) (bool, error) {
	account, err := s.find(name)
	if err != nil || account == nil {
		return false, err
	}

	return account.IsAdmin, nil
}

func (s *Store) ListAdminDomains(name string) ([]string, error) {
	return s.admins.ListAdminDomains(name)
}

func (s *Store) SetAdminDomains(name string, domains []string) error {
	return s.admins.SetAdminDomains(name, domains)
}

func (s *Store) find(name string) (*stalwart.Account, error) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()

	accounts, err := s.client.ListAccounts(ctx)
	if err != nil {
		return nil, err
	}

	for i := range accounts {
		if accounts[i].Type == "User" && strings.EqualFold(accounts[i].Email, name) {
			return &accounts[i], nil
		}
	}

	return nil, nil
}

func toModel(account stalwart.Account) model.Account {
	return model.Account{
		Name:        account.Email,
		Description: account.Description,
		Type:        "individual",
		Quota:       int(account.DiskQuota),
		Active:      true,
		IsAdmin:     account.IsAdmin,
	}
}
