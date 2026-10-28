// Package directory is the account store behind the HTTP handlers. Accounts
// live in Stalwart and are reached through its JMAP admin API; only the domain
// admin assignments stay in this app's own database.
package directory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
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
	ListDomains(ctx context.Context) ([]stalwart.Domain, error)
	Authenticate(ctx context.Context, username, password string) (bool, error)
	SetPassword(ctx context.Context, account stalwart.Account, secret string) error
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
	name = auth.CanonicalName(name)

	account, err := s.find(name)
	if err != nil || account == nil {
		return nil, err
	}

	result := toModel(*account)
	return &result, nil
}

func (s *Store) CreateAccount(name, password, description, accountType string, quota int) error {
	name = auth.CanonicalName(name)

	if accountType == "group" {
		return fmt.Errorf("%w: groups can't be created", ErrUnsupported)
	}

	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()

	return s.client.CreateAccount(ctx, name, password, description, int64(quota))
}

func (s *Store) UpdateAccount(name string, description *string, quota *int, active *bool) error {
	name = auth.CanonicalName(name)

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
	name = auth.CanonicalName(name)

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
	name = auth.CanonicalName(name)

	account, err := s.find(name)
	if err != nil || account == nil {
		return false, err
	}

	return account.IsAdmin, nil
}

// Authenticate checks the credentials against Stalwart.
func (s *Store) Authenticate(ctx context.Context, name, password string) (bool, error) {
	name = auth.CanonicalName(name)

	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	return s.client.Authenticate(ctx, name, password)
}

// SetPassword sends the new plaintext password to Stalwart, which hashes it and
// enforces its password policy.
func (s *Store) SetPassword(name, password string) error {
	name = auth.CanonicalName(name)

	account, err := s.find(name)
	if err != nil {
		return err
	}
	if account == nil {
		return db.ErrAccountNotFound
	}

	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()

	return s.client.SetPassword(ctx, *account, password)
}

func (s *Store) ListAdminDomains(name string) ([]string, error) {
	return s.admins.ListAdminDomains(auth.CanonicalName(name))
}

func (s *Store) SetAdminDomains(name string, domains []string) error {
	return s.admins.SetAdminDomains(auth.CanonicalName(name), domains)
}

func (s *Store) find(name string) (*stalwart.Account, error) {
	accounts, err := s.listAccounts()
	if err != nil {
		return nil, err
	}

	return findByType(accounts, "User", name), nil
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

// ErrAddressInUse means another account already owns the address; handlers map
// it to 409.
var ErrAddressInUse = errors.New("address already in use")

// ListEmails returns the primary address first, then the aliases sorted by
// address.
func (s *Store) ListEmails(name string) ([]model.Email, error) {
	name = auth.CanonicalName(name)

	account, aliases, err := s.findWithAliases(name)
	if err != nil {
		return nil, err
	}

	emails := []model.Email{{Name: account.Email, Address: account.Email, Type: "primary"}}
	addresses := make([]string, 0, len(aliases))
	for _, address := range aliases {
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)
	for _, address := range addresses {
		emails = append(emails, model.Email{Name: account.Email, Address: address, Type: "alias"})
	}

	return emails, nil
}

// InsertEmail adds an alias; Stalwart accounts have a single primary address.
func (s *Store) InsertEmail(name, address, emailType string) error {
	name = auth.CanonicalName(name)
	address = auth.CanonicalName(address)

	if emailType != "" && emailType != "alias" {
		return fmt.Errorf("%w: only alias addresses can be added", ErrUnsupported)
	}

	localPart, domain, ok := strings.Cut(address, "@")
	if !ok || localPart == "" || domain == "" {
		return fmt.Errorf("%w: invalid address %q", ErrUnsupported, address)
	}

	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()

	accounts, err := s.client.ListAccounts(ctx)
	if err != nil {
		return err
	}
	domains, err := s.client.ListDomains(ctx)
	if err != nil {
		return err
	}

	account := findByType(accounts, "User", name)
	if account == nil {
		return db.ErrAccountNotFound
	}

	domainID := ""
	for _, d := range domains {
		if strings.EqualFold(d.Name, domain) {
			domainID = d.ID
			break
		}
	}
	if domainID == "" {
		return fmt.Errorf("%w: domain %s is not hosted here", ErrUnsupported, domain)
	}

	if addressInUse(accounts, domains, address) {
		return ErrAddressInUse
	}

	next := 0
	for key := range account.Aliases {
		if n, err := strconv.Atoi(key); err == nil && n >= next {
			next = n + 1
		}
	}

	return s.client.UpdateAccount(ctx, account.ID, map[string]any{
		"aliases/" + strconv.Itoa(next): map[string]any{
			"enable":      true,
			"name":        localPart,
			"domainId":    domainID,
			"description": nil,
		},
	})
}

// GetEmailType returns "primary", "alias", or "" when the address is not on the
// account.
func (s *Store) GetEmailType(name, address string) (string, error) {
	name = auth.CanonicalName(name)
	address = auth.CanonicalName(address)

	account, aliases, err := s.findWithAliases(name)
	if err != nil {
		return "", err
	}

	if strings.EqualFold(account.Email, address) {
		return "primary", nil
	}
	for _, alias := range aliases {
		if strings.EqualFold(alias, address) {
			return "alias", nil
		}
	}

	return "", nil
}

// DeleteEmail removes an alias. An address that is not on the account is a
// no-op; the primary address cannot be removed.
func (s *Store) DeleteEmail(name, address string) error {
	name = auth.CanonicalName(name)
	address = auth.CanonicalName(address)

	account, aliases, err := s.findWithAliases(name)
	if err != nil {
		return err
	}

	if strings.EqualFold(account.Email, address) {
		return fmt.Errorf("%w: the primary address can not be removed", ErrUnsupported)
	}
	for key, alias := range aliases {
		if strings.EqualFold(alias, address) {
			ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
			defer cancel()

			return s.client.UpdateAccount(ctx, account.ID, map[string]any{"aliases/" + key: nil})
		}
	}

	return nil
}

// AddressInUse reports whether any account, user or group, has the address as
// its primary address or an alias.
func (s *Store) AddressInUse(address string) (bool, error) {
	address = auth.CanonicalName(address)

	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()

	accounts, err := s.client.ListAccounts(ctx)
	if err != nil {
		return false, err
	}
	domains, err := s.client.ListDomains(ctx)
	if err != nil {
		return false, err
	}

	return addressInUse(accounts, domains, address), nil
}

// ListGroups returns the addresses of the groups the account belongs to, sorted.
func (s *Store) ListGroups(name string) ([]string, error) {
	name = auth.CanonicalName(name)

	accounts, err := s.listAccounts()
	if err != nil {
		return nil, err
	}
	account := findByType(accounts, "User", name)
	if account == nil {
		return nil, db.ErrAccountNotFound
	}

	groups := []string{}
	for _, id := range account.MemberGroupIDs {
		for _, candidate := range accounts {
			if candidate.Type == "Group" && candidate.ID == id {
				groups = append(groups, candidate.Email)
			}
		}
	}
	sort.Strings(groups)

	return groups, nil
}

// AddGroup adds the account to an existing group; already being a member is a
// no-op.
func (s *Store) AddGroup(name, memberOf string) error {
	name = auth.CanonicalName(name)
	memberOf = auth.CanonicalName(memberOf)

	accounts, err := s.listAccounts()
	if err != nil {
		return err
	}
	account := findByType(accounts, "User", name)
	if account == nil {
		return db.ErrAccountNotFound
	}

	group := findByType(accounts, "Group", memberOf)
	if group == nil {
		return fmt.Errorf("%w: group %s does not exist", ErrUnsupported, memberOf)
	}
	if slices.Contains(account.MemberGroupIDs, group.ID) {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()

	return s.client.UpdateAccount(ctx, account.ID, map[string]any{"memberGroupIds/" + group.ID: true})
}

func (s *Store) RemoveGroup(name, memberOf string) error {
	name = auth.CanonicalName(name)
	memberOf = auth.CanonicalName(memberOf)

	accounts, err := s.listAccounts()
	if err != nil {
		return err
	}
	account := findByType(accounts, "User", name)
	if account == nil {
		return db.ErrAccountNotFound
	}

	group := findByType(accounts, "Group", memberOf)
	if group == nil || !slices.Contains(account.MemberGroupIDs, group.ID) {
		return db.ErrGroupMembershipNotFound
	}

	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()

	return s.client.UpdateAccount(ctx, account.ID, map[string]any{"memberGroupIds/" + group.ID: nil})
}

func (s *Store) listAccounts() ([]stalwart.Account, error) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()

	return s.client.ListAccounts(ctx)
}

// findWithAliases returns the user and its alias addresses keyed by alias key.
func (s *Store) findWithAliases(name string) (*stalwart.Account, map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()

	accounts, err := s.client.ListAccounts(ctx)
	if err != nil {
		return nil, nil, err
	}
	account := findByType(accounts, "User", name)
	if account == nil {
		return nil, nil, db.ErrAccountNotFound
	}

	domains, err := s.client.ListDomains(ctx)
	if err != nil {
		return nil, nil, err
	}

	return account, aliasAddresses(*account, domainNames(domains)), nil
}

// findByType matches the primary address case-insensitively among accounts of
// one Stalwart type ("User" or "Group"); nil when there is none.
func findByType(accounts []stalwart.Account, accountType, address string) *stalwart.Account {
	for i := range accounts {
		if accounts[i].Type == accountType && strings.EqualFold(accounts[i].Email, address) {
			return &accounts[i]
		}
	}

	return nil
}

func domainNames(domains []stalwart.Domain) map[string]string {
	names := make(map[string]string, len(domains))
	for _, domain := range domains {
		names[domain.ID] = domain.Name
	}

	return names
}

// aliasAddresses maps alias keys to full addresses, skipping aliases whose
// domain is unknown.
func aliasAddresses(account stalwart.Account, domains map[string]string) map[string]string {
	addresses := make(map[string]string, len(account.Aliases))
	for key, alias := range account.Aliases {
		if domain, ok := domains[alias.DomainID]; ok {
			addresses[key] = alias.Name + "@" + domain
		}
	}

	return addresses
}

func addressInUse(accounts []stalwart.Account, domains []stalwart.Domain, address string) bool {
	names := domainNames(domains)
	for _, account := range accounts {
		if strings.EqualFold(account.Email, address) {
			return true
		}
		for _, alias := range aliasAddresses(account, names) {
			if strings.EqualFold(alias, address) {
				return true
			}
		}
	}

	return false
}
