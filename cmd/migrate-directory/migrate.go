package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/operinko-labs/stalwart-users/internal/auth"
	"github.com/operinko-labs/stalwart-users/internal/stalwart"
)

const (
	minHashBytes = 65
	hashPrefix   = "{ssha512}"
)

var hashBody = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)

type sqlAccount struct {
	Name, Secret, Description string
	Quota                     int64
	IsAdmin                   bool
	Aliases                   []string
}

type change struct {
	Address, AccountID string
	Patch              map[string]any
	Secret             string
	Account            stalwart.Account
}

// writer is the part of the Stalwart client the migration writes through.
type writer interface {
	UpdateAccount(ctx context.Context, id string, patch map[string]any) error
	SetPassword(ctx context.Context, account stalwart.Account, secret string) error
}

// loadSQL reads the active accounts and their 'alias' addresses. An address
// row whose type is neither 'primary' nor 'alias' (for example a mailing list)
// is an error: it must not be imported as a personal alias.
func loadSQL(db *sql.DB) ([]sqlAccount, error) {
	rows, err := db.Query(`
		SELECT a.name, COALESCE(a.secret, ''), COALESCE(a.description, ''),
		       COALESCE(a.quota, 0), COALESCE(a.is_admin, false), e.address, e.type
		FROM directory.accounts a
		LEFT JOIN directory.emails e ON e.name = a.name
		WHERE a.active = true
		ORDER BY a.name, e.address`)
	if err != nil {
		return nil, fmt.Errorf("query directory accounts: %w", err)
	}
	defer rows.Close()

	var accounts []sqlAccount
	for rows.Next() {
		var (
			account      sqlAccount
			address, typ sql.NullString
		)
		if err := rows.Scan(&account.Name, &account.Secret, &account.Description, &account.Quota, &account.IsAdmin, &address, &typ); err != nil {
			return nil, fmt.Errorf("scan directory account: %w", err)
		}

		if n := len(accounts); n == 0 || accounts[n-1].Name != account.Name {
			accounts = append(accounts, account)
		}
		current := &accounts[len(accounts)-1]

		if !address.Valid {
			continue
		}
		switch typ.String {
		case "primary":
		case "alias":
			current.Aliases = append(current.Aliases, address.String)
		default:
			return nil, fmt.Errorf("%s: address %s has type %q; only 'primary' and 'alias' can be migrated", account.Name, address.String, typ.String)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read directory accounts: %w", err)
	}

	return accounts, nil
}

// validHash reports whether Stalwart will store secret verbatim as an SSHA512
// hash: case-insensitive {SSHA512} prefix, strict standard base64, and enough
// decoded bytes for a 64-byte digest plus a salt.
func validHash(secret string) bool {
	if len(secret) < len(hashPrefix) || strings.ToLower(secret[:len(hashPrefix)]) != hashPrefix {
		return false
	}
	body := secret[len(hashPrefix):]
	if !hashBody.MatchString(body) {
		return false
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(body)

	return err == nil && len(decoded) >= minHashBytes
}

// plan matches every SQL account to its Stalwart User and works out the patch
// that brings Stalwart up to the SQL data. It only ever adds: Stalwart's
// roles and aliases are the source of truth and are never lowered or removed.
// All problems are reported together; nothing is returned on error.
func plan(sqlAccts []sqlAccount, accts []stalwart.Account, domains []stalwart.Domain) ([]change, error) {
	users := make(map[string]stalwart.Account, len(accts))
	for _, account := range accts {
		if account.Type == "User" {
			users[auth.CanonicalName(account.Email)] = account
		}
	}

	domainIDs := make(map[string]string, len(domains))
	domainNames := make(map[string]string, len(domains))
	for _, domain := range domains {
		domainIDs[auth.CanonicalName(domain.Name)] = domain.ID
		domainNames[domain.ID] = auth.CanonicalName(domain.Name)
	}

	// owners maps every address and alias Stalwart knows, on Users and Groups
	// alike, to the account that holds it.
	owners := make(map[string]string, len(accts))
	for _, account := range accts {
		owners[auth.CanonicalName(account.Email)] = account.ID
		for _, alias := range account.Aliases {
			if domain, ok := domainNames[alias.DomainID]; ok {
				owners[auth.CanonicalName(alias.Name)+"@"+domain] = account.ID
			}
		}
	}

	var (
		changes      []change
		errs         []error
		seenAccounts = map[string]bool{}
		sqlAliases   = map[string]string{} // alias -> SQL account that lists it
	)
	for _, source := range sqlAccts {
		address := auth.CanonicalName(source.Name)

		if seenAccounts[address] {
			errs = append(errs, fmt.Errorf("%s: listed more than once in the SQL directory", address))
			continue
		}
		seenAccounts[address] = true

		if !validHash(source.Secret) {
			errs = append(errs, fmt.Errorf("%s: secret is not a valid {SSHA512} hash", address))
			continue
		}
		account, ok := users[address]
		if !ok {
			errs = append(errs, fmt.Errorf("%s: no matching User account in Stalwart", address))
			continue
		}

		patch, err := buildPatch(address, source, account, domainIDs, domainNames)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, raw := range source.Aliases {
			full := auth.CanonicalName(raw)
			if owner, ok := owners[full]; ok && owner != account.ID {
				errs = append(errs, fmt.Errorf("%s: alias %s already belongs to another Stalwart account", address, full))
			}
			if other, ok := sqlAliases[full]; ok && other != address {
				errs = append(errs, fmt.Errorf("%s: alias %s is also listed on %s", address, full, other))
			}
			sqlAliases[full] = address
		}
		changes = append(changes, change{
			Address: address, AccountID: account.ID, Patch: patch, Secret: source.Secret, Account: account,
		})
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return changes, nil
}

func buildPatch(address string, source sqlAccount, account stalwart.Account, domainIDs, domainNames map[string]string) (map[string]any, error) {
	patch := map[string]any{}

	if source.Description != "" && source.Description != account.Description {
		patch["description"] = source.Description
	}
	if source.IsAdmin && !account.IsAdmin {
		patch["roles"] = map[string]any{"@type": "Admin"}
	}
	if source.Quota > 0 && source.Quota != account.DiskQuota {
		patch["quotas/maxDiskQuota"] = source.Quota
	}

	have := map[string]bool{address: true}
	nextKey := 0
	for key, alias := range account.Aliases {
		if domain, ok := domainNames[alias.DomainID]; ok {
			have[auth.CanonicalName(alias.Name)+"@"+domain] = true
		}
		if n, err := strconv.Atoi(key); err == nil && n >= nextKey {
			nextKey = n + 1
		}
	}

	for _, raw := range source.Aliases {
		full := auth.CanonicalName(raw)
		local, domain, ok := strings.Cut(full, "@")
		if !ok || local == "" || domain == "" {
			return nil, fmt.Errorf("%s: invalid alias %q", address, raw)
		}
		domainID, ok := domainIDs[domain]
		if !ok {
			return nil, fmt.Errorf("%s: alias %s is on domain %s, which Stalwart does not host", address, full, domain)
		}
		if have[full] {
			continue
		}
		have[full] = true

		patch["aliases/"+strconv.Itoa(nextKey)] = map[string]any{
			"enable": true, "name": local, "domainId": domainID, "description": nil,
		}
		nextKey++
	}

	return patch, nil
}

// fields lists the top-level properties a patch touches, plus the secret.
func (c change) fields() []string {
	seen := map[string]bool{}
	for key := range c.Patch {
		name, _, _ := strings.Cut(key, "/")
		seen[name] = true
	}
	names := make([]string, 0, len(seen)+1)
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)

	return append(names, "secret")
}

// filterOnly keeps the SQL accounts named in only (canonical match). An empty
// list keeps everything; a name that matches nothing is an error.
func filterOnly(sqlAccts []sqlAccount, only []string) ([]sqlAccount, error) {
	if len(only) == 0 {
		return sqlAccts, nil
	}

	wanted := make(map[string]bool, len(only))
	for _, address := range only {
		wanted[auth.CanonicalName(address)] = true
	}

	var kept []sqlAccount
	for _, account := range sqlAccts {
		name := auth.CanonicalName(account.Name)
		if wanted[name] {
			kept = append(kept, account)
			delete(wanted, name)
		}
	}

	if len(wanted) > 0 {
		missing := make([]string, 0, len(wanted))
		for address := range wanted {
			missing = append(missing, address)
		}
		sort.Strings(missing)

		return nil, fmt.Errorf("--only: no active SQL account named %s", strings.Join(missing, ", "))
	}

	return kept, nil
}

// run plans the migration and, with apply, writes it. Every check happens
// before the first write. Secrets are never printed.
func run(ctx context.Context, out io.Writer, sqlAccts []sqlAccount, accts []stalwart.Account, domains []stalwart.Domain, w writer, apply bool, only []string) error {
	selected, err := filterOnly(sqlAccts, only)
	if err != nil {
		return err
	}

	changes, err := plan(selected, accts, domains)
	if err != nil {
		return err
	}

	for _, c := range changes {
		if apply {
			if len(c.Patch) > 0 {
				if err := w.UpdateAccount(ctx, c.AccountID, c.Patch); err != nil {
					return fmt.Errorf("%s: %w", c.Address, err)
				}
			}
			if err := w.SetPassword(ctx, c.Account, c.Secret); err != nil {
				return fmt.Errorf("%s: set password: %w", c.Address, err)
			}
		}

		switch {
		case len(c.Patch) == 0:
			fmt.Fprintf(out, "%s: unchanged\n", c.Address)
		case apply:
			fmt.Fprintf(out, "%s: updated (%s)\n", c.Address, strings.Join(c.fields(), ", "))
		default:
			fmt.Fprintf(out, "%s: would update (%s)\n", c.Address, strings.Join(c.fields(), ", "))
		}
	}

	return nil
}
