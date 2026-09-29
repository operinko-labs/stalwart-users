package db

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// EnsureDomainAdminsTable creates the table of domain admin assignments. It is
// owned by this app, not by Stalwart, so the app creates it on startup.
func (p *Pool) EnsureDomainAdminsTable() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := p.DB().ExecContext(ctx, `CREATE TABLE IF NOT EXISTS directory.domain_admins (
		name TEXT NOT NULL,
		domain TEXT NOT NULL,
		PRIMARY KEY (name, domain)
	)`)
	return err
}

func (p *Pool) ListAdminDomains(name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := p.DB().QueryContext(ctx, `SELECT domain FROM directory.domain_admins WHERE name = $1 ORDER BY domain`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	domains := make([]string, 0)
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return domains, nil
}

func (p *Pool) SetAdminDomains(name string, domains []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := p.DB().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(ctx, `DELETE FROM directory.domain_admins WHERE name = $1`, name); err != nil {
		return err
	}
	for _, domain := range domains {
		if _, err := tx.ExecContext(ctx, `INSERT INTO directory.domain_admins (name, domain) VALUES ($1, $2)`, name, domain); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (p *Pool) IsAdmin(name string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var isAdmin bool
	err := p.DB().QueryRowContext(ctx, `SELECT COALESCE(is_admin, false) FROM directory.accounts WHERE name = $1`, name).Scan(&isAdmin)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return isAdmin, nil
}
