package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/operinko-labs/stalwart-users/internal/model"
)

var ErrAccountNotFound = errors.New("account not found")

func (p *Pool) ListAccounts() ([]model.Account, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := p.DB().QueryContext(ctx, `SELECT name, description, type, quota, active FROM directory.accounts ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	accounts := make([]model.Account, 0)
	for rows.Next() {
		var account model.Account
		if err := rows.Scan(&account.Name, &account.Description, &account.Type, &account.Quota, &account.Active); err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return accounts, nil
}

func (p *Pool) GetAccount(name string) (*model.Account, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var account model.Account
	err := p.DB().QueryRowContext(ctx, `SELECT name, description, type, quota, active FROM directory.accounts WHERE name = $1`, name).
		Scan(&account.Name, &account.Description, &account.Type, &account.Quota, &account.Active)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &account, nil
}

func (p *Pool) CreateAccount(name, secret, description, accountType string, quota int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := p.DB().ExecContext(ctx,
		`INSERT INTO directory.accounts (name, secret, description, type, quota) VALUES ($1, $2, $3, $4, $5)`,
		name, secret, description, accountType, quota,
	)
	return err
}

func (p *Pool) GetAccountSecret(name string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var secret string
	err := p.DB().QueryRowContext(ctx, `SELECT secret FROM directory.accounts WHERE name = $1`, name).Scan(&secret)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrAccountNotFound
	}
	if err != nil {
		return "", err
	}

	return secret, nil
}

func (p *Pool) InsertEmail(name, address, emailType string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := p.DB().ExecContext(ctx,
		`INSERT INTO directory.emails (name, address, type) VALUES ($1, $2, $3)`,
		name, address, emailType,
	)
	return err
}

func (p *Pool) UpdateAccount(name string, description *string, quota *int, active *bool) error {
	setClauses := make([]string, 0, 3)
	args := make([]any, 0, 4)
	argIndex := 1

	if description != nil {
		setClauses = append(setClauses, fmt.Sprintf("description = $%d", argIndex))
		args = append(args, *description)
		argIndex++
	}
	if quota != nil {
		setClauses = append(setClauses, fmt.Sprintf("quota = $%d", argIndex))
		args = append(args, *quota)
		argIndex++
	}
	if active != nil {
		setClauses = append(setClauses, fmt.Sprintf("active = $%d", argIndex))
		args = append(args, *active)
		argIndex++
	}

	if len(setClauses) == 0 {
		return nil
	}

	args = append(args, name)
	query := fmt.Sprintf("UPDATE directory.accounts SET %s WHERE name = $%d", strings.Join(setClauses, ", "), argIndex)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := p.DB().ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrAccountNotFound
	}

	return nil
}

func (p *Pool) UpdateAccountPassword(name, secret string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := p.DB().ExecContext(ctx, `UPDATE directory.accounts SET secret = $1 WHERE name = $2`, secret, name)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrAccountNotFound
	}

	return nil
}

func (p *Pool) DeleteAccount(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := p.DB().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(ctx, `DELETE FROM directory.group_members WHERE name = $1 OR member_of = $1`, name); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM directory.emails WHERE name = $1`, name); err != nil {
		return err
	}

	result, err := tx.ExecContext(ctx, `DELETE FROM directory.accounts WHERE name = $1`, name)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrAccountNotFound
	}

	return tx.Commit()
}
