package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/operinko-labs/stalwart-users/internal/model"
)

func (p *Pool) ListEmails(name string) ([]model.Email, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := p.DB().QueryContext(ctx, `SELECT name, address, type FROM directory.emails WHERE name = $1 ORDER BY type DESC, address`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	emails := make([]model.Email, 0)
	for rows.Next() {
		var email model.Email
		if err := rows.Scan(&email.Name, &email.Address, &email.Type); err != nil {
			return nil, err
		}
		emails = append(emails, email)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return emails, nil
}

func (p *Pool) GetEmailType(name, address string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var emailType string
	err := p.DB().QueryRowContext(ctx, `SELECT type FROM directory.emails WHERE name = $1 AND address = $2`, name, address).Scan(&emailType)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}

	return emailType, nil
}

func (p *Pool) DeleteEmail(name, address string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := p.DB().ExecContext(ctx, `DELETE FROM directory.emails WHERE name = $1 AND address = $2`, name, address)
	return err
}
