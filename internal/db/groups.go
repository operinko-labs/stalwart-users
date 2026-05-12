package db

import (
	"context"
	"errors"
	"time"
)

var ErrGroupMembershipNotFound = errors.New("group membership not found")

func (p *Pool) ListGroups(name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := p.DB().QueryContext(ctx, `SELECT member_of FROM directory.group_members WHERE name = $1 ORDER BY member_of`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	groups := make([]string, 0)
	for rows.Next() {
		var memberOf string
		if err := rows.Scan(&memberOf); err != nil {
			return nil, err
		}
		groups = append(groups, memberOf)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return groups, nil
}

func (p *Pool) AddGroup(name, memberOf string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := p.DB().ExecContext(ctx, `INSERT INTO directory.group_members (name, member_of) VALUES ($1, $2)`, name, memberOf)
	return err
}

func (p *Pool) RemoveGroup(name, memberOf string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := p.DB().ExecContext(ctx, `DELETE FROM directory.group_members WHERE name = $1 AND member_of = $2`, name, memberOf)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrGroupMembershipNotFound
	}

	return nil
}
