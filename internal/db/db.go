package db

import (
	"context"
	"database/sql"
	"time"

	_ "github.com/lib/pq"
)

type Pool struct {
	db *sql.DB
}

func NewPool(databaseURL string) (*Pool, error) {
	database, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, err
	}

	database.SetMaxOpenConns(10)
	database.SetMaxIdleConns(5)
	database.SetConnMaxLifetime(5 * time.Minute)

	pool := &Pool{db: database}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := database.PingContext(ctx); err != nil {
		return pool, err
	}

	return pool, nil
}

func (p *Pool) HealthCheck() error {
	if p == nil || p.db == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return p.db.PingContext(ctx)
}

func (p *Pool) Close() error {
	if p == nil || p.db == nil {
		return nil
	}

	return p.db.Close()
}

func (p *Pool) DB() *sql.DB {
	if p == nil {
		return nil
	}

	return p.db
}
