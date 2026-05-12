package db

import "testing"

const invalidDatabaseURL = "://bad"

func TestNewPoolReturnsPoolWhenInitialPingFails(t *testing.T) {
	t.Parallel()

	pool, err := NewPool(invalidDatabaseURL)
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
	defer func() {
		_ = pool.Close()
	}()

	if err == nil {
		t.Fatal("expected initial ping error")
	}

	if err := pool.HealthCheck(); err == nil {
		t.Fatal("expected health check error")
	}
}

func TestPoolCloseShutsDownPoolWithoutError(t *testing.T) {
	t.Parallel()

	pool, err := NewPool(invalidDatabaseURL)
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}

	if err == nil {
		t.Fatal("expected initial ping error")
	}

	if err := pool.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestPoolDBReturnsUnderlyingDatabase(t *testing.T) {
	t.Parallel()

	pool, err := NewPool(invalidDatabaseURL)
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
	defer func() {
		_ = pool.Close()
	}()

	if err == nil {
		t.Fatal("expected initial ping error")
	}

	if pool.DB() == nil {
		t.Fatal("expected underlying *sql.DB")
	}
}
