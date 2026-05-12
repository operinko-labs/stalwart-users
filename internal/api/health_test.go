package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	internaldb "github.com/operinko-labs/stalwart-users/internal/db"
)

const unreachableDatabaseURL = "postgresql://stalwart:stalwart@127.0.0.1:1/stalwart?connect_timeout=1&sslmode=disable"

func TestHealthHandlerReturnsOKWhenNoDatabaseConfigured(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()

	HealthHandler(nil).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusOK)
	}

	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if body["status"] != "ok" {
		t.Fatalf("status = %q, want %q", body["status"], "ok")
	}

	if body["message"] != "no database configured" {
		t.Fatalf("message = %q, want %q", body["message"], "no database configured")
	}
}

func TestHealthHandlerReturnsServiceUnavailableOnDatabaseError(t *testing.T) {
	t.Parallel()

	pool, err := internaldb.NewPool(unreachableDatabaseURL)
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
	defer func() {
		_ = pool.Close()
	}()

	if err == nil {
		t.Fatal("expected database ping error")
	}

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()

	HealthHandler(pool).ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}

	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if body["status"] != "error" {
		t.Fatalf("status = %q, want %q", body["status"], "error")
	}

	if body["message"] == "" {
		t.Fatal("expected non-empty error message")
	}
}
