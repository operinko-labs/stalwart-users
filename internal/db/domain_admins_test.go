package db

import (
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func newMockPool(t *testing.T) (*Pool, sqlmock.Sqlmock) {
	t.Helper()

	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = database.Close()
	})

	return &Pool{db: database}, mock
}

func TestEnsureDomainAdminsTableCreatesTable(t *testing.T) {
	t.Parallel()

	pool, mock := newMockPool(t)
	mock.ExpectExec(regexp.QuoteMeta(`CREATE TABLE IF NOT EXISTS directory.domain_admins`)).WillReturnResult(sqlmock.NewResult(0, 0))

	if err := pool.EnsureDomainAdminsTable(); err != nil {
		t.Fatalf("EnsureDomainAdminsTable() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteAdminDomainsRemovesRows(t *testing.T) {
	t.Parallel()

	pool, mock := newMockPool(t)
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM directory.domain_admins WHERE name = $1`)).
		WithArgs("dora@client.fi").
		WillReturnResult(sqlmock.NewResult(0, 2))

	if err := pool.DeleteAdminDomains("dora@client.fi"); err != nil {
		t.Fatalf("DeleteAdminDomains() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestListAdminDomainsReturnsDomains(t *testing.T) {
	t.Parallel()

	pool, mock := newMockPool(t)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT domain FROM directory.domain_admins WHERE name = $1 ORDER BY domain`)).
		WithArgs("dora@client.fi").
		WillReturnRows(sqlmock.NewRows([]string{"domain"}).AddRow("client.fi").AddRow("client2.fi"))

	domains, err := pool.ListAdminDomains("dora@client.fi")
	if err != nil {
		t.Fatalf("ListAdminDomains() error = %v", err)
	}
	if len(domains) != 2 || domains[0] != "client.fi" || domains[1] != "client2.fi" {
		t.Fatalf("domains = %#v, want [client.fi client2.fi]", domains)
	}
}

func TestSetAdminDomainsReplacesDomainsInTransaction(t *testing.T) {
	t.Parallel()

	pool, mock := newMockPool(t)
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM directory.domain_admins WHERE name = $1`)).WithArgs("dora@client.fi").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO directory.domain_admins (name, domain) VALUES ($1, $2)`)).WithArgs("dora@client.fi", "client.fi").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO directory.domain_admins (name, domain) VALUES ($1, $2)`)).WithArgs("dora@client.fi", "client2.fi").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := pool.SetAdminDomains("dora@client.fi", []string{"client.fi", "client2.fi"}); err != nil {
		t.Fatalf("SetAdminDomains() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
