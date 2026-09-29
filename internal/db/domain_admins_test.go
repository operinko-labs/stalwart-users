package db

import (
	"database/sql"
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

func TestIsAdmin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rows *sqlmock.Rows
		err  error
		want bool
	}{
		{name: "admin", rows: sqlmock.NewRows([]string{"is_admin"}).AddRow(true), want: true},
		{name: "not admin", rows: sqlmock.NewRows([]string{"is_admin"}).AddRow(false), want: false},
		{name: "missing account", err: sql.ErrNoRows, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pool, mock := newMockPool(t)
			query := mock.ExpectQuery(regexp.QuoteMeta(`SELECT COALESCE(is_admin, false) FROM directory.accounts WHERE name = $1`)).WithArgs("boss@client.fi")
			if tt.err != nil {
				query.WillReturnError(tt.err)
			} else {
				query.WillReturnRows(tt.rows)
			}

			got, err := pool.IsAdmin("boss@client.fi")
			if err != nil {
				t.Fatalf("IsAdmin() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("IsAdmin() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddressInUse(t *testing.T) {
	t.Parallel()

	for _, want := range []bool{true, false} {
		pool, mock := newMockPool(t)
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT EXISTS (SELECT 1 FROM directory.emails WHERE lower(address) = lower($1))`)).
			WithArgs("ceo@client.fi").
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(want))

		got, err := pool.AddressInUse("ceo@client.fi")
		if err != nil {
			t.Fatalf("AddressInUse() error = %v", err)
		}
		if got != want {
			t.Fatalf("AddressInUse() = %v, want %v", got, want)
		}
	}
}

func TestListAccountsReadsAdminFlag(t *testing.T) {
	t.Parallel()

	pool, mock := newMockPool(t)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT name, description, type, quota, active, COALESCE(is_admin, false) FROM directory.accounts ORDER BY name`)).
		WillReturnRows(sqlmock.NewRows([]string{"name", "description", "type", "quota", "active", "is_admin"}).
			AddRow("boss@client.fi", "Boss", "individual", 0, true, true))

	accounts, err := pool.ListAccounts()
	if err != nil {
		t.Fatalf("ListAccounts() error = %v", err)
	}
	if len(accounts) != 1 || !accounts[0].IsAdmin {
		t.Fatalf("accounts = %#v, want one admin account", accounts)
	}
}

func TestDeleteAccountRemovesDomainAdminRows(t *testing.T) {
	t.Parallel()

	pool, mock := newMockPool(t)
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM directory.group_members WHERE name = $1 OR member_of = $1`)).WithArgs("bob@client.fi").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM directory.emails WHERE name = $1`)).WithArgs("bob@client.fi").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM directory.domain_admins WHERE name = $1`)).WithArgs("bob@client.fi").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM directory.accounts WHERE name = $1`)).WithArgs("bob@client.fi").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := pool.DeleteAccount("bob@client.fi"); err != nil {
		t.Fatalf("DeleteAccount() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
