package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"github.com/operinko-labs/stalwart-users/internal/stalwart"
)

func hashOf(prefix string, decodedLen int) string {
	return prefix + base64.StdEncoding.EncodeToString(make([]byte, decodedLen))
}

var testDomains = []stalwart.Domain{
	{ID: "d1", Name: "vaderrp.com"},
	{ID: "d2", Name: "erinko.fi"},
}

func goodHash() string { return hashOf("{SSHA512}", 68) }

func TestValidHash(t *testing.T) {
	t.Parallel()

	valid := map[string]string{
		"salt 4":       hashOf("{SSHA512}", 68),
		"salt 8":       hashOf("{SSHA512}", 72),
		"salt 16":      hashOf("{SSHA512}", 80),
		"lower-case":   hashOf("{ssha512}", 72),
		"one pad (71)": "{SSHA512}" + base64.StdEncoding.EncodeToString(make([]byte, 71)),
		"two pad (67)": "{SSHA512}" + base64.StdEncoding.EncodeToString(make([]byte, 67)),
	}
	for name, secret := range valid {
		if !validHash(secret) {
			t.Errorf("%s: validHash(%q) = false, want true", name, secret)
		}
	}

	// Non-zero trailing pad bits decode in lax mode but are not canonical base64.
	padBits := hashOf("{SSHA512}", 71)
	padBits = padBits[:len(padBits)-2] + "B="

	urlSafe := "{SSHA512}" + strings.NewReplacer("+", "-", "/", "_").Replace(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\xfb\xff", 40))))
	invalid := map[string]string{
		"url-safe body":    urlSafe,
		"trailing space":   goodHash() + " ",
		"trailing newline": goodHash() + "\n",
		"leading space":    " " + goodHash(),
		"prefix only":      "{SSHA}",
		"ssha512 no body":  "{SSHA512}",
		"wrong scheme":     hashOf("{SSHA}", 68),
		"too short":        hashOf("{SSHA512}", 64),
		"pad bits":         padBits,
		"empty":            "",
		"plaintext":        "hunter2hunter2",
	}
	for name, secret := range invalid {
		if validHash(secret) {
			t.Errorf("%s: validHash(%q) = true, want false", name, secret)
		}
	}
}

func TestLoadSQL(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(loadSQLQuery).WillReturnRows(
		sqlmock.NewRows([]string{"name", "secret", "description", "quota", "is_admin", "address", "type"}).
			AddRow("admin@vaderrp.com", "s1", "Admin", 0, true, "admin@vaderrp.com", "primary").
			AddRow("admin@vaderrp.com", "s1", "Admin", 0, true, "hostmaster@vaderrp.com", "alias").
			AddRow("admin@vaderrp.com", "s1", "Admin", 0, true, "root@vaderrp.com", "alias").
			AddRow("olli@erinko.fi", "s2", "", 1024, false, "olli@erinko.fi", "primary").
			AddRow("solo@erinko.fi", "s3", "", 0, false, nil, nil),
	)

	got, err := loadSQL(db)
	if err != nil {
		t.Fatalf("loadSQL() error = %v", err)
	}

	want := []sqlAccount{
		{Name: "admin@vaderrp.com", Secret: "s1", Description: "Admin", IsAdmin: true, Aliases: []string{"hostmaster@vaderrp.com", "root@vaderrp.com"}},
		{Name: "olli@erinko.fi", Secret: "s2", Quota: 1024},
		{Name: "solo@erinko.fi", Secret: "s3"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loadSQL() = %+v, want %+v", got, want)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

// loadSQLQuery pins the active filter and the join on every address row (the
// type is decided in Go, so a 'list' row can't slip in as an alias).
const loadSQLQuery = `(?s)e\.type\s+FROM directory\.accounts a\s+LEFT JOIN directory\.emails e ON e\.name = a\.name\s+WHERE a\.active = true`

func TestLoadSQLRejectsUnknownAddressType(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(loadSQLQuery).WillReturnRows(
		sqlmock.NewRows([]string{"name", "secret", "description", "quota", "is_admin", "address", "type"}).
			AddRow("a@vaderrp.com", "s1", "", 0, false, "a@vaderrp.com", "primary").
			AddRow("a@vaderrp.com", "s1", "", 0, false, "team@vaderrp.com", "list"),
	)

	_, err = loadSQL(db)
	if err == nil || !strings.Contains(err.Error(), "a@vaderrp.com") || !strings.Contains(err.Error(), "team@vaderrp.com") {
		t.Fatalf("loadSQL() error = %v, want it to name the account and the list address", err)
	}
}

func TestLoadSQLQueryError(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(loadSQLQuery).WillReturnError(errors.New("boom"))
	if _, err := loadSQL(db); err == nil {
		t.Fatal("loadSQL() error = nil, want error")
	}
}

func stalwartUser(id, email string) stalwart.Account {
	local, domain, _ := strings.Cut(email, "@")
	domainID := "d1"
	if domain == "erinko.fi" {
		domainID = "d2"
	}
	return stalwart.Account{
		ID: id, Type: "User", Name: local, DomainID: domainID, Email: email,
		Aliases: map[string]stalwart.Alias{}, PasswordKey: "0",
	}
}

func TestPlanAdminAndAliases(t *testing.T) {
	t.Parallel()

	sqlAccts := []sqlAccount{
		{Name: "Admin@vaderrp.com ", Secret: goodHash(), Description: "Site admin", Quota: 2048, IsAdmin: true,
			Aliases: []string{"root@vaderrp.com", "POSTMASTER@erinko.fi", "admin@erinko.fi"}},
	}
	account := stalwartUser("a1", "admin@vaderrp.com")
	account.Aliases = map[string]stalwart.Alias{
		"3":    {Name: "postmaster", DomainID: "d2"},  // already there; SQL lists it too
		"7":    {Name: "vaultwarden", DomainID: "d2"}, // unknown to SQL, must survive
		"misc": {Name: "x", DomainID: "d1"},           // non-numeric key is ignored for numbering
	}

	changes, err := plan(sqlAccts, []stalwart.Account{account}, testDomains)
	if err != nil {
		t.Fatalf("plan() error = %v", err)
	}
	if len(changes) != 1 {
		t.Fatalf("len(changes) = %d, want 1", len(changes))
	}
	got := changes[0]

	if got.Address != "admin@vaderrp.com" || got.AccountID != "a1" || got.Secret != goodHash() {
		t.Errorf("change header = %q %q (secret match %t), want admin@vaderrp.com a1 and the SQL secret verbatim", got.Address, got.AccountID, got.Secret == goodHash())
	}

	want := map[string]any{
		"description":         "Site admin",
		"roles":               map[string]any{"@type": "Admin"},
		"quotas/maxDiskQuota": int64(2048),
		"aliases/8":           map[string]any{"enable": true, "name": "root", "domainId": "d1", "description": nil},
		"aliases/9":           map[string]any{"enable": true, "name": "admin", "domainId": "d2", "description": nil},
	}
	if !reflect.DeepEqual(got.Patch, want) {
		t.Fatalf("Patch = %#v, want %#v", got.Patch, want)
	}
}

func TestPlanFirstAliasKeyIsZero(t *testing.T) {
	t.Parallel()

	changes, err := plan(
		[]sqlAccount{{Name: "a@vaderrp.com", Secret: goodHash(), Aliases: []string{"b@vaderrp.com"}}},
		[]stalwart.Account{stalwartUser("a1", "a@vaderrp.com")}, testDomains)
	if err != nil {
		t.Fatalf("plan() error = %v", err)
	}
	if _, ok := changes[0].Patch["aliases/0"]; !ok {
		t.Fatalf("Patch = %#v, want aliases/0", changes[0].Patch)
	}
}

func TestPlanNeverDemotesAdmin(t *testing.T) {
	t.Parallel()

	account := stalwartUser("a1", "olli@erinko.fi")
	account.IsAdmin = true

	changes, err := plan(
		[]sqlAccount{{Name: "olli@erinko.fi", Secret: goodHash(), IsAdmin: false}},
		[]stalwart.Account{account}, testDomains)
	if err != nil {
		t.Fatalf("plan() error = %v", err)
	}
	if _, ok := changes[0].Patch["roles"]; ok {
		t.Fatalf("Patch = %#v, must not touch roles", changes[0].Patch)
	}

	// Already Admin and SQL admin: nothing to do either.
	changes, err = plan(
		[]sqlAccount{{Name: "olli@erinko.fi", Secret: goodHash(), IsAdmin: true}},
		[]stalwart.Account{account}, testDomains)
	if err != nil {
		t.Fatalf("plan() error = %v", err)
	}
	if len(changes[0].Patch) != 0 {
		t.Fatalf("Patch = %#v, want empty", changes[0].Patch)
	}
}

func TestPlanDescriptionAndQuotaOnlyWhenNeeded(t *testing.T) {
	t.Parallel()

	account := stalwartUser("a1", "a@vaderrp.com")
	account.Description = "Same"
	account.DiskQuota = 500

	changes, err := plan(
		[]sqlAccount{
			{Name: "a@vaderrp.com", Secret: goodHash(), Description: "Same", Quota: 500},
		}, []stalwart.Account{account}, testDomains)
	if err != nil {
		t.Fatalf("plan() error = %v", err)
	}
	if len(changes[0].Patch) != 0 {
		t.Fatalf("equal values: Patch = %#v, want empty", changes[0].Patch)
	}

	// Empty SQL description and zero SQL quota never overwrite Stalwart.
	changes, err = plan(
		[]sqlAccount{{Name: "a@vaderrp.com", Secret: goodHash()}},
		[]stalwart.Account{account}, testDomains)
	if err != nil {
		t.Fatalf("plan() error = %v", err)
	}
	if len(changes[0].Patch) != 0 {
		t.Fatalf("empty SQL values: Patch = %#v, want empty", changes[0].Patch)
	}
}

func TestMigrateMissingInternalAccount(t *testing.T) {
	t.Parallel()

	fake := newFakeStalwart(stalwartUser("a1", "a@vaderrp.com"))
	var out bytes.Buffer
	err := run(context.Background(), &out, []sqlAccount{
		{Name: "a@vaderrp.com", Secret: goodHash()},
		{Name: "ghost@vaderrp.com", Secret: goodHash()},
	}, fake.list(), testDomains, fake, true, nil)
	if err == nil || !strings.Contains(err.Error(), "ghost@vaderrp.com") {
		t.Fatalf("run() error = %v, want it to name ghost@vaderrp.com", err)
	}
	if fake.writes() != 0 {
		t.Fatalf("writes = %d, want 0", fake.writes())
	}
}

func TestMigrateGroupIsNotAUserMatch(t *testing.T) {
	t.Parallel()

	group := stalwartUser("g1", "a@vaderrp.com")
	group.Type = "Group"
	_, err := plan([]sqlAccount{{Name: "a@vaderrp.com", Secret: goodHash()}}, []stalwart.Account{group}, testDomains)
	if err == nil {
		t.Fatal("plan() error = nil, want missing-account error")
	}
}

func TestMigrateUnknownAliasDomain(t *testing.T) {
	t.Parallel()

	fake := newFakeStalwart(stalwartUser("a1", "a@vaderrp.com"))
	err := run(context.Background(), &bytes.Buffer{}, []sqlAccount{
		{Name: "a@vaderrp.com", Secret: goodHash(), Aliases: []string{"x@nowhere.example"}},
	}, fake.list(), testDomains, fake, true, nil)
	if err == nil || !strings.Contains(err.Error(), "nowhere.example") {
		t.Fatalf("run() error = %v, want unknown-domain error", err)
	}
	if fake.writes() != 0 {
		t.Fatalf("writes = %d, want 0", fake.writes())
	}
}

func TestMigrateRejectsMalformedHash(t *testing.T) {
	t.Parallel()

	const bad = "{SSHA512}not_base64-url"
	fake := newFakeStalwart(stalwartUser("a1", "a@vaderrp.com"), stalwartUser("a2", "b@vaderrp.com"))
	var out bytes.Buffer
	err := run(context.Background(), &out, []sqlAccount{
		{Name: "a@vaderrp.com", Secret: goodHash(), Description: "would change"},
		{Name: "b@vaderrp.com", Secret: bad},
	}, fake.list(), testDomains, fake, true, nil)
	if err == nil || !strings.Contains(err.Error(), "b@vaderrp.com") {
		t.Fatalf("run() error = %v, want it to name b@vaderrp.com", err)
	}
	if strings.Contains(err.Error(), bad) || strings.Contains(out.String(), bad) {
		t.Fatal("secret leaked into output")
	}
	if fake.writes() != 0 {
		t.Fatalf("writes = %d, want 0 (whole run must abort)", fake.writes())
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	t.Parallel()

	fake := newFakeStalwart(stalwartUser("a1", "a@vaderrp.com"), stalwartUser("a2", "b@vaderrp.com"))
	var out bytes.Buffer
	err := run(context.Background(), &out, []sqlAccount{
		{Name: "a@vaderrp.com", Secret: goodHash(), Description: "A"},
		{Name: "b@vaderrp.com", Secret: goodHash()},
	}, fake.list(), testDomains, fake, false, nil)
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if fake.writes() != 0 {
		t.Fatalf("writes = %d, want 0", fake.writes())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if lines[0] != "a@vaderrp.com: would update (description, secret)" {
		t.Errorf("line 0 = %q", lines[0])
	}
	if lines[1] != "b@vaderrp.com: unchanged" {
		t.Errorf("line 1 = %q", lines[1])
	}
	if strings.Contains(out.String(), goodHash()) {
		t.Error("secret printed")
	}
}

func TestApplyWritesPatchThenSecret(t *testing.T) {
	t.Parallel()

	fake := newFakeStalwart(stalwartUser("a1", "a@vaderrp.com"), stalwartUser("a2", "b@vaderrp.com"))
	var out bytes.Buffer
	err := run(context.Background(), &out, []sqlAccount{
		{Name: "a@vaderrp.com", Secret: goodHash(), Description: "A"},
		{Name: "b@vaderrp.com", Secret: goodHash()},
	}, fake.list(), testDomains, fake, true, nil)
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}

	if want := []string{"update a1", "password a1", "password a2"}; !reflect.DeepEqual(fake.calls, want) {
		t.Fatalf("calls = %v, want %v", fake.calls, want)
	}
	if fake.passwords["a1"] != goodHash() {
		t.Error("secret for a1 not passed through verbatim")
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if lines[0] != "a@vaderrp.com: updated (description, secret)" {
		t.Errorf("line 0 = %q", lines[0])
	}
	if lines[1] != "b@vaderrp.com: unchanged" {
		t.Errorf("line 1 = %q", lines[1])
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	t.Parallel()

	fake := newFakeStalwart(stalwartUser("a1", "admin@vaderrp.com"), stalwartUser("a2", "b@erinko.fi"))
	sqlAccts := []sqlAccount{
		{Name: "admin@vaderrp.com", Secret: goodHash(), Description: "Admin", Quota: 99, IsAdmin: true,
			Aliases: []string{"root@vaderrp.com", "r@erinko.fi"}},
		{Name: "b@erinko.fi", Secret: goodHash(), Description: "B"},
	}

	if err := run(context.Background(), &bytes.Buffer{}, sqlAccts, fake.list(), testDomains, fake, true, nil); err != nil {
		t.Fatalf("first run() error = %v", err)
	}

	changes, err := plan(sqlAccts, fake.list(), testDomains)
	if err != nil {
		t.Fatalf("second plan() error = %v", err)
	}
	for _, c := range changes {
		if len(c.Patch) != 0 {
			t.Errorf("%s: second plan Patch = %#v, want empty", c.Address, c.Patch)
		}
	}

	var out bytes.Buffer
	if err := run(context.Background(), &out, sqlAccts, fake.list(), testDomains, fake, false, nil); err != nil {
		t.Fatalf("second run() error = %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if !strings.HasSuffix(line, ": unchanged") {
			t.Errorf("second run line = %q, want unchanged", line)
		}
	}
}

func TestOnlyLimitsPlanAndApply(t *testing.T) {
	t.Parallel()

	fake := newFakeStalwart(stalwartUser("a1", "a@vaderrp.com"), stalwartUser("a2", "b@vaderrp.com"))
	var out bytes.Buffer
	err := run(context.Background(), &out, []sqlAccount{
		{Name: "a@vaderrp.com", Secret: goodHash()},
		{Name: "b@vaderrp.com", Secret: "garbage"},
	}, fake.list(), testDomains, fake, true, []string{" B@vaderrp.com"})
	if err == nil {
		t.Fatal("run() with --only b, whose hash is bad: want error")
	}
	if fake.writes() != 0 {
		t.Fatalf("writes = %d, want 0 after the aborted run", fake.writes())
	}

	err = run(context.Background(), &out, []sqlAccount{
		{Name: "a@vaderrp.com", Secret: goodHash()},
		{Name: "b@vaderrp.com", Secret: "garbage"}, // outside --only, so its bad hash is never examined
	}, fake.list(), testDomains, fake, true, []string{"A@vaderrp.com"})
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if want := []string{"password a1"}; !reflect.DeepEqual(fake.calls, want) {
		t.Fatalf("calls = %v, want %v", fake.calls, want)
	}
}

func TestOnlyUnknownAddress(t *testing.T) {
	t.Parallel()

	fake := newFakeStalwart(stalwartUser("a1", "a@vaderrp.com"))
	err := run(context.Background(), &bytes.Buffer{}, []sqlAccount{{Name: "a@vaderrp.com", Secret: goodHash()}},
		fake.list(), testDomains, fake, true, []string{"typo@vaderrp.com"})
	if err == nil || !strings.Contains(err.Error(), "typo@vaderrp.com") {
		t.Fatalf("run() error = %v, want unknown --only error", err)
	}
	if fake.writes() != 0 {
		t.Fatalf("writes = %d, want 0", fake.writes())
	}
}

func TestApplyStopsAtFirstWriteError(t *testing.T) {
	t.Parallel()

	fake := newFakeStalwart(stalwartUser("a1", "a@vaderrp.com"), stalwartUser("a2", "b@vaderrp.com"))
	fake.failPassword = "a1"
	err := run(context.Background(), &bytes.Buffer{}, []sqlAccount{
		{Name: "a@vaderrp.com", Secret: goodHash()},
		{Name: "b@vaderrp.com", Secret: goodHash()},
	}, fake.list(), testDomains, fake, true, nil)
	if err == nil || !strings.Contains(err.Error(), "a@vaderrp.com") {
		t.Fatalf("run() error = %v, want it to name a@vaderrp.com", err)
	}
	if _, ok := fake.passwords["a2"]; ok {
		t.Error("continued past a failed write")
	}
}

// fakeStalwart applies patches to in-memory accounts, enough for the
// idempotence check, and records every write.
type fakeStalwart struct {
	accounts     []stalwart.Account
	calls        []string
	passwords    map[string]string
	failPassword string
}

func newFakeStalwart(accounts ...stalwart.Account) *fakeStalwart {
	return &fakeStalwart{accounts: accounts, passwords: map[string]string{}}
}

func (f *fakeStalwart) list() []stalwart.Account {
	out := make([]stalwart.Account, len(f.accounts))
	copy(out, f.accounts)
	return out
}

func (f *fakeStalwart) writes() int { return len(f.calls) }

func (f *fakeStalwart) UpdateAccount(_ context.Context, id string, patch map[string]any) error {
	f.calls = append(f.calls, "update "+id)
	for i := range f.accounts {
		if f.accounts[i].ID != id {
			continue
		}
		a := &f.accounts[i]
		aliases := map[string]stalwart.Alias{}
		for k, v := range a.Aliases {
			aliases[k] = v
		}
		a.Aliases = aliases
		for key, value := range patch {
			switch {
			case key == "description":
				a.Description = value.(string)
			case key == "roles":
				a.IsAdmin = value.(map[string]any)["@type"] == "Admin"
			case key == "quotas/maxDiskQuota":
				a.DiskQuota = value.(int64)
			case strings.HasPrefix(key, "aliases/"):
				entry := value.(map[string]any)
				a.Aliases[strings.TrimPrefix(key, "aliases/")] = stalwart.Alias{
					Name: entry["name"].(string), DomainID: entry["domainId"].(string),
				}
			default:
				return errors.New("unexpected patch key " + strconv.Quote(key))
			}
		}
	}
	return nil
}

func (f *fakeStalwart) SetPassword(_ context.Context, account stalwart.Account, secret string) error {
	f.calls = append(f.calls, "password "+account.ID)
	if account.ID == f.failPassword {
		return errors.New("rejected")
	}
	f.passwords[account.ID] = secret
	return nil
}

func TestPlanAliasOwnedByAnotherStalwartAccount(t *testing.T) {
	t.Parallel()

	a := stalwartUser("a1", "a@vaderrp.com")
	b := stalwartUser("a2", "b@vaderrp.com")
	b.Aliases = map[string]stalwart.Alias{"0": {Name: "shared", DomainID: "d1"}}
	group := stalwartUser("g1", "team@vaderrp.com")
	group.Type = "Group"

	for name, alias := range map[string]string{
		"another user's alias":   "Shared@vaderrp.com",
		"another user's address": "b@vaderrp.com",
		"a group's address":      "team@vaderrp.com",
	} {
		_, err := plan(
			[]sqlAccount{{Name: "a@vaderrp.com", Secret: goodHash(), Aliases: []string{alias}}},
			[]stalwart.Account{a, b, group}, testDomains)
		if err == nil || !strings.Contains(err.Error(), "a@vaderrp.com") || !strings.Contains(err.Error(), strings.ToLower(alias)) {
			t.Errorf("%s: plan() error = %v, want it to name the account and alias", name, err)
		}
	}
}

func TestPlanAliasOnTwoSQLAccounts(t *testing.T) {
	t.Parallel()

	fake := newFakeStalwart(stalwartUser("a1", "a@vaderrp.com"), stalwartUser("a2", "b@vaderrp.com"))
	err := run(context.Background(), &bytes.Buffer{}, []sqlAccount{
		{Name: "a@vaderrp.com", Secret: goodHash(), Aliases: []string{"x@vaderrp.com"}},
		{Name: "b@vaderrp.com", Secret: goodHash(), Aliases: []string{"X@vaderrp.com"}},
	}, fake.list(), testDomains, fake, true, nil)
	if err == nil || !strings.Contains(err.Error(), "x@vaderrp.com") {
		t.Fatalf("run() error = %v, want duplicate-alias error", err)
	}
	if fake.writes() != 0 {
		t.Fatalf("writes = %d, want 0", fake.writes())
	}
}

func TestPlanAliasAlreadyOnOwnAccountIsFine(t *testing.T) {
	t.Parallel()

	a := stalwartUser("a1", "a@vaderrp.com")
	a.Aliases = map[string]stalwart.Alias{"0": {Name: "x", DomainID: "d1"}}
	changes, err := plan(
		[]sqlAccount{{Name: "a@vaderrp.com", Secret: goodHash(), Aliases: []string{"x@vaderrp.com"}}},
		[]stalwart.Account{a}, testDomains)
	if err != nil {
		t.Fatalf("plan() error = %v", err)
	}
	if len(changes[0].Patch) != 0 {
		t.Fatalf("Patch = %#v, want empty", changes[0].Patch)
	}
}

func TestPlanDuplicateCanonicalSQLName(t *testing.T) {
	t.Parallel()

	_, err := plan([]sqlAccount{
		{Name: "a@vaderrp.com", Secret: goodHash()},
		{Name: " A@Vaderrp.com", Secret: goodHash()},
	}, []stalwart.Account{stalwartUser("a1", "a@vaderrp.com")}, testDomains)
	if err == nil || !strings.Contains(err.Error(), "a@vaderrp.com") {
		t.Fatalf("plan() error = %v, want duplicate-name error", err)
	}
}
