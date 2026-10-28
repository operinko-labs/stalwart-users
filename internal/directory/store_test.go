package directory

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/operinko-labs/stalwart-users/internal/db"
	"github.com/operinko-labs/stalwart-users/internal/model"
	"github.com/operinko-labs/stalwart-users/internal/stalwart"
)

type fakeClient struct {
	accounts []stalwart.Account
	domains  []stalwart.Domain

	created struct {
		name, password, description string
		quota                       int64
	}
	createCalls int
	updatedID   string
	patch       map[string]any
	updateCalls int
	deleted     []string

	authOK       bool
	authSeen     [2]string
	passwordFor  stalwart.Account
	passwordSent string
	passwordErr  error
}

func (f *fakeClient) Authenticate(_ context.Context, username, password string) (bool, error) {
	f.authSeen = [2]string{username, password}
	return f.authOK, nil
}

func (f *fakeClient) SetPassword(_ context.Context, account stalwart.Account, secret string) error {
	f.passwordFor, f.passwordSent = account, secret
	return f.passwordErr
}

func (f *fakeClient) ListAccounts(context.Context) ([]stalwart.Account, error) {
	return f.accounts, nil
}

func (f *fakeClient) ListDomains(context.Context) ([]stalwart.Domain, error) {
	return f.domains, nil
}

func (f *fakeClient) CreateAccount(_ context.Context, name, password, description string, quota int64) error {
	f.createCalls++
	f.created.name, f.created.password, f.created.description, f.created.quota = name, password, description, quota
	return nil
}

func (f *fakeClient) UpdateAccount(_ context.Context, id string, patch map[string]any) error {
	f.updateCalls++
	f.updatedID, f.patch = id, patch
	return nil
}

func (f *fakeClient) DeleteAccount(_ context.Context, name string) error {
	f.deleted = append(f.deleted, name)
	return nil
}

type fakeAdmins struct {
	domains map[string][]string
	set     map[string][]string
	deleted []string
}

func (f *fakeAdmins) ListAdminDomains(name string) ([]string, error) { return f.domains[name], nil }
func (f *fakeAdmins) SetAdminDomains(name string, domains []string) error {
	if f.set == nil {
		f.set = map[string][]string{}
	}
	f.set[name] = domains
	return nil
}
func (f *fakeAdmins) DeleteAdminDomains(name string) error {
	f.deleted = append(f.deleted, name)
	return nil
}

func newStore() (*Store, *fakeClient, *fakeAdmins) {
	client := &fakeClient{accounts: []stalwart.Account{
		{
			ID: "a1", Type: "User", Name: "dora", Email: "Dora@client.fi", Description: "Dora D", DiskQuota: 1024,
			Aliases: map[string]stalwart.Alias{
				"0": {Name: "sales", DomainID: "j"},
				"3": {Name: "hello", DomainID: "v"},
			},
			MemberGroupIDs: []string{"g1"},
		},
		{ID: "a2", Type: "User", Name: "root", Email: "root@vaderrp.com", IsAdmin: true, Aliases: map[string]stalwart.Alias{"0": {Name: "postmaster", DomainID: "v"}}},
		{ID: "g1", Type: "Group", Name: "team", Email: "team@client.fi"},
		{ID: "g2", Type: "Group", Name: "staff", Email: "staff@client.fi"},
	}, domains: []stalwart.Domain{{ID: "j", Name: "client.fi"}, {ID: "v", Name: "vaderrp.com"}}}
	admins := &fakeAdmins{}
	return New(client, admins), client, admins
}

func TestListAccountsMapsModel(t *testing.T) {
	t.Parallel()

	store, _, _ := newStore()
	got, err := store.ListAccounts()
	if err != nil {
		t.Fatalf("ListAccounts() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (users only): %#v", len(got), got)
	}
	if got[0].Name != "Dora@client.fi" || got[0].Description != "Dora D" || got[0].Type != "individual" || got[0].Quota != 1024 || !got[0].Active || got[0].IsAdmin {
		t.Fatalf("got[0] = %#v", got[0])
	}
	if !got[1].IsAdmin {
		t.Fatalf("got[1].IsAdmin = false, want true")
	}
}

func TestGetAccountFindsCaseInsensitively(t *testing.T) {
	t.Parallel()

	store, _, _ := newStore()
	got, err := store.GetAccount("dora@CLIENT.fi")
	if err != nil || got == nil || got.Description != "Dora D" {
		t.Fatalf("GetAccount() = %#v, %v", got, err)
	}
}

func TestGetAccountMissing(t *testing.T) {
	t.Parallel()

	store, _, _ := newStore()
	for _, name := range []string{"nobody@client.fi", "team@client.fi"} {
		got, err := store.GetAccount(name)
		if got != nil || err != nil {
			t.Fatalf("GetAccount(%q) = %#v, %v; want nil, nil", name, got, err)
		}
	}
}

func TestCreateAccountPassesPlaintext(t *testing.T) {
	t.Parallel()

	store, client, _ := newStore()
	if err := store.CreateAccount("new@client.fi", "hunter2-Long!", "New", "individual", 2048); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}
	c := client.created
	if c.name != "new@client.fi" || c.password != "hunter2-Long!" || c.description != "New" || c.quota != 2048 {
		t.Fatalf("created = %#v", c)
	}
}

func TestCreateGroupUnsupported(t *testing.T) {
	t.Parallel()

	store, client, _ := newStore()
	err := store.CreateAccount("g@client.fi", "pw", "", "group", 0)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if client.createCalls != 0 {
		t.Fatal("client.CreateAccount called for a group")
	}
}

func TestUpdateAccountQuotaPatch(t *testing.T) {
	t.Parallel()

	store, client, _ := newStore()
	zero, size, desc := 0, 4096, "Changed"

	if err := store.UpdateAccount("dora@client.fi", nil, &zero, nil); err != nil {
		t.Fatalf("UpdateAccount() error = %v", err)
	}
	if client.updatedID != "a1" || !reflect.DeepEqual(client.patch, map[string]any{"quotas": map[string]any{}}) {
		t.Fatalf("id = %q, patch = %#v", client.updatedID, client.patch)
	}

	if err := store.UpdateAccount("dora@client.fi", &desc, &size, nil); err != nil {
		t.Fatalf("UpdateAccount() error = %v", err)
	}
	want := map[string]any{"description": "Changed", "quotas": map[string]any{"maxDiskQuota": int64(4096)}}
	if !reflect.DeepEqual(client.patch, want) {
		t.Fatalf("patch = %#v, want %#v", client.patch, want)
	}
}

func TestUpdateAccountActiveTrueIsNoop(t *testing.T) {
	t.Parallel()

	store, client, _ := newStore()
	active := true
	if err := store.UpdateAccount("dora@client.fi", nil, nil, &active); err != nil {
		t.Fatalf("UpdateAccount() error = %v", err)
	}
	if client.updateCalls != 0 {
		t.Fatal("empty patch was sent")
	}
}

func TestUpdateAccountDeactivateUnsupported(t *testing.T) {
	t.Parallel()

	store, client, _ := newStore()
	active := false
	err := store.UpdateAccount("dora@client.fi", nil, nil, &active)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if client.updateCalls != 0 {
		t.Fatal("client.UpdateAccount called")
	}
}

func TestUpdateAccountUnknown(t *testing.T) {
	t.Parallel()

	store, client, _ := newStore()
	desc := "x"
	if err := store.UpdateAccount("nobody@client.fi", &desc, nil, nil); !errors.Is(err, db.ErrAccountNotFound) {
		t.Fatalf("err = %v, want ErrAccountNotFound", err)
	}
	if client.updateCalls != 0 {
		t.Fatal("client.UpdateAccount called")
	}
}

func TestDeleteAccountRemovesAdminDomains(t *testing.T) {
	t.Parallel()

	store, client, admins := newStore()
	if err := store.DeleteAccount("dora@client.fi"); err != nil {
		t.Fatalf("DeleteAccount() error = %v", err)
	}
	if !reflect.DeepEqual(client.deleted, []string{"Dora@client.fi"}) || !reflect.DeepEqual(admins.deleted, []string{"dora@client.fi"}) {
		t.Fatalf("client.deleted = %v, admins.deleted = %v", client.deleted, admins.deleted)
	}
}

func TestDeleteAccountUnknown(t *testing.T) {
	t.Parallel()

	store, client, admins := newStore()
	if err := store.DeleteAccount("nobody@client.fi"); !errors.Is(err, db.ErrAccountNotFound) {
		t.Fatalf("err = %v, want ErrAccountNotFound", err)
	}
	if len(client.deleted) != 0 || len(admins.deleted) != 0 {
		t.Fatal("something was deleted")
	}
}

func TestIsAdminFromRoles(t *testing.T) {
	t.Parallel()

	store, _, _ := newStore()
	for name, want := range map[string]bool{"root@vaderrp.com": true, "dora@client.fi": false, "nobody@client.fi": false} {
		got, err := store.IsAdmin(name)
		if err != nil || got != want {
			t.Fatalf("IsAdmin(%q) = %v, %v; want %v", name, got, err, want)
		}
	}
}

func TestAdminDomainsDelegate(t *testing.T) {
	t.Parallel()

	store, _, admins := newStore()
	admins.domains = map[string][]string{"dora@client.fi": {"client.fi"}}

	got, err := store.ListAdminDomains("dora@client.fi")
	if err != nil || !reflect.DeepEqual(got, []string{"client.fi"}) {
		t.Fatalf("ListAdminDomains() = %v, %v", got, err)
	}
	if err := store.SetAdminDomains("dora@client.fi", []string{"a.fi"}); err != nil || !reflect.DeepEqual(admins.set["dora@client.fi"], []string{"a.fi"}) {
		t.Fatalf("SetAdminDomains() err = %v, set = %v", err, admins.set)
	}
}

func TestListEmailsPrimaryFirst(t *testing.T) {
	t.Parallel()

	store, _, _ := newStore()
	got, err := store.ListEmails("dora@client.fi")
	if err != nil {
		t.Fatalf("ListEmails() error = %v", err)
	}
	want := []model.Email{
		{Name: "Dora@client.fi", Address: "Dora@client.fi", Type: "primary"},
		{Name: "Dora@client.fi", Address: "hello@vaderrp.com", Type: "alias"},
		{Name: "Dora@client.fi", Address: "sales@client.fi", Type: "alias"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ListEmails() = %#v, want %#v", got, want)
	}
}

func TestListEmailsUnknownAccount(t *testing.T) {
	t.Parallel()

	store, _, _ := newStore()
	if _, err := store.ListEmails("nobody@client.fi"); !errors.Is(err, db.ErrAccountNotFound) {
		t.Fatalf("err = %v, want ErrAccountNotFound", err)
	}
}

func TestInsertEmailAddsAlias(t *testing.T) {
	t.Parallel()

	store, client, _ := newStore()
	if err := store.InsertEmail("dora@client.fi", "info@CLIENT.fi", "alias"); err != nil {
		t.Fatalf("InsertEmail() error = %v", err)
	}
	want := map[string]any{"aliases/4": map[string]any{"enable": true, "name": "info", "domainId": "j", "description": nil}}
	if client.updatedID != "a1" || !reflect.DeepEqual(client.patch, want) {
		t.Fatalf("id = %q, patch = %#v, want %#v", client.updatedID, client.patch, want)
	}
}

func TestInsertEmailFirstAliasKeyIsZero(t *testing.T) {
	t.Parallel()

	store, client, _ := newStore()
	client.accounts[0].Aliases = nil
	if err := store.InsertEmail("dora@client.fi", "info@client.fi", ""); err != nil {
		t.Fatalf("InsertEmail() error = %v", err)
	}
	if _, ok := client.patch["aliases/0"]; !ok {
		t.Fatalf("patch = %#v, want aliases/0", client.patch)
	}
}

func TestInsertEmailUnknownDomain(t *testing.T) {
	t.Parallel()

	store, client, _ := newStore()
	err := store.InsertEmail("dora@client.fi", "info@elsewhere.org", "alias")
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "elsewhere.org") {
		t.Fatalf("err = %v, want ErrUnsupported naming the domain", err)
	}
	if client.updateCalls != 0 {
		t.Fatal("client.UpdateAccount called")
	}
}

func TestInsertEmailUnsupportedType(t *testing.T) {
	t.Parallel()

	store, client, _ := newStore()
	if err := store.InsertEmail("dora@client.fi", "info@client.fi", "primary"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if client.updateCalls != 0 {
		t.Fatal("client.UpdateAccount called")
	}
}

func TestInsertEmailInUse(t *testing.T) {
	t.Parallel()

	store, client, _ := newStore()
	for _, address := range []string{"POSTMASTER@vaderrp.com", "root@vaderrp.com", "team@client.fi", "sales@client.fi"} {
		if err := store.InsertEmail("dora@client.fi", address, "alias"); !errors.Is(err, ErrAddressInUse) {
			t.Fatalf("InsertEmail(%q) err = %v, want ErrAddressInUse", address, err)
		}
	}
	if client.updateCalls != 0 {
		t.Fatal("client.UpdateAccount called")
	}
}

func TestInsertEmailUnknownAccount(t *testing.T) {
	t.Parallel()

	store, _, _ := newStore()
	if err := store.InsertEmail("nobody@client.fi", "info@client.fi", "alias"); !errors.Is(err, db.ErrAccountNotFound) {
		t.Fatalf("err = %v, want ErrAccountNotFound", err)
	}
}

func TestGetEmailType(t *testing.T) {
	t.Parallel()

	store, _, _ := newStore()
	for address, want := range map[string]string{
		"dora@client.fi":    "primary",
		"SALES@client.fi":   "alias",
		"root@vaderrp.com":  "",
		"unknown@client.fi": "",
	} {
		got, err := store.GetEmailType("dora@client.fi", address)
		if err != nil || got != want {
			t.Fatalf("GetEmailType(%q) = %q, %v; want %q", address, got, err, want)
		}
	}
}

func TestDeleteEmailRemovesAlias(t *testing.T) {
	t.Parallel()

	store, client, _ := newStore()
	if err := store.DeleteEmail("dora@client.fi", "Hello@vaderrp.com"); err != nil {
		t.Fatalf("DeleteEmail() error = %v", err)
	}
	if client.updatedID != "a1" || !reflect.DeepEqual(client.patch, map[string]any{"aliases/3": nil}) {
		t.Fatalf("id = %q, patch = %#v", client.updatedID, client.patch)
	}
}

func TestDeleteEmailPrimaryUnsupported(t *testing.T) {
	t.Parallel()

	store, client, _ := newStore()
	if err := store.DeleteEmail("dora@client.fi", "dora@client.fi"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if client.updateCalls != 0 {
		t.Fatal("client.UpdateAccount called")
	}
}

func TestDeleteEmailAbsentIsNoop(t *testing.T) {
	t.Parallel()

	store, client, _ := newStore()
	if err := store.DeleteEmail("dora@client.fi", "nothing@client.fi"); err != nil {
		t.Fatalf("DeleteEmail() error = %v", err)
	}
	if client.updateCalls != 0 {
		t.Fatal("client.UpdateAccount called")
	}
}

func TestAddressInUseCaseInsensitive(t *testing.T) {
	t.Parallel()

	store, _, _ := newStore()
	for address, want := range map[string]bool{
		"DORA@client.fi":         true,
		"Postmaster@VADERRP.com": true,
		"team@client.fi":         true,
		"free@client.fi":         false,
	} {
		got, err := store.AddressInUse(address)
		if err != nil || got != want {
			t.Fatalf("AddressInUse(%q) = %v, %v; want %v", address, got, err, want)
		}
	}
}

func TestListGroupsMapsIDsToAddresses(t *testing.T) {
	t.Parallel()

	store, client, _ := newStore()
	client.accounts[0].MemberGroupIDs = []string{"g2", "g1", "gone"}
	got, err := store.ListGroups("dora@client.fi")
	if err != nil || !reflect.DeepEqual(got, []string{"staff@client.fi", "team@client.fi"}) {
		t.Fatalf("ListGroups() = %v, %v", got, err)
	}
}

func TestListGroupsUnknownAccount(t *testing.T) {
	t.Parallel()

	store, _, _ := newStore()
	if _, err := store.ListGroups("nobody@client.fi"); !errors.Is(err, db.ErrAccountNotFound) {
		t.Fatalf("err = %v, want ErrAccountNotFound", err)
	}
}

func TestAddGroup(t *testing.T) {
	t.Parallel()

	store, client, _ := newStore()
	if err := store.AddGroup("dora@client.fi", "STAFF@client.fi"); err != nil {
		t.Fatalf("AddGroup() error = %v", err)
	}
	if client.updatedID != "a1" || !reflect.DeepEqual(client.patch, map[string]any{"memberGroupIds/g2": true}) {
		t.Fatalf("id = %q, patch = %#v", client.updatedID, client.patch)
	}
}

func TestAddGroupAlreadyMember(t *testing.T) {
	t.Parallel()

	store, client, _ := newStore()
	if err := store.AddGroup("dora@client.fi", "team@client.fi"); err != nil {
		t.Fatalf("AddGroup() error = %v", err)
	}
	if client.updateCalls != 0 {
		t.Fatal("client.UpdateAccount called")
	}
}

func TestAddGroupUnknownGroup(t *testing.T) {
	t.Parallel()

	store, client, _ := newStore()
	for _, group := range []string{"nogroup@client.fi", "root@vaderrp.com"} {
		err := store.AddGroup("dora@client.fi", group)
		if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), group) {
			t.Fatalf("AddGroup(%q) err = %v, want ErrUnsupported naming the group", group, err)
		}
	}
	if client.updateCalls != 0 {
		t.Fatal("client.UpdateAccount called")
	}
}

func TestRemoveGroup(t *testing.T) {
	t.Parallel()

	store, client, _ := newStore()
	if err := store.RemoveGroup("dora@client.fi", "Team@client.fi"); err != nil {
		t.Fatalf("RemoveGroup() error = %v", err)
	}
	if client.updatedID != "a1" || !reflect.DeepEqual(client.patch, map[string]any{"memberGroupIds/g1": nil}) {
		t.Fatalf("id = %q, patch = %#v", client.updatedID, client.patch)
	}
}

func TestRemoveGroupMissing(t *testing.T) {
	t.Parallel()

	store, client, _ := newStore()
	for _, group := range []string{"staff@client.fi", "nogroup@client.fi"} {
		if err := store.RemoveGroup("dora@client.fi", group); !errors.Is(err, db.ErrGroupMembershipNotFound) {
			t.Fatalf("RemoveGroup(%q) err = %v, want ErrGroupMembershipNotFound", group, err)
		}
	}
	if client.updateCalls != 0 {
		t.Fatal("client.UpdateAccount called")
	}
}

func TestAuthenticateDelegates(t *testing.T) {
	t.Parallel()

	store, client, _ := newStore()
	client.authOK = true
	ok, err := store.Authenticate(context.Background(), "dora@client.fi", "pw")
	if err != nil || !ok {
		t.Fatalf("Authenticate() = %v, %v; want true, nil", ok, err)
	}
	if client.authSeen != [2]string{"dora@client.fi", "pw"} {
		t.Fatalf("client saw %v", client.authSeen)
	}
}

func TestSetPasswordFindsAccount(t *testing.T) {
	t.Parallel()

	store, client, _ := newStore()
	if err := store.SetPassword("dora@CLIENT.fi", "new-Password-1"); err != nil {
		t.Fatalf("SetPassword() error = %v", err)
	}
	if client.passwordFor.ID != "a1" || client.passwordSent != "new-Password-1" {
		t.Fatalf("SetPassword sent %q for %#v", client.passwordSent, client.passwordFor)
	}
}

func TestSetPasswordPassesInvalid(t *testing.T) {
	t.Parallel()

	store, client, _ := newStore()
	client.passwordErr = fmt.Errorf("update account: %w", stalwart.ErrInvalid{Description: "Password is too weak"})
	var invalid stalwart.ErrInvalid
	if err := store.SetPassword("dora@client.fi", "x"); !errors.As(err, &invalid) || invalid.Description != "Password is too weak" {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

func TestSetPasswordUnknown(t *testing.T) {
	t.Parallel()

	store, client, _ := newStore()
	if err := store.SetPassword("team@client.fi", "pw"); !errors.Is(err, db.ErrAccountNotFound) {
		t.Fatalf("err = %v, want ErrAccountNotFound", err)
	}
	if client.passwordSent != "" {
		t.Fatal("client.SetPassword called")
	}
}

func TestMixedCaseNamesUseCanonicalName(t *testing.T) {
	t.Parallel()

	store, client, admins := newStore()
	admins.domains = map[string][]string{"dora@client.fi": {"client.fi", "other.fi"}}

	domains, err := store.ListAdminDomains(" Dora@CLIENT.fi")
	if err != nil || !reflect.DeepEqual(domains, []string{"client.fi", "other.fi"}) {
		t.Fatalf("ListAdminDomains() = %v, %v; want the canonical account's domains", domains, err)
	}
	if isAdmin, err := store.IsAdmin("Root@VaderRP.com"); err != nil || !isAdmin {
		t.Fatalf("IsAdmin() = %v, %v; want true", isAdmin, err)
	}
	if err := store.SetAdminDomains("Dora@Client.fi", []string{"client.fi"}); err != nil {
		t.Fatalf("SetAdminDomains() error = %v", err)
	}
	if _, ok := admins.set["dora@client.fi"]; !ok || len(admins.set) != 1 {
		t.Fatalf("SetAdminDomains wrote %v, want key dora@client.fi", admins.set)
	}
	if _, err := store.Authenticate(context.Background(), " Dora@Client.FI ", "pw"); err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if client.authSeen[0] != "dora@client.fi" {
		t.Fatalf("Authenticate sent %q, want dora@client.fi", client.authSeen[0])
	}
}

func TestDeleteAccountMixedCaseRemovesCanonicalAdminDomains(t *testing.T) {
	t.Parallel()

	store, _, admins := newStore()
	if err := store.DeleteAccount("Dora@CLIENT.fi"); err != nil {
		t.Fatalf("DeleteAccount() error = %v", err)
	}
	if !reflect.DeepEqual(admins.deleted, []string{"dora@client.fi"}) {
		t.Fatalf("admins.deleted = %v, want [dora@client.fi]", admins.deleted)
	}
}

func TestFoldingVariantsDoNotMatch(t *testing.T) {
	t.Parallel()

	store, client, _ := newStore()
	client.accounts = append(client.accounts, stalwart.Account{ID: "s1", Type: "User", Name: "sam", Email: "sam@client.fi"})

	// U+017F (long s) case-folds to "s" but does not lower-case to it.
	if got, err := store.GetAccount("ſam@client.fi"); got != nil || err != nil {
		t.Fatalf("GetAccount() = %#v, %v; want nil, nil", got, err)
	}
	if isAdmin, err := store.IsAdmin("ſam@client.fi"); isAdmin || err != nil {
		t.Fatalf("IsAdmin() = %v, %v; want false, nil", isAdmin, err)
	}
	if err := store.SetPassword("ſam@client.fi", "pw"); !errors.Is(err, db.ErrAccountNotFound) {
		t.Fatalf("SetPassword() err = %v, want ErrAccountNotFound", err)
	}
	if got, err := store.GetEmailType("dora@client.fi", "ſales@client.fi"); got != "" || err != nil {
		t.Fatalf("GetEmailType() = %q, %v; want empty", got, err)
	}
	if inUse, err := store.AddressInUse("ſam@client.fi"); inUse || err != nil {
		t.Fatalf("AddressInUse() = %v, %v; want false", inUse, err)
	}
	if err := store.DeleteEmail("dora@client.fi", "ſales@client.fi"); err != nil || client.updateCalls != 0 {
		t.Fatalf("DeleteEmail() err = %v, updates = %d; want no-op", err, client.updateCalls)
	}
}
