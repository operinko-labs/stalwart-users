package directory

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/operinko-labs/stalwart-users/internal/db"
	"github.com/operinko-labs/stalwart-users/internal/stalwart"
)

type fakeClient struct {
	accounts []stalwart.Account

	created struct {
		name, password, description string
		quota                       int64
	}
	createCalls int
	updatedID   string
	patch       map[string]any
	updateCalls int
	deleted     []string
}

func (f *fakeClient) ListAccounts(context.Context) ([]stalwart.Account, error) {
	return f.accounts, nil
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
		{ID: "a1", Type: "User", Name: "dora", Email: "Dora@client.fi", Description: "Dora D", DiskQuota: 1024},
		{ID: "a2", Type: "User", Name: "root", Email: "root@vaderrp.com", IsAdmin: true},
		{ID: "g1", Type: "Group", Name: "team", Email: "team@client.fi"},
	}}
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
