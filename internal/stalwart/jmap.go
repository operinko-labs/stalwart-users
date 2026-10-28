package stalwart

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
)

const (
	jmapCoreCapability     = "urn:ietf:params:jmap:core"
	jmapStalwartCapability = "urn:stalwart:jmap"
)

type Client struct {
	baseURL    string
	adminToken string
	httpClient *http.Client
}

type jmapRequest struct {
	Using       []string         `json:"using"`
	MethodCalls []jmapMethodCall `json:"methodCalls"`
}

type jmapMethodCall []any

type jmapResponse struct {
	MethodResponses []jmapMethodResponse `json:"methodResponses"`
}

type jmapMethodResponse []json.RawMessage

type jmapError struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

type jmapQueryResponse struct {
	IDs []string `json:"ids"`
}

type jmapSetResponse struct {
	Created      map[string]jmapCreatedObject `json:"created"`
	Updated      map[string]json.RawMessage   `json:"updated"`
	Destroyed    []string                     `json:"destroyed"`
	NotCreated   map[string]jmapError         `json:"notCreated"`
	NotUpdated   map[string]jmapError         `json:"notUpdated"`
	NotDestroyed map[string]jmapError         `json:"notDestroyed"`
}

// ErrInvalid wraps Stalwart's notCreated/notUpdated "invalidProperties" and
// "invalidPatch" errors. Its Error() is Stalwart's description so handlers can
// return it to the caller as a 400.
type ErrInvalid struct{ Description string }

func (e ErrInvalid) Error() string { return e.Description }

type jmapCreatedObject struct {
	ID string `json:"id"`
}

type Alias struct{ Name, DomainID string }

type Account struct {
	ID, Type, Name, DomainID, Email, Description string           // Type: "User" | "Group"
	Aliases                                      map[string]Alias // keyed by Stalwart list key
	IsAdmin                                      bool             // roles["@type"] == "Admin"
	DiskQuota                                    int64            // quotas["maxDiskQuota"], 0 if absent
	MemberGroupIDs                               []string
	PasswordKey                                  string // list key of the Password credential, "" if none
}

type Domain struct{ ID, Name string }

type jmapAccountObject struct {
	ID           string `json:"id"`
	Type         string `json:"@type"`
	Name         string `json:"name"`
	DomainID     string `json:"domainId"`
	EmailAddress string `json:"emailAddress"`
	Description  string `json:"description"`
	Roles        struct {
		Type string `json:"@type"`
	} `json:"roles"`
	Quotas  map[string]any `json:"quotas"`
	Aliases map[string]struct {
		Name     string `json:"name"`
		DomainID string `json:"domainId"`
	} `json:"aliases"`
	MemberGroupIDs map[string]bool `json:"memberGroupIds"`
	Credentials    map[string]struct {
		Type string `json:"@type"`
	} `json:"credentials"`
}

type jmapAccountGetResponse struct {
	List []jmapAccountObject `json:"list"`
}

type jmapDomainGetResponse struct {
	List []Domain `json:"list"`
}

func NewClient(baseURL, adminToken string) *Client {
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		adminToken: adminToken,
		httpClient: &http.Client{},
	}
}

// CreateAccount creates a User account. password may be plaintext or a hash;
// Stalwart decides which. A diskQuota of 0 leaves the quota unset.
func (c *Client) CreateAccount(ctx context.Context, name, password, description string, diskQuota int64) error {
	localPart, domain, err := splitAddress(name)
	if err != nil {
		return err
	}

	domainID, err := c.queryDomainID(ctx, domain)
	if err != nil {
		return fmt.Errorf("create account %s: %w", name, err)
	}

	quotas := map[string]any{}
	if diskQuota > 0 {
		quotas["maxDiskQuota"] = diskQuota
	}

	var response jmapSetResponse
	if err := c.call(ctx, "x:Account/set", map[string]any{
		"create": map[string]any{
			"new1": map[string]any{
				"@type":            "User",
				"name":             localPart,
				"domainId":         domainID,
				"description":      description,
				"credentials":      map[string]any{"0": passwordCredential(password)},
				"memberGroupIds":   map[string]any{},
				"roles":            map[string]any{"@type": "User"},
				"permissions":      map[string]any{"@type": "Inherit"},
				"quotas":           quotas,
				"aliases":          map[string]any{},
				"encryptionAtRest": map[string]any{"@type": "Disabled"},
			},
		},
	}, &response); err != nil {
		return fmt.Errorf("create account %s: %w", name, err)
	}

	if len(response.NotCreated) > 0 {
		return fmt.Errorf("create account %s: %w", name, firstJMAPError(response.NotCreated))
	}

	if len(response.Created) == 0 {
		return fmt.Errorf("create account %s: empty create response", name)
	}

	return nil
}

// UpdateAccount applies a JMAP patch (keys use "/" as the path separator, e.g.
// "credentials/0/secret") to the account with the given Stalwart ID.
func (c *Client) UpdateAccount(ctx context.Context, id string, patch map[string]any) error {
	var response jmapSetResponse
	if err := c.call(ctx, "x:Account/set", map[string]any{
		"update": map[string]any{id: patch},
	}, &response); err != nil {
		return fmt.Errorf("update account %s: %w", id, err)
	}

	if len(response.NotUpdated) > 0 {
		return fmt.Errorf("update account %s: %w", id, firstJMAPError(response.NotUpdated))
	}

	if _, ok := response.Updated[id]; !ok {
		return fmt.Errorf("update account %s: account not in update response", id)
	}

	return nil
}

// SetPassword replaces the account's Password credential, or adds one at key 0
// when the account has none.
func (c *Client) SetPassword(ctx context.Context, account Account, secret string) error {
	patch := map[string]any{"credentials/0": passwordCredential(secret)}
	if account.PasswordKey != "" {
		patch = map[string]any{"credentials/" + account.PasswordKey + "/secret": secret}
	}

	return c.UpdateAccount(ctx, account.ID, patch)
}

func passwordCredential(secret string) map[string]any {
	return map[string]any{"@type": "Password", "secret": secret}
}

func (c *Client) DeleteAccount(ctx context.Context, name string) error {
	localPart, domain, err := splitAddress(name)
	if err != nil {
		return err
	}

	domainID, err := c.queryDomainID(ctx, domain)
	if err != nil {
		return fmt.Errorf("delete account %s: %w", name, err)
	}

	accountID, err := c.queryAccountID(ctx, localPart, domainID)
	if err != nil {
		return fmt.Errorf("delete account %s: %w", name, err)
	}
	if accountID == "" {
		log.Printf("Stalwart account %s not found during delete", name)
		return nil
	}

	var response jmapSetResponse
	if err := c.call(ctx, "x:Account/set", map[string]any{
		"destroy": []string{accountID},
	}, &response); err != nil {
		return fmt.Errorf("delete account %s: %w", name, err)
	}

	if len(response.NotDestroyed) > 0 {
		return fmt.Errorf("delete account %s: %w", name, firstJMAPError(response.NotDestroyed))
	}

	return nil
}

func (c *Client) ListAccounts(ctx context.Context) ([]Account, error) {
	var response jmapAccountGetResponse
	if err := c.call(ctx, "x:Account/get", map[string]any{"ids": nil}, &response); err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}

	accounts := make([]Account, 0, len(response.List))
	for _, object := range response.List {
		account := Account{
			ID:          object.ID,
			Type:        object.Type,
			Name:        object.Name,
			DomainID:    object.DomainID,
			Email:       object.EmailAddress,
			Description: object.Description,
			Aliases:     make(map[string]Alias, len(object.Aliases)),
			IsAdmin:     object.Roles.Type == "Admin",
		}
		if quota, ok := object.Quotas["maxDiskQuota"].(float64); ok {
			account.DiskQuota = int64(quota)
		}
		for key, alias := range object.Aliases {
			account.Aliases[key] = Alias{Name: alias.Name, DomainID: alias.DomainID}
		}
		for groupID := range object.MemberGroupIDs {
			account.MemberGroupIDs = append(account.MemberGroupIDs, groupID)
		}
		sort.Strings(account.MemberGroupIDs)
		for key, credential := range object.Credentials {
			if credential.Type == "Password" && (account.PasswordKey == "" || key < account.PasswordKey) {
				account.PasswordKey = key
			}
		}
		accounts = append(accounts, account)
	}

	return accounts, nil
}

func (c *Client) ListDomains(ctx context.Context) ([]Domain, error) {
	var response jmapDomainGetResponse
	if err := c.call(ctx, "x:Domain/get", map[string]any{
		"ids":        nil,
		"properties": []string{"name"},
	}, &response); err != nil {
		return nil, fmt.Errorf("list domains: %w", err)
	}

	return response.List, nil
}

// Authenticate checks a user's credentials against Stalwart's JMAP session
// endpoint. It deliberately does not send the admin bearer token.
func (c *Client) Authenticate(ctx context.Context, username, password string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/jmap/session", nil)
	if err != nil {
		return false, fmt.Errorf("build authenticate request: %w", err)
	}
	req.SetBasicAuth(username, password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("send authenticate request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("authenticate request failed with status %d", resp.StatusCode)
	}
}

func (c *Client) queryDomainID(ctx context.Context, domain string) (string, error) {
	var response jmapQueryResponse
	if err := c.call(ctx, "x:Domain/query", map[string]any{
		"filter": map[string]string{"name": domain},
	}, &response); err != nil {
		return "", fmt.Errorf("query domain %s: %w", domain, err)
	}

	if len(response.IDs) == 0 {
		return "", fmt.Errorf("query domain %s: domain not found", domain)
	}

	return response.IDs[0], nil
}

func (c *Client) queryAccountID(ctx context.Context, localPart, domainID string) (string, error) {
	var response jmapQueryResponse
	if err := c.call(ctx, "x:Account/query", map[string]any{
		"filter": map[string]string{
			"name":     localPart,
			"domainId": domainID,
		},
	}, &response); err != nil {
		return "", fmt.Errorf("query account %s in domain %s: %w", localPart, domainID, err)
	}

	if len(response.IDs) == 0 {
		return "", nil
	}

	return response.IDs[0], nil
}

func (c *Client) call(ctx context.Context, method string, arguments any, target any) error {
	body, err := json.Marshal(jmapRequest{
		Using:       []string{jmapCoreCapability, jmapStalwartCapability},
		MethodCalls: []jmapMethodCall{{method, arguments, "c1"}},
	})
	if err != nil {
		return fmt.Errorf("marshal %s request: %w", method, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/jmap/", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build %s request: %w", method, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.adminToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send %s request: %w", method, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		responseBody, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("%s request failed with status %d and unreadable body: %w", method, resp.StatusCode, readErr)
		}
		return fmt.Errorf("%s request failed with status %d: %s", method, resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}

	var response jmapResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("decode %s response: %w", method, err)
	}

	if len(response.MethodResponses) == 0 {
		return fmt.Errorf("decode %s response: missing method responses", method)
	}

	methodResponse := response.MethodResponses[0]
	if len(methodResponse) != 3 {
		return fmt.Errorf("decode %s response: invalid method response shape", method)
	}

	var responseMethod string
	if err := json.Unmarshal(methodResponse[0], &responseMethod); err != nil {
		return fmt.Errorf("decode %s response method: %w", method, err)
	}

	if responseMethod == "error" {
		var jmapErr jmapError
		if err := json.Unmarshal(methodResponse[1], &jmapErr); err != nil {
			return fmt.Errorf("decode %s error response: %w", method, err)
		}
		if jmapErr.Description != "" {
			return fmt.Errorf("jmap error %s: %s", jmapErr.Type, jmapErr.Description)
		}
		return fmt.Errorf("jmap error %s", jmapErr.Type)
	}

	if responseMethod != method {
		return fmt.Errorf("unexpected method response %s", responseMethod)
	}

	if err := json.Unmarshal(methodResponse[1], target); err != nil {
		return fmt.Errorf("decode %s response body: %w", method, err)
	}

	return nil
}

func splitAddress(name string) (string, string, error) {
	localPart, domain, ok := strings.Cut(name, "@")
	if !ok || localPart == "" || domain == "" {
		return "", "", fmt.Errorf("invalid account name %q", name)
	}

	return localPart, domain, nil
}

func firstJMAPError(errs map[string]jmapError) error {
	for _, err := range errs {
		if err.Type == "invalidProperties" || err.Type == "invalidPatch" {
			return ErrInvalid{Description: err.Description}
		}
		if err.Description != "" {
			return fmt.Errorf("jmap error %s: %s", err.Type, err.Description)
		}
		return fmt.Errorf("jmap error %s", err.Type)
	}

	return fmt.Errorf("jmap error")
}
