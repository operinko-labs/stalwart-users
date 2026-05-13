package stalwart

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
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
	Destroyed    []string                     `json:"destroyed"`
	NotCreated   map[string]jmapError         `json:"notCreated"`
	NotDestroyed map[string]jmapError         `json:"notDestroyed"`
}

type jmapCreatedObject struct {
	ID string `json:"id"`
}

func NewClient(baseURL, adminToken string) *Client {
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		adminToken: adminToken,
		httpClient: &http.Client{},
	}
}

func (c *Client) CreateAccount(ctx context.Context, name, password, description string) error {
	_ = password

	localPart, domain, err := splitAddress(name)
	if err != nil {
		return err
	}

	domainID, err := c.queryDomainID(ctx, domain)
	if err != nil {
		return fmt.Errorf("create account %s: %w", name, err)
	}

	var response jmapSetResponse
	if err := c.call(ctx, "x:Account/set", map[string]any{
		"create": map[string]any{
			"new1": map[string]any{
				"@type":            "User",
				"name":             localPart,
				"domainId":         domainID,
				"description":      description,
				"credentials":      map[string]any{},
				"memberGroupIds":   map[string]any{},
				"roles":            map[string]any{"@type": "User"},
				"permissions":      map[string]any{"@type": "Inherit"},
				"quotas":           map[string]any{},
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
		if err.Description != "" {
			return fmt.Errorf("jmap error %s: %s", err.Type, err.Description)
		}
		return fmt.Errorf("jmap error %s", err.Type)
	}

	return fmt.Errorf("jmap error")
}
