package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type StalwartAdminClient struct {
	baseURL    string
	adminToken string
	httpClient *http.Client
}

func NewStalwartAdminClient(baseURL, adminToken string) *StalwartAdminClient {
	return &StalwartAdminClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		adminToken: adminToken,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

func (c *StalwartAdminClient) IsAdmin(ctx context.Context, username string) bool {
	if c == nil || c.baseURL == "" || c.adminToken == "" || username == "" {
		return false
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/principal/"+url.PathEscape(username), nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+c.adminToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	var body struct {
		Roles json.RawMessage `json:"roles"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false
	}

	return rolesContainAdmin(body.Roles)
}

func rolesContainAdmin(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}

	var roles []string
	if err := json.Unmarshal(raw, &roles); err == nil {
		for _, role := range roles {
			if strings.EqualFold(role, "admin") {
				return true
			}
		}
		return false
	}

	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return strings.EqualFold(single, "admin")
	}

	return false
}
