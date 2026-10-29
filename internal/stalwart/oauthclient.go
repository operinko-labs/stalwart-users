package stalwart

import (
	"context"
	"errors"
	"fmt"
)

// OAuthClientSpec describes a first-party OAuth client for Stalwart's OIDC
// provider.
type OAuthClientSpec struct{ ClientID, Secret, RedirectURI, Description string }

func oauthGrantTypes() map[string]any {
	return map[string]any{"authorizationCode": true, "refreshToken": true}
}

// EnsureOAuthClient makes Stalwart hold an x:OAuthClient matching spec: it is
// created when no client has spec.ClientID, otherwise its secret, redirect
// URIs, grant types and description are brought in line. created reports
// which one happened. Errors never contain spec.Secret.
func (c *Client) EnsureOAuthClient(ctx context.Context, spec OAuthClientSpec) (created bool, err error) {
	var query jmapQueryResponse
	if err := c.call(ctx, "x:OAuthClient/query", map[string]any{
		"filter": map[string]any{"clientId": spec.ClientID},
	}, &query); err != nil {
		return false, fmt.Errorf("query oauth client %s: %w", spec.ClientID, err)
	}

	var response jmapSetResponse
	if len(query.IDs) == 0 {
		if err := c.call(ctx, "x:OAuthClient/set", map[string]any{
			"create": map[string]any{"new1": map[string]any{
				"clientId":               spec.ClientID,
				"description":            spec.Description,
				"contacts":               map[string]any{},
				"secret":                 spec.Secret,
				"redirectUris":           map[string]any{spec.RedirectURI: true},
				"postLogoutRedirectUris": map[string]any{},
				"logo":                   nil,
				"firstParty":             true,
				"scopes":                 map[string]any{},
				"grantTypes":             oauthGrantTypes(),
			}},
		}, &response); err != nil {
			return false, fmt.Errorf("create oauth client %s: %w", spec.ClientID, err)
		}
		if len(response.NotCreated) > 0 {
			return false, fmt.Errorf("create oauth client %s: %w", spec.ClientID, firstJMAPError(response.NotCreated))
		}
		if len(response.Created) == 0 {
			return false, fmt.Errorf("create oauth client %s: %w", spec.ClientID, errors.New("empty create response"))
		}
		return true, nil
	}

	id := query.IDs[0]
	if err := c.call(ctx, "x:OAuthClient/set", map[string]any{
		"update": map[string]any{id: map[string]any{
			"secret":       spec.Secret,
			"redirectUris": map[string]any{spec.RedirectURI: true},
			"firstParty":   true,
			"grantTypes":   oauthGrantTypes(),
			"description":  spec.Description,
		}},
	}, &response); err != nil {
		return false, fmt.Errorf("update oauth client %s: %w", spec.ClientID, err)
	}
	if len(response.NotUpdated) > 0 {
		return false, fmt.Errorf("update oauth client %s: %w", spec.ClientID, firstJMAPError(response.NotUpdated))
	}
	if _, ok := response.Updated[id]; !ok {
		return false, fmt.Errorf("update oauth client %s: %w", spec.ClientID, errors.New("client not in update response"))
	}
	return false, nil
}
