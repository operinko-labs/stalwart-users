package stalwart

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// OAuthClientSpec describes a first-party OAuth client for Stalwart's OIDC
// provider.
type OAuthClientSpec struct{ ClientID, Secret, RedirectURI, Description string }

func oauthGrantTypes() map[string]any {
	return map[string]any{"authorizationCode": true, "refreshToken": true}
}

// redactedError is err with every occurrence of a secret masked in its text.
// errors.Is and errors.As still see through it.
type redactedError struct {
	err    error
	secret string
}

func (e *redactedError) Error() string {
	return strings.ReplaceAll(e.err.Error(), e.secret, "[redacted]")
}

func (e *redactedError) Unwrap() error { return e.err }

// EnsureOAuthClient makes Stalwart hold an x:OAuthClient matching spec: it is
// created when no client has exactly spec.ClientID, otherwise its secret,
// redirect URIs, grant types and description are brought in line. created
// reports which one happened. The query filter is not trusted to be exact, so
// the returned clients' clientId is checked before anything is written; two
// exact matches are an error. Error text never contains spec.Secret.
func (c *Client) EnsureOAuthClient(ctx context.Context, spec OAuthClientSpec) (created bool, err error) {
	defer func() {
		if err != nil && spec.Secret != "" {
			err = &redactedError{err: err, secret: spec.Secret}
		}
	}()

	var query jmapQueryResponse
	if err := c.call(ctx, "x:OAuthClient/query", map[string]any{
		"filter": map[string]any{"clientId": spec.ClientID},
	}, &query); err != nil {
		return false, fmt.Errorf("query oauth client %s: %w", spec.ClientID, err)
	}

	var exact []string
	if len(query.IDs) > 0 {
		var got struct {
			List []struct {
				ID       string `json:"id"`
				ClientID string `json:"clientId"`
			} `json:"list"`
		}
		if err := c.call(ctx, "x:OAuthClient/get", map[string]any{
			"ids":        query.IDs,
			"properties": []string{"clientId"},
		}, &got); err != nil {
			return false, fmt.Errorf("get oauth client %s: %w", spec.ClientID, err)
		}
		for _, object := range got.List {
			if object.ClientID == spec.ClientID {
				exact = append(exact, object.ID)
			}
		}
	}

	var response jmapSetResponse
	switch len(exact) {
	case 0:
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
		if _, ok := response.Created["new1"]; !ok {
			return false, fmt.Errorf("create oauth client %s: %w", spec.ClientID, errors.New("client not in create response"))
		}
		return true, nil
	case 1:
		id := exact[0]
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
	default:
		return false, fmt.Errorf("oauth client %s: %d clients have this clientId, refusing to pick one", spec.ClientID, len(exact))
	}
}
