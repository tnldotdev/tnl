package controlclient

import (
	"context"
	"net/http"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (c *Client) ListAvailablePublicURLs(ctx context.Context, teamID, cursor string) (controlv1.AvailablePublicURLPage, error) {
	p := &controlv1.ListAvailablePublicURLsParams{}
	if teamID != "" {
		p.TeamId = &teamID
	}
	if cursor != "" {
		p.Cursor = &cursor
	}
	return requestWithAccess[controlv1.AvailablePublicURLPage](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListAvailablePublicURLs(ctx, p, e...)
	})
}
func (c *Client) CreateTeamVisitorGrant(ctx context.Context, id, key string, body controlv1.CreateTeamVisitorGrantRequest) (controlv1.VisitorGrant, error) {
	return requestWithAccess[controlv1.VisitorGrant](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateTeamVisitorGrant(ctx, id, &controlv1.CreateTeamVisitorGrantParams{IdempotencyKey: key}, body, e...)
	})
}

func (c *Client) CreateIdentityVisitorGrant(ctx context.Context, id, key string, body controlv1.CreateIdentityVisitorGrantRequest) (controlv1.VisitorGrant, error) {
	return requestWithAccess[controlv1.VisitorGrant](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateIdentityVisitorGrant(ctx, id, &controlv1.CreateIdentityVisitorGrantParams{IdempotencyKey: key}, body, e...)
	})
}

func (c *Client) ListVisitorGrants(ctx context.Context, id string) ([]controlv1.VisitorGrant, error) {
	return requestWithAccess[[]controlv1.VisitorGrant](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListVisitorGrants(ctx, id, e...)
	})
}
func (c *Client) RevokeVisitorGrant(ctx context.Context, id, grantID string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokeVisitorGrant(ctx, id, grantID, e...)
	})
	return err
}
func (c *Client) CreateVisitorInvitation(ctx context.Context, id, key string, body controlv1.CreateVisitorInvitationRequest) (controlv1.VisitorInvitation, error) {
	return requestWithAccess[controlv1.VisitorInvitation](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateVisitorInvitation(ctx, id, &controlv1.CreateVisitorInvitationParams{IdempotencyKey: key}, body, e...)
	})
}
func (c *Client) ListVisitorInvitations(ctx context.Context, id string) ([]controlv1.VisitorInvitation, error) {
	return requestWithAccess[[]controlv1.VisitorInvitation](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListVisitorInvitations(ctx, id, e...)
	})
}
func (c *Client) RevokeVisitorInvitation(ctx context.Context, id, inviteID string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokeVisitorInvitation(ctx, id, inviteID, e...)
	})
	return err
}
func (c *Client) AcceptVisitorInvitation(ctx context.Context, secret string) (controlv1.VisitorGrant, error) {
	return requestWithAccess[controlv1.VisitorGrant](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AcceptVisitorInvitation(ctx, controlv1.AcceptVisitorInvitationJSONRequestBody{Secret: secret}, e...)
	})
}
func (c *Client) ReplaceVisitorAccess(ctx context.Context, id string, body controlv1.ReplaceVisitorAccessRequest) (controlv1.PublicURL, error) {
	return requestWithAccess[controlv1.PublicURL](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ReplaceVisitorAccess(ctx, id, body, e...)
	})
}
