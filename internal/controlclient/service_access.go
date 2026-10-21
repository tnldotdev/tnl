package controlclient

import (
	"context"
	"net/http"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (c *Client) InvitePrivateServiceVisitor(ctx context.Context, service, key string, body controlv1.CreatePrivateServiceInvitationRequest) (controlv1.PrivateServiceInvitation, error) {
	return requestWithAccess[controlv1.PrivateServiceInvitation](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.InvitePrivateServiceVisitor(ctx, service, &controlv1.InvitePrivateServiceVisitorParams{IdempotencyKey: key}, body, e...)
	})
}

func (c *Client) AcceptPrivateServiceInvitation(ctx context.Context, secret string) (controlv1.PrivateServiceGrant, error) {
	return requestWithAccess[controlv1.PrivateServiceGrant](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AcceptPrivateServiceInvitation(ctx, controlv1.AcceptPrivateServiceInvitationJSONRequestBody{Secret: secret}, e...)
	})
}

func (c *Client) ListPrivateServiceInvitations(ctx context.Context, service string) ([]controlv1.PrivateServiceInvitation, error) {
	return requestWithAccess[[]controlv1.PrivateServiceInvitation](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListPrivateServiceInvitations(ctx, service, e...)
	})
}

func (c *Client) RevokePrivateServiceInvitation(ctx context.Context, service, id string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokePrivateServiceInvitation(ctx, service, id, e...)
	})
	return err
}

func (c *Client) ListPrivateServiceGrants(ctx context.Context, service string) ([]controlv1.PrivateServiceGrant, error) {
	return requestWithAccess[[]controlv1.PrivateServiceGrant](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListPrivateServiceGrants(ctx, service, e...)
	})
}

func (c *Client) RevokePrivateServiceGrant(ctx context.Context, service, id string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokePrivateServiceGrant(ctx, service, id, e...)
	})
	return err
}
