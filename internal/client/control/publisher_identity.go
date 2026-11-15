package control

import (
	"context"
	"net/http"
	"strings"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) ControlURL() string { return strings.TrimSuffix(c.api.Server, "/") }

func (c *Client) CreatePublisherEnrollment(ctx context.Context, b controlv1.CreatePublisherEnrollmentRequest) (controlv1.PublisherEnrollment, error) {
	return requestWithAccess[controlv1.PublisherEnrollment](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreatePublisherEnrollment(ctx, b, e...)
	})
}
func (c *Client) ListPublisherIdentities(ctx context.Context, team, after string) (controlv1.PublisherIdentityPage, error) {
	p := &controlv1.ListPublisherIdentitiesParams{TeamId: team}
	if after != "" {
		p.Cursor = &after
	}
	return requestWithAccess[controlv1.PublisherIdentityPage](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListPublisherIdentities(ctx, p, e...)
	})
}
func (c *Client) CreatePublisherGrant(ctx context.Context, id string, b controlv1.CreatePublisherGrantRequest) (controlv1.PublisherGrant, error) {
	return requestWithAccess[controlv1.PublisherGrant](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreatePublisherGrant(ctx, id, b, e...)
	})
}
func (c *Client) RevokePublisherIdentity(ctx context.Context, team, id string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokePublisherIdentity(ctx, id, &controlv1.RevokePublisherIdentityParams{TeamId: team}, e...)
	})
	return err
}
func (c *Client) RevokePublisherGrant(ctx context.Context, team, id, grant string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokePublisherGrant(ctx, id, grant, &controlv1.RevokePublisherGrantParams{TeamId: team}, e...)
	})
	return err
}
func (c *Client) AllocatePublisherService(ctx context.Context, token string, b controlv1.AllocateServiceRequest) (controlv1.Service, error) {
	return request[controlv1.Service](ctx, c, token, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AllocatePublisherService(ctx, b, e...)
	})
}
func (c *Client) DeletePublisherService(ctx context.Context, token, id string) error {
	_, err := request[struct{}](ctx, c, token, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.DeletePublisherService(ctx, id, e...)
	})
	return err
}
