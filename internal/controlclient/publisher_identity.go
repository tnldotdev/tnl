package controlclient

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
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
func (c *Client) PublisherPublicURL(ctx context.Context, token string) (controlv1.PublicURL, error) {
	return request[controlv1.PublicURL](ctx, c, token, c.api.GetPublisherPublicURL)
}
func (c *Client) AllocatePublisherPublicURL(ctx context.Context, token string, b controlv1.AllocateEphemeralPublicURLRequest) (controlv1.PublicURL, error) {
	return request[controlv1.PublicURL](ctx, c, token, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AllocatePublisherPublicURL(ctx, b, e...)
	})
}
func (c *Client) DeletePublisherPublicURL(ctx context.Context, token, id string) error {
	_, err := request[struct{}](ctx, c, token, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.DeletePublisherPublicURL(ctx, id, e...)
	})
	return err
}
func (c *Client) CreatePublisherRun(ctx context.Context, id, retry, token, proof string) (controlv1.PublishRunSetup, error) {
	return c.CreatePublisherRunWithTraffic(ctx, id, retry, token, proof, nil)
}
func (c *Client) EnrollGuestPublisher(ctx context.Context, id string, public ed25519.PublicKey) (controlv1.GuestPublisherIdentity, error) {
	return requestWithAccess[controlv1.GuestPublisherIdentity](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.EnrollGuestPublisher(ctx, controlv1.EnrollGuestPublisherRequest{PublicUrlId: id, PublicKey: base64.RawURLEncoding.EncodeToString(public)}, e...)
	})
}
