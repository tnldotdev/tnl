package controlclient

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/trafficlimits"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (c *Client) RegisterGuestPublisherIdentity(ctx context.Context, trial credentials.AccessToken, public ed25519.PublicKey) (controlv1.GuestPublisherIdentity, error) {
	return request[controlv1.GuestPublisherIdentity](ctx, c, string(trial), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RegisterGuestPublisherIdentity(ctx, controlv1.RegisterGuestPublisherIdentityRequest{
			PublicKey: base64.RawURLEncoding.EncodeToString(public),
		}, editors...)
	})
}

func (c *Client) CreatePublisherEnrollment(ctx context.Context, body controlv1.CreatePublisherEnrollmentRequest) (controlv1.IssuedPublisherEnrollment, error) {
	return requestWithAccess[controlv1.IssuedPublisherEnrollment](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreatePublisherEnrollment(ctx, body, editors...)
	})
}

func (c *Client) CreatePublisherGrant(ctx context.Context, id string, body controlv1.CreatePublisherGrantRequest) (controlv1.PublisherGrant, error) {
	return requestWithAccess[controlv1.PublisherGrant](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreatePublisherGrant(ctx, id, body, editors...)
	})
}

func (c *Client) ListPublisherIdentities(ctx context.Context, teamID, cursor string) (controlv1.PublisherIdentityPage, error) {
	params := &controlv1.ListPublisherIdentitiesParams{TeamId: teamID}
	if cursor != "" {
		params.Cursor = &cursor
	}
	return requestWithAccess[controlv1.PublisherIdentityPage](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListPublisherIdentities(ctx, params, editors...)
	})
}

func (c *Client) RevokePublisherIdentity(ctx context.Context, teamID, id string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokePublisherIdentity(ctx, id, &controlv1.RevokePublisherIdentityParams{TeamId: teamID}, editors...)
	})
	return err
}

func (c *Client) RevokePublisherGrant(ctx context.Context, teamID, id, grantID string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokePublisherGrant(ctx, id, grantID, &controlv1.RevokePublisherGrantParams{TeamId: teamID}, editors...)
	})
	return err
}

func (c *Client) PublisherPublicURL(ctx context.Context, token string) (controlv1.PublicURL, error) {
	return request[controlv1.PublicURL](ctx, c, token, c.api.GetPublisherPublicURL)
}

func (c *Client) AllocatePublisherPublicURL(ctx context.Context, token string, body controlv1.AllocateEphemeralPublicURLRequest) (controlv1.PublicURL, error) {
	return request[controlv1.PublicURL](ctx, c, token, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AllocateEphemeralPublicURL(ctx, body, editors...)
	})
}

func (c *Client) DeletePublisherPublicURL(ctx context.Context, token, id string) error {
	_, err := request[struct{}](ctx, c, token, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.DeleteEphemeralPublicURL(ctx, id, editors...)
	})
	return err
}

func (c *Client) CreatePublisherRun(ctx context.Context, id, key, token, proof string, traffic trafficlimits.Selection) (controlv1.PublishRunSetup, error) {
	body := createPublishRunBody([]trafficlimits.Selection{traffic})
	body.PublisherProof = &proof
	return request[controlv1.PublishRunSetup](ctx, c, token, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreatePublishRun(ctx, id, &controlv1.CreatePublishRunParams{IdempotencyKey: key}, body, editors...)
	})
}
