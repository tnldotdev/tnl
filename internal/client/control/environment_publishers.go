package control

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) CreateEnvironmentPublisherEnrollment(ctx context.Context, project, environment, key string, body controlv1.CreateEnvironmentPublisherEnrollmentRequest) (controlv1.EnvironmentPublisherEnrollment, error) {
	params := &controlv1.CreateEnvironmentPublisherEnrollmentParams{}
	if key != "" {
		params.IdempotencyKey = &key
	}
	return requestWithAccess[controlv1.EnvironmentPublisherEnrollment](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateEnvironmentPublisherEnrollment(ctx, project, environment, params, body, editors...)
	})
}

func (c *Client) ListEnvironmentPublishers(ctx context.Context, team, project, environment string) ([]controlv1.EnvironmentPublisherStatus, error) {
	return requestWithAccess[[]controlv1.EnvironmentPublisherStatus](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListEnvironmentPublishers(ctx, project, environment, &controlv1.ListEnvironmentPublishersParams{TeamId: team}, editors...)
	})
}

func (c *Client) RevokeEnvironmentPublisher(ctx context.Context, team, project, environment, publisher string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokeEnvironmentPublisher(ctx, project, environment, publisher, &controlv1.RevokeEnvironmentPublisherParams{TeamId: team}, editors...)
	})
	return err
}

func (c *Client) RedeemEnvironmentPublisherEnrollment(ctx context.Context, key string, public ed25519.PublicKey) (controlv1.EnvironmentPublisher, error) {
	return request[controlv1.EnvironmentPublisher](ctx, c, "", func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RedeemEnvironmentPublisherEnrollment(ctx, controlv1.RedeemEnvironmentPublisherEnrollmentRequest{EnrollmentKey: key, PublicKey: base64.RawURLEncoding.EncodeToString(public)}, editors...)
	})
}

func (c *Client) VerifyEnvironmentPublisher(ctx context.Context, body controlv1.EnvironmentPublisherProof) (controlv1.EnvironmentPublisher, error) {
	return request[controlv1.EnvironmentPublisher](ctx, c, "", func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.VerifyEnvironmentPublisher(ctx, body, editors...)
	})
}

func (c *Client) AcquireEnvironmentPublisherLease(ctx context.Context, body controlv1.EnvironmentPublisherProof) (controlv1.EnvironmentPublisherLease, error) {
	return request[controlv1.EnvironmentPublisherLease](ctx, c, "", func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AcquireEnvironmentPublisherLease(ctx, body, editors...)
	})
}

func (c *Client) GetEnvironmentPublisherAssignments(ctx context.Context, token string) (controlv1.EnvironmentPublisherAssignments, error) {
	return request[controlv1.EnvironmentPublisherAssignments](ctx, c, token, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetEnvironmentPublisherAssignments(ctx, editors...)
	})
}

func (c *Client) AcknowledgeEnvironmentPublisher(ctx context.Context, token string, body controlv1.EnvironmentPublisherAcknowledgement) error {
	_, err := request[struct{}](ctx, c, token, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AcknowledgeEnvironmentPublisher(ctx, body, editors...)
	})
	return err
}
