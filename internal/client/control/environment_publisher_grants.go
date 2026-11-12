package control

import (
	"context"
	"net/http"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) GetEnvironmentPublisherGrant(ctx context.Context, team, project, environment, publisher, service string) (controlv1.EnvironmentPublisherGrantState, error) {
	return requestWithAccess[controlv1.EnvironmentPublisherGrantState](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetEnvironmentPublisherGrant(ctx, project, environment, publisher, service, &controlv1.GetEnvironmentPublisherGrantParams{TeamId: team}, editors...)
	})
}

func (c *Client) AuthorizeEnvironmentPublisherService(ctx context.Context, project, environment, publisher, service string, body controlv1.AuthorizeEnvironmentPublisherServiceRequest) (controlv1.EnvironmentPublisherGrantState, error) {
	return requestWithAccess[controlv1.EnvironmentPublisherGrantState](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AuthorizeEnvironmentPublisherService(ctx, project, environment, publisher, service, body, editors...)
	})
}

func (c *Client) RevokeEnvironmentPublisherGrant(ctx context.Context, project, environment, publisher, service, grant string, params controlv1.RevokeEnvironmentPublisherGrantParams) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokeEnvironmentPublisherGrant(ctx, project, environment, publisher, service, grant, &params, editors...)
	})
	return err
}
