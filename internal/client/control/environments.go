package control

import (
	"context"
	"net/http"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) CreateServiceDefinition(ctx context.Context, project string, body controlv1.CreateServiceDefinitionRequest) (controlv1.ServiceDefinitionRevision, error) {
	return requestWithAccess[controlv1.ServiceDefinitionRevision](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateServiceDefinition(ctx, project, body, editors...)
	})
}

func (c *Client) CreateEnvironment(ctx context.Context, project string, body controlv1.CreateEnvironmentRequest) (controlv1.Environment, error) {
	return requestWithAccess[controlv1.Environment](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateEnvironment(ctx, project, body, editors...)
	})
}

func (c *Client) GetEnvironment(ctx context.Context, team, project, id string) (controlv1.Environment, error) {
	return requestWithAccess[controlv1.Environment](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetEnvironment(ctx, project, id, &controlv1.GetEnvironmentParams{TeamId: team}, editors...)
	})
}

func (c *Client) ListEnvironments(ctx context.Context, team, project string) ([]controlv1.Environment, error) {
	return requestWithAccess[[]controlv1.Environment](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListEnvironments(ctx, project, &controlv1.ListEnvironmentsParams{TeamId: team}, editors...)
	})
}

func (c *Client) ApplyEnvironment(ctx context.Context, project, id string, body controlv1.ApplyEnvironmentRequest) (controlv1.Environment, error) {
	return requestWithAccess[controlv1.Environment](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ApplyEnvironment(ctx, project, id, body, editors...)
	})
}

func (c *Client) ApplyEnvironments(ctx context.Context, project string, body controlv1.ApplyEnvironmentsRequest) ([]controlv1.Environment, error) {
	return requestWithAccess[[]controlv1.Environment](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ApplyEnvironments(ctx, project, body, editors...)
	})
}

func (c *Client) RetireEnvironment(ctx context.Context, team, project, id string, revision int64) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RetireEnvironment(ctx, project, id, &controlv1.RetireEnvironmentParams{TeamId: team, ExpectedRevision: revision}, editors...)
	})
	return err
}
