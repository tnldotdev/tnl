package control

import (
	"context"
	"net/http"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) RealizeLocalProjectService(ctx context.Context, project, service string, body controlv1.RealizeLocalProjectServiceRequest) (controlv1.LocalProjectService, error) {
	return requestWithAccess[controlv1.LocalProjectService](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RealizeLocalProjectService(ctx, project, service, body, editors...)
	})
}

func (c *Client) GetLocalProjectService(ctx context.Context, project, service string, params controlv1.GetLocalProjectServiceParams) (controlv1.LocalProjectService, error) {
	return requestWithAccess[controlv1.LocalProjectService](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetLocalProjectService(ctx, project, service, &params, editors...)
	})
}

func (c *Client) GetProjectPublicMetadata(ctx context.Context, team, project string) (controlv1.ProjectPublicMetadata, error) {
	return requestWithAccess[controlv1.ProjectPublicMetadata](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetProjectPublicMetadata(ctx, project, &controlv1.GetProjectPublicMetadataParams{TeamId: team}, editors...)
	})
}
