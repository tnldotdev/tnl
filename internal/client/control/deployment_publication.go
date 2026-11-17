package control

import (
	"context"
	"net/http"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) DeploymentPublication(ctx context.Context, token, team, project, deployment, service string) (controlv1.Service, error) {
	return request[controlv1.Service](ctx, c, token, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetDeploymentPublication(ctx, project, deployment, service, &controlv1.GetDeploymentPublicationParams{TeamId: team}, editors...)
	})
}

func (c *Client) AllocateDeploymentPublication(ctx context.Context, token, team, project, deployment string, body controlv1.AllocateServiceRequest) (controlv1.Service, error) {
	return request[controlv1.Service](ctx, c, token, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AllocateDeploymentPublication(ctx, project, deployment, &controlv1.AllocateDeploymentPublicationParams{TeamId: team}, body, editors...)
	})
}
