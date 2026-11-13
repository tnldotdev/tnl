package control

import (
	"context"
	"net/http"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) RegisterDeploymentCredential(ctx context.Context, team, project, key string, body controlv1.RegisterDeploymentCredentialRequest) (controlv1.DeploymentCredential, error) {
	return requestWithAccess[controlv1.DeploymentCredential](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RegisterDeploymentCredential(ctx, project, &controlv1.RegisterDeploymentCredentialParams{TeamId: team, IdempotencyKey: key}, body, editors...)
	})
}
