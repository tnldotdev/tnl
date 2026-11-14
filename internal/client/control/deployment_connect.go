package control

import (
	"context"
	"net/http"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) SelectDeploymentServiceRun(ctx context.Context, team, project, deployment, service string, source controlv1.VisitorTokenSource) (controlv1.ServiceSelection, error) {
	return visitorSourceRequest[controlv1.ServiceSelection](ctx, c, source, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.SelectDeploymentServiceRun(ctx, project, deployment, service, &controlv1.SelectDeploymentServiceRunParams{TeamId: team}, controlv1.SelectDeploymentServiceRunJSONRequestBody{Source: source}, editors...)
	})
}
