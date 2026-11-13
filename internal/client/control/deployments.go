package control

import (
	"context"
	"net/http"
	"strconv"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) CreateDeployment(ctx context.Context, team, project, key string, body controlv1.CreateDeploymentRequest) (controlv1.Deployment, error) {
	return requestWithAccess[controlv1.Deployment](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateDeployment(ctx, project, &controlv1.CreateDeploymentParams{TeamId: team, IdempotencyKey: key}, body, editors...)
	})
}

func (c *Client) ListDeployments(ctx context.Context, team, project, after string, limit int) (controlv1.DeploymentPage, error) {
	params := &controlv1.ListDeploymentsParams{TeamId: team, Limit: &limit}
	if after != "" {
		params.After = &after
	}
	return requestWithAccess[controlv1.DeploymentPage](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListDeployments(ctx, project, params, editors...)
	})
}

func (c *Client) GetDeployment(ctx context.Context, team, project, selector string) (controlv1.Deployment, error) {
	return requestWithAccess[controlv1.Deployment](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetDeployment(ctx, project, selector, &controlv1.GetDeploymentParams{TeamId: team}, editors...)
	})
}

func (c *Client) UpdateDeployment(ctx context.Context, team, project, selector string, revision int64, body controlv1.UpdateDeploymentRequest) (controlv1.Deployment, error) {
	condition := strconv.Quote(strconv.FormatInt(revision, 10))
	return requestWithAccess[controlv1.Deployment](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.UpdateDeployment(ctx, project, selector, &controlv1.UpdateDeploymentParams{TeamId: team, IfMatch: &condition}, body, editors...)
	})
}

func (c *Client) DeleteDeployment(ctx context.Context, team, project, selector string, revision int64) error {
	condition := strconv.Quote(strconv.FormatInt(revision, 10))
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.DeleteDeployment(ctx, project, selector, &controlv1.DeleteDeploymentParams{TeamId: team, IfMatch: &condition}, editors...)
	})
	return err
}
