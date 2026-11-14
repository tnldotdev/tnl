package control

import (
	"context"
	"net/http"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) CreateDeploymentPublisherEnrollment(ctx context.Context, team, project, deployment, key string, body controlv1.CreateDeploymentPublisherEnrollmentRequest) (controlv1.DeploymentPublisherEnrollment, error) {
	return requestWithAccess[controlv1.DeploymentPublisherEnrollment](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateDeploymentPublisherEnrollment(ctx, project, deployment, &controlv1.CreateDeploymentPublisherEnrollmentParams{TeamId: team, IdempotencyKey: key}, body, editors...)
	})
}

func (c *Client) ListDeploymentPublishers(ctx context.Context, team, project, deployment, after string, limit int) (controlv1.DeploymentPublisherPage, error) {
	params := &controlv1.ListDeploymentPublishersParams{TeamId: team, Limit: &limit}
	if after != "" {
		params.After = &after
	}
	return requestWithAccess[controlv1.DeploymentPublisherPage](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListDeploymentPublishers(ctx, project, deployment, params, editors...)
	})
}

func (c *Client) GetDeploymentPublisher(ctx context.Context, team, project, deployment, publisher string) (controlv1.DeploymentPublisher, error) {
	return requestWithAccess[controlv1.DeploymentPublisher](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetDeploymentPublisher(ctx, project, deployment, publisher, &controlv1.GetDeploymentPublisherParams{TeamId: team}, editors...)
	})
}

func (c *Client) RevokeDeploymentPublisher(ctx context.Context, team, project, deployment, publisher string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokeDeploymentPublisher(ctx, project, deployment, publisher, &controlv1.RevokeDeploymentPublisherParams{TeamId: team}, editors...)
	})
	return err
}
