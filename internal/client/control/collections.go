package control

import (
	"context"
	"net/http"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) CreateCollection(ctx context.Context, project string, body controlv1.CreateCollectionRequest) (controlv1.Collection, error) {
	return requestWithAccess[controlv1.Collection](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateCollection(ctx, project, body, editors...)
	})
}

func (c *Client) GetCollection(ctx context.Context, team, project, id string) (controlv1.Collection, error) {
	return requestWithAccess[controlv1.Collection](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetCollection(ctx, project, id, &controlv1.GetCollectionParams{TeamId: team}, editors...)
	})
}

func (c *Client) ListCollections(ctx context.Context, team, project string) ([]controlv1.Collection, error) {
	return requestWithAccess[[]controlv1.Collection](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListCollections(ctx, project, &controlv1.ListCollectionsParams{TeamId: team}, editors...)
	})
}

func (c *Client) UpdateCollectionDefault(ctx context.Context, project, id string, body controlv1.UpdateCollectionDefaultRequest) (controlv1.Collection, error) {
	return requestWithAccess[controlv1.Collection](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.UpdateCollectionDefault(ctx, project, id, body, editors...)
	})
}
