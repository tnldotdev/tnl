package control

import (
	"context"
	"net/http"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) RegisterApplication(ctx context.Context, key string, body controlv1.RegisterApplicationRequest) (controlv1.RegisteredApplication, error) {
	return requestWithAccess[controlv1.RegisteredApplication](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RegisterApplication(ctx, &controlv1.RegisterApplicationParams{IdempotencyKey: key}, body, editors...)
	})
}
