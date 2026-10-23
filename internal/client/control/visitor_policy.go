package control

import (
	"context"
	"net/http"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) ReadPublisherVisitorPolicy(ctx context.Context, body controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	return request[controlv1.VisitorPolicyUpdate](ctx, c, token, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ReadPublisherVisitorPolicy(ctx, body, editors...)
	})
}
