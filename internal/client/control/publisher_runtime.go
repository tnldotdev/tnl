package controlclient

import (
	"context"
	"net/http"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (c *Client) PublisherRuntime(ctx context.Context, body controlv1.PublisherRuntimeRequest) (controlv1.PublisherRuntimeResponse, error) {
	return request[controlv1.PublisherRuntimeResponse](ctx, c, "", func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ObservePublisherRuntime(ctx, body, editors...)
	})
}
