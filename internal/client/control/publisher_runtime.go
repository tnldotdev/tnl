package control

import (
	"context"
	"net/http"

	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) PublisherRuntime(ctx context.Context, body controlv1.PublisherRuntimeRequest) (controlv1.PublisherRuntimeResponse, error) {
	return request[controlv1.PublisherRuntimeResponse](ctx, c, "", func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		switch body.Action {
		case controlv1.RuntimeInspect:
			return c.api.InspectPublisherRuntime(ctx, body.PublisherIdentityId, body, editors...)
		case controlv1.RuntimeStart:
			return c.api.StartPublisherRuntime(ctx, body.PublisherIdentityId, body, editors...)
		case controlv1.RuntimeRenew:
			return c.api.RenewPublisherRuntime(ctx, body.PublisherIdentityId, body, editors...)
		case controlv1.RuntimeStop:
			return c.api.StopPublisherRuntime(ctx, body.PublisherIdentityId, body, editors...)
		default:
			return nil, publisherproof.ErrProof
		}
	})
}
