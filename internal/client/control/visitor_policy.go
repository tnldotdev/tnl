package control

import (
	"context"
	"net/http"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) ReadPublisherVisitorPolicy(ctx context.Context, body controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	// snapshots grow with the authenticated server's live authority inventory.
	// retain the request deadline and strict decoder without an inventory cap.
	return requestWithTimeoutAndLimit[controlv1.VisitorPolicyUpdate](ctx, c, c.timeout, token, 0, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ReadPublisherVisitorPolicy(ctx, body, editors...)
	})
}
