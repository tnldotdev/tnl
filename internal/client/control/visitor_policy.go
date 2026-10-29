package control

import (
	"context"
	"net/http"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// the policy includes up to 64 keys, 4096 workloads, 2048 IP prefixes and
// 256 events. their bounded strings and control's RFC3339Nano timestamps fit
// within 2 MiB; unrelated operations retain the 1 MiB response limit.
const maxVisitorPolicyResponseBytes = 2 << 20

func (c *Client) ReadPublisherVisitorPolicy(ctx context.Context, body controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	return requestWithTimeoutAndLimit[controlv1.VisitorPolicyUpdate](ctx, c, c.timeout, token, maxVisitorPolicyResponseBytes, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ReadPublisherVisitorPolicy(ctx, body, editors...)
	})
}
