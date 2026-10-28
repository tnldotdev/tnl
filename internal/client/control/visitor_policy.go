package control

import (
	"context"
	"net/http"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// the visitor-policy and stream-capacity schemas bound combined state to 64
// keys, 4096 workloads, 2048 allocations, 2048 IP prefixes and 256 events.
// allowing six JSON bytes per string character and 19 per positive int64:
// 16 KiB envelope/events + 64*1 KiB keys + 4096*192 B workloads +
// 2048*3 KiB allocations + 2048*128 B prefixes = 7,421,952 B, below 8 MiB.
// date-time strings have no schema length bound; this accounts for control
// state's generated time.Time RFC3339Nano encoding (at most 37 B with quotes),
// not arbitrary date-time spellings. unrelated methods retain the 1 MiB limit.
const maxVisitorPolicyResponseBytes = 8 << 20

func (c *Client) ReadPublisherVisitorPolicy(ctx context.Context, body controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	return requestWithTimeoutAndLimit[controlv1.VisitorPolicyUpdate](ctx, c, c.timeout, token, maxVisitorPolicyResponseBytes, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ReadPublisherVisitorPolicy(ctx, body, editors...)
	})
}
