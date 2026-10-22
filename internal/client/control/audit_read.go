package controlclient

import (
	"context"
	"net/http"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// ListServiceAudit reads one manager-authorized page using the person's session.
// callers retain filters and advance the returned cursor when reading more pages.
func (c *Client) ListServiceAudit(ctx context.Context, team string, params controlv1.ListServiceAuditParams) (controlv1.ServiceAuditPage, error) {
	return requestWithAccess[controlv1.ServiceAuditPage](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListServiceAudit(ctx, team, &params, editors...)
	})
}
