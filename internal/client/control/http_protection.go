package control

import (
	"context"
	"net/http"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) ReportHTTPProtectionRejections(ctx context.Context, body controlv1.ReportHTTPProtectionRejectionsRequest, token string) error {
	_, err := request[struct{}](ctx, c, token, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ReportHTTPProtectionRejections(ctx, body, editors...)
	})
	return err
}
