package control

import (
	"context"
	"net/http"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// IssueVisitorToken exchanges an explicit authentication source for permission.
// source credentials stay in the request body; they never become control bearer
// credentials or application headers.
func (c *Client) IssueVisitorToken(ctx context.Context, body controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
	return request[controlv1.VisitorTokenResponse](ctx, c, "", func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.IssueVisitorToken(ctx, body, editors...)
	})
}
