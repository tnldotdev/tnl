package control

import (
	"context"
	"net/http"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) AuthorizeHTTPVisitor(ctx context.Context, runID string, input controlv1.HTTPVisitorRequest, token credentials.PublishRunToken) (controlv1.HTTPVisitorResponse, error) {
	return request[controlv1.HTTPVisitorResponse](ctx, c, token.String(), func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AuthorizeHTTPVisitor(ctx, runID, input, e...)
	})
}
