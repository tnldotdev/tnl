package control

import (
	"context"
	"encoding/json"
	"net/http"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type visitorSourceAuthenticationKey struct{}

// VisitorSourceAuthenticates reports that this exact request carries its own
// browser, share, grant, or workload source instead of a management session.
func VisitorSourceAuthenticates(ctx context.Context) bool {
	value, _ := ctx.Value(visitorSourceAuthenticationKey{}).(bool)
	return value
}

// IssueVisitorToken exchanges an explicit authentication source for permission.
// source credentials stay in the request body; they never become control bearer
// credentials or application headers.
func (c *Client) IssueVisitorToken(ctx context.Context, body controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
	var source struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(body.Source, &source); err != nil {
		return controlv1.VisitorTokenResponse{}, err
	}
	if source.Kind == "control_session" || source.Kind == "device" {
		return requestWithAccess[controlv1.VisitorTokenResponse](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
			return c.api.IssueVisitorToken(ctx, body, editors...)
		})
	}
	ctx = context.WithValue(ctx, visitorSourceAuthenticationKey{}, true)
	return request[controlv1.VisitorTokenResponse](ctx, c, "", func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.IssueVisitorToken(ctx, body, editors...)
	})
}
