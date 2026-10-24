package control

import (
	"context"
	"encoding/json"
	"net/http"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) CreateVisitorCredential(ctx context.Context, body controlv1.CreateVisitorCredentialRequest) (controlv1.VisitorCredential, error) {
	return requestWithAccess[controlv1.VisitorCredential](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateVisitorCredential(ctx, body, editors...)
	})
}

// IssueVisitorToken exchanges an explicit authentication source for permission.
// source credentials stay in the request body; they never become control bearer
// credentials or application headers.
func (c *Client) IssueVisitorToken(ctx context.Context, body controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
	return request[controlv1.VisitorTokenResponse](ctx, c, "", func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.IssueVisitorToken(ctx, body, editors...)
	})
}

// IssueDeviceVisitorToken prepares service permission using the current control
// session and the explicitly selected enrolled device.
func (c *Client) IssueDeviceVisitorToken(ctx context.Context, service, device string) (controlv1.VisitorTokenResponse, error) {
	source, err := json.Marshal(controlv1.VisitorTokenDeviceSource{Kind: controlv1.VisitorTokenDevice, DeviceId: device})
	if err != nil {
		return controlv1.VisitorTokenResponse{}, err
	}
	body := controlv1.VisitorTokenRequest{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: service}, Source: source}
	return requestWithAccess[controlv1.VisitorTokenResponse](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.IssueVisitorToken(ctx, body, editors...)
	})
}
