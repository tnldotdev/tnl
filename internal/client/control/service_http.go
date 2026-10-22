package control

import (
	"context"
	"net/http"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) AuthorizeServiceHTTPVisitor(ctx context.Context, service, run string, token credentials.ServiceRunToken, input controlv1.ServiceHTTPVisitorRequest) (controlv1.ServiceClientCertificateDecision, error) {
	return request[controlv1.ServiceClientCertificateDecision](ctx, c, token.String(), func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AuthorizeServiceHTTPVisitor(ctx, service, run, input, e...)
	})
}
func (c *Client) RedeemServiceBrowserHandoff(ctx context.Context, service, run string, token credentials.ServiceRunToken, input controlv1.ServiceBrowserRequest) (controlv1.BrowserHandoffResponse, error) {
	return request[controlv1.BrowserHandoffResponse](ctx, c, token.String(), func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RedeemServiceBrowserHandoff(ctx, service, run, input, e...)
	})
}
func (c *Client) CheckServiceBrowserSession(ctx context.Context, service, run string, token credentials.ServiceRunToken, input controlv1.ServiceBrowserRequest) (controlv1.BrowserAccessResponse, error) {
	return request[controlv1.BrowserAccessResponse](ctx, c, token.String(), func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CheckServiceBrowserSession(ctx, service, run, input, e...)
	})
}
func (c *Client) RevokeServiceBrowserSession(ctx context.Context, service, run string, token credentials.ServiceRunToken, input controlv1.ServiceBrowserRequest) error {
	_, err := request[struct{}](ctx, c, token.String(), func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokeServiceBrowserSession(ctx, service, run, input, e...)
	})
	return err
}
func (c *Client) CreateServiceHTTPGrant(ctx context.Context, service string, input controlv1.CreateServiceHTTPGrantRequest) (controlv1.ServiceHTTPGrant, error) {
	return requestWithAccess[controlv1.ServiceHTTPGrant](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateServiceHTTPGrant(ctx, service, input, e...)
	})
}
func (c *Client) RevokeServiceHTTPGrant(ctx context.Context, service, id string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokeServiceHTTPGrant(ctx, service, id, e...)
	})
	return err
}

func (c *Client) ListServiceHTTPGrants(ctx context.Context, service string) ([]controlv1.ServiceHTTPGrantSummary, error) {
	return requestWithAccess[[]controlv1.ServiceHTTPGrantSummary](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListServiceHTTPGrants(ctx, service, e...)
	})
}
