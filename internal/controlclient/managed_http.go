package controlclient

import (
	"context"
	"net/http"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (c *Client) AuthorizeManagedHTTPVisitor(ctx context.Context, service, run string, token credentials.ManagedRunToken, input controlv1.ManagedHTTPVisitorRequest) (controlv1.ServiceClientCertificateDecision, error) {
	return request[controlv1.ServiceClientCertificateDecision](ctx, c, token.String(), func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AuthorizeManagedHTTPVisitor(ctx, service, run, input, e...)
	})
}
func (c *Client) RedeemManagedBrowserHandoff(ctx context.Context, service, run string, token credentials.ManagedRunToken, input controlv1.ManagedBrowserRequest) (controlv1.BrowserHandoffResponse, error) {
	return request[controlv1.BrowserHandoffResponse](ctx, c, token.String(), func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RedeemManagedBrowserHandoff(ctx, service, run, input, e...)
	})
}
func (c *Client) CheckManagedBrowserSession(ctx context.Context, service, run string, token credentials.ManagedRunToken, input controlv1.ManagedBrowserRequest) (controlv1.BrowserAccessResponse, error) {
	return request[controlv1.BrowserAccessResponse](ctx, c, token.String(), func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CheckManagedBrowserSession(ctx, service, run, input, e...)
	})
}
func (c *Client) RevokeManagedBrowserSession(ctx context.Context, service, run string, token credentials.ManagedRunToken, input controlv1.ManagedBrowserRequest) error {
	_, err := request[struct{}](ctx, c, token.String(), func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokeManagedBrowserSession(ctx, service, run, input, e...)
	})
	return err
}
func (c *Client) CreateManagedHTTPGrant(ctx context.Context, service string, input controlv1.CreateManagedHTTPGrantRequest) (controlv1.ManagedHTTPGrant, error) {
	return requestWithAccess[controlv1.ManagedHTTPGrant](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateManagedHTTPGrant(ctx, service, input, e...)
	})
}
func (c *Client) RevokeManagedHTTPGrant(ctx context.Context, service, id string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokeManagedHTTPGrant(ctx, service, id, e...)
	})
	return err
}

func (c *Client) ListManagedHTTPGrants(ctx context.Context, service string) ([]controlv1.ManagedHTTPGrantSummary, error) {
	return requestWithAccess[[]controlv1.ManagedHTTPGrantSummary](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListManagedHTTPGrants(ctx, service, e...)
	})
}
