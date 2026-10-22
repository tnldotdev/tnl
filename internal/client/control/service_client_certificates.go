package controlclient

import (
	"context"
	"net/http"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (c *Client) IssueServiceClientCertificate(ctx context.Context, service, device string, csr []byte) (controlv1.ServiceClientCertificate, error) {
	return requestWithAccess[controlv1.ServiceClientCertificate](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.IssueServiceClientCertificate(ctx, service, controlv1.IssueServiceClientCertificateRequest{DeviceId: device, Csr: csr}, editors...)
	})
}

func (c *Client) AuthorizeServiceClientCertificate(ctx context.Context, service, run string, token credentials.ManagedRunToken, body controlv1.AuthorizeServiceClientCertificateRequest) (controlv1.ServiceClientCertificateDecision, error) {
	return request[controlv1.ServiceClientCertificateDecision](ctx, c, string(token), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AuthorizeServiceClientCertificate(ctx, service, run, body, editors...)
	})
}

func (c *Client) AuthorizeServiceConnector(ctx context.Context, service, run string, token credentials.ManagedRunToken, body controlv1.AuthorizeServiceConnectorRequest) (controlv1.ServiceClientCertificateDecision, error) {
	return request[controlv1.ServiceClientCertificateDecision](ctx, c, string(token), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AuthorizeServiceConnector(ctx, service, run, body, editors...)
	})
}
