package identity

import (
	"context"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type serviceHTTPControl interface {
	RedeemServiceBrowserHandoff(context.Context, string, string, credentials.ServiceRunToken, controlv1.ServiceBrowserRequest) (controlv1.BrowserHandoffResponse, error)
	CheckServiceBrowserSession(context.Context, string, string, credentials.ServiceRunToken, controlv1.ServiceBrowserRequest) (controlv1.BrowserAccessResponse, error)
	RevokeServiceBrowserSession(context.Context, string, string, credentials.ServiceRunToken, controlv1.ServiceBrowserRequest) error
}

func (n *Native) serviceHTTP(service string) (serviceHTTPControl, error) {
	if _, err := n.serviceCertificates(service); err != nil {
		return nil, err
	}
	control, ok := n.NativeControl.(serviceHTTPControl)
	if !ok {
		return nil, ErrScope
	}
	return control, nil
}
func (n *Native) RedeemServiceBrowserHandoff(ctx context.Context, service, run string, token credentials.ServiceRunToken, body controlv1.ServiceBrowserRequest) (controlv1.BrowserHandoffResponse, error) {
	c, err := n.serviceHTTP(service)
	if err != nil {
		return controlv1.BrowserHandoffResponse{}, err
	}
	return c.RedeemServiceBrowserHandoff(ctx, service, run, token, body)
}
func (n *Native) CheckServiceBrowserSession(ctx context.Context, service, run string, token credentials.ServiceRunToken, body controlv1.ServiceBrowserRequest) (controlv1.BrowserAccessResponse, error) {
	c, err := n.serviceHTTP(service)
	if err != nil {
		return controlv1.BrowserAccessResponse{}, err
	}
	return c.CheckServiceBrowserSession(ctx, service, run, token, body)
}
func (n *Native) RevokeServiceBrowserSession(ctx context.Context, service, run string, token credentials.ServiceRunToken, body controlv1.ServiceBrowserRequest) error {
	c, err := n.serviceHTTP(service)
	if err != nil {
		return err
	}
	return c.RevokeServiceBrowserSession(ctx, service, run, token, body)
}
