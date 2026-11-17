package identity

import (
	"context"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type serviceHTTPControl interface {
	Discovery(context.Context) (controlv1.ControlDiscovery, error)
	httpaccess.PolicyClient
	httpaccess.TokenClient
	httpaccess.ShareClient
	httpaccess.BrowserClient
	serviceFeedbackControl
}

func (n *Native) Discovery(ctx context.Context) (controlv1.ControlDiscovery, error) {
	if n == nil || n.Services == nil {
		return controlv1.ControlDiscovery{}, ErrScope
	}
	return n.Services.Discovery(ctx)
}

func (n *Native) ReadPublisherVisitorPolicy(ctx context.Context, request controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	if n == nil || request.Resource.Kind != "service" || request.RunNumber < 1 ||
		!opaqueid.Valid(request.RunId, opaqueid.ServiceRunPrefix) || token == "" {
		return controlv1.VisitorPolicyUpdate{}, ErrScope
	}
	control, err := n.serviceHTTP(request.Resource.Id)
	if err != nil {
		return controlv1.VisitorPolicyUpdate{}, err
	}
	return control.ReadPublisherVisitorPolicy(ctx, request, token)
}

func (n *Native) IssueVisitorToken(ctx context.Context, request controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
	if n == nil || request.Resource.Kind != "service" {
		return controlv1.VisitorTokenResponse{}, ErrScope
	}
	control, err := n.serviceHTTP(request.Resource.Id)
	if err != nil {
		return controlv1.VisitorTokenResponse{}, err
	}
	return control.IssueVisitorToken(ctx, request)
}

func (n *Native) serviceHTTP(service string) (serviceHTTPControl, error) {
	if _, err := n.serviceCertificates(service); err != nil {
		return nil, err
	}
	return n.Services, nil
}
func (n *Native) RedeemServiceBrowserHandoff(ctx context.Context, service, run string, token credentials.ServiceRunToken, body controlv1.ServiceBrowserRequest) (controlv1.BrowserHandoffResponse, error) {
	c, err := n.serviceHTTP(service)
	if err != nil {
		return controlv1.BrowserHandoffResponse{}, err
	}
	return c.RedeemServiceBrowserHandoff(ctx, service, run, token, body)
}
func (n *Native) RedeemServiceShare(ctx context.Context, service, run string, body controlv1.RedeemServiceShareRequest, token credentials.ServiceRunToken) (controlv1.ShareRedemption, error) {
	c, err := n.serviceHTTP(service)
	if err != nil {
		return controlv1.ShareRedemption{}, err
	}
	return c.RedeemServiceShare(ctx, service, run, body, token)
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
