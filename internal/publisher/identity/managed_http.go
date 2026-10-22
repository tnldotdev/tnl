package native

import (
	"context"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type managedHTTPControl interface {
	AuthorizeManagedHTTPVisitor(context.Context, string, string, credentials.PublishRunToken, controlv1.ManagedHTTPVisitorRequest) (controlv1.ServiceClientCertificateDecision, error)
	RedeemManagedBrowserHandoff(context.Context, string, string, credentials.PublishRunToken, controlv1.ManagedBrowserRequest) (controlv1.BrowserHandoffResponse, error)
	CheckManagedBrowserSession(context.Context, string, string, credentials.PublishRunToken, controlv1.ManagedBrowserRequest) (controlv1.BrowserAccessResponse, error)
	RevokeManagedBrowserSession(context.Context, string, string, credentials.PublishRunToken, controlv1.ManagedBrowserRequest) error
}

func (n *Native) managedHTTP(service string) (managedHTTPControl, error) {
	if _, err := n.managedCertificates(service); err != nil {
		return nil, err
	}
	if control, ok := n.NativeControl.(managedControl); ok {
		return legacyManagedControl{control}, nil
	}
	control, ok := n.NativeControl.(managedHTTPControl)
	if !ok {
		return nil, ErrScope
	}
	return control, nil
}
func (n *Native) AuthorizeManagedHTTPVisitor(ctx context.Context, service, run string, token credentials.PublishRunToken, body controlv1.ManagedHTTPVisitorRequest) (controlv1.ServiceClientCertificateDecision, error) {
	c, err := n.managedHTTP(service)
	if err != nil {
		return controlv1.ServiceClientCertificateDecision{}, err
	}
	return c.AuthorizeManagedHTTPVisitor(ctx, service, run, token, body)
}
func (n *Native) RedeemManagedBrowserHandoff(ctx context.Context, service, run string, token credentials.PublishRunToken, body controlv1.ManagedBrowserRequest) (controlv1.BrowserHandoffResponse, error) {
	c, err := n.managedHTTP(service)
	if err != nil {
		return controlv1.BrowserHandoffResponse{}, err
	}
	return c.RedeemManagedBrowserHandoff(ctx, service, run, token, body)
}
func (n *Native) CheckManagedBrowserSession(ctx context.Context, service, run string, token credentials.PublishRunToken, body controlv1.ManagedBrowserRequest) (controlv1.BrowserAccessResponse, error) {
	c, err := n.managedHTTP(service)
	if err != nil {
		return controlv1.BrowserAccessResponse{}, err
	}
	return c.CheckManagedBrowserSession(ctx, service, run, token, body)
}
func (n *Native) RevokeManagedBrowserSession(ctx context.Context, service, run string, token credentials.PublishRunToken, body controlv1.ManagedBrowserRequest) error {
	c, err := n.managedHTTP(service)
	if err != nil {
		return err
	}
	return c.RevokeManagedBrowserSession(ctx, service, run, token, body)
}
