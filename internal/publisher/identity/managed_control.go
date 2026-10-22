package native

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// managedControl is the current internal boundary. the legacy Native methods
// retain their public token signatures through an explicit compatibility view.
type managedControl interface {
	PreparePrivateServiceRun(context.Context, string, string, string, ...controlv1.PrivateServiceRunDeclaration) (controlv1.PrivateServiceRunPreparation, error)
	HeartbeatPrivateServiceRun(context.Context, string, string, credentials.ManagedRunToken) (controlv1.PrivateServiceRunState, error)
	HeartbeatPrivateServiceRunHealth(context.Context, string, string, credentials.ManagedRunToken, controlv1.PrivateServiceRunHeartbeat) (controlv1.PrivateServiceRunState, error)
	ClosePrivateServiceRun(context.Context, string, string, credentials.ManagedRunToken) error
	CreatePrivateCertificateIssuance(context.Context, string, string, int64, credentials.ManagedRunToken, []byte, string) (controlv1.PrivateCertificateIssuance, error)
	GetPrivateCertificateIssuance(context.Context, string, string, string, credentials.ManagedRunToken) (controlv1.PrivateCertificateIssuance, error)
	MarkPrivateCertificateInstalled(context.Context, string, string, int64, string, time.Time, credentials.ManagedRunToken) error
	AuthorizeServiceClientCertificate(context.Context, string, string, credentials.ManagedRunToken, controlv1.AuthorizeServiceClientCertificateRequest) (controlv1.ServiceClientCertificateDecision, error)
	AuthorizeServiceConnector(context.Context, string, string, credentials.ManagedRunToken, controlv1.AuthorizeServiceConnectorRequest) (controlv1.ServiceClientCertificateDecision, error)
	AuthorizeManagedHTTPVisitor(context.Context, string, string, credentials.ManagedRunToken, controlv1.ManagedHTTPVisitorRequest) (controlv1.ServiceClientCertificateDecision, error)
	RedeemManagedBrowserHandoff(context.Context, string, string, credentials.ManagedRunToken, controlv1.ManagedBrowserRequest) (controlv1.BrowserHandoffResponse, error)
	CheckManagedBrowserSession(context.Context, string, string, credentials.ManagedRunToken, controlv1.ManagedBrowserRequest) (controlv1.BrowserAccessResponse, error)
	RevokeManagedBrowserSession(context.Context, string, string, credentials.ManagedRunToken, controlv1.ManagedBrowserRequest) error
}

// ManagedControl exposes managed-run tokens to internal lifecycle callers while
// Native, also exported as pkg/tnl.Publisher, keeps its existing method set.
type ManagedControl struct{ *Native }

func (n *Native) ManagedRunControl() *ManagedControl { return &ManagedControl{Native: n} }

func (m *ManagedControl) control(service string) (managedControl, error) {
	if m == nil || m.Native == nil || m.identity.kind != authorityv1.PrivateService || m.identity.privateServiceID != service {
		return nil, ErrScope
	}
	c, ok := m.NativeControl.(managedControl)
	if !ok {
		return nil, ErrScope
	}
	return c, nil
}

func (m *ManagedControl) HeartbeatPrivateServiceRun(ctx context.Context, service, run string, token credentials.ManagedRunToken) (controlv1.PrivateServiceRunState, error) {
	c, err := m.control(service)
	if err != nil {
		return controlv1.PrivateServiceRunState{}, err
	}
	state, err := c.HeartbeatPrivateServiceRun(ctx, service, run, token)
	if err == nil {
		err = m.renewRuntime(ctx)
	}
	return state, err
}

func (m *ManagedControl) HeartbeatPrivateServiceRunHealth(ctx context.Context, service, run string, token credentials.ManagedRunToken, health controlv1.PrivateServiceRunHeartbeat) (controlv1.PrivateServiceRunState, error) {
	c, err := m.control(service)
	if err != nil {
		return controlv1.PrivateServiceRunState{}, err
	}
	state, err := c.HeartbeatPrivateServiceRunHealth(ctx, service, run, token, health)
	if err == nil {
		err = m.renewRuntime(ctx)
	}
	return state, err
}

func (m *ManagedControl) ClosePrivateServiceRun(ctx context.Context, service, run string, token credentials.ManagedRunToken) error {
	c, err := m.control(service)
	if err != nil {
		return err
	}
	return c.ClosePrivateServiceRun(ctx, service, run, token)
}

func (m *ManagedControl) CreatePrivateCertificateIssuance(ctx context.Context, service, run string, number int64, token credentials.ManagedRunToken, csr []byte, key string) (controlv1.PrivateCertificateIssuance, error) {
	c, err := m.control(service)
	if err != nil {
		return controlv1.PrivateCertificateIssuance{}, err
	}
	return c.CreatePrivateCertificateIssuance(ctx, service, run, number, token, csr, key)
}

func (m *ManagedControl) GetPrivateCertificateIssuance(ctx context.Context, service, run, issuance string, token credentials.ManagedRunToken) (controlv1.PrivateCertificateIssuance, error) {
	c, err := m.control(service)
	if err != nil {
		return controlv1.PrivateCertificateIssuance{}, err
	}
	return c.GetPrivateCertificateIssuance(ctx, service, run, issuance, token)
}

func (m *ManagedControl) MarkPrivateCertificateInstalled(ctx context.Context, service, run string, number int64, issuance string, expires time.Time, token credentials.ManagedRunToken) error {
	c, err := m.control(service)
	if err != nil {
		return err
	}
	return c.MarkPrivateCertificateInstalled(ctx, service, run, number, issuance, expires, token)
}

func (m *ManagedControl) AuthorizeServiceClientCertificate(ctx context.Context, service, run string, token credentials.ManagedRunToken, body controlv1.AuthorizeServiceClientCertificateRequest) (controlv1.ServiceClientCertificateDecision, error) {
	c, err := m.control(service)
	if err != nil {
		return controlv1.ServiceClientCertificateDecision{}, err
	}
	return c.AuthorizeServiceClientCertificate(ctx, service, run, token, body)
}

func (m *ManagedControl) AuthorizeServiceConnector(ctx context.Context, service, run string, token credentials.ManagedRunToken, body controlv1.AuthorizeServiceConnectorRequest) (controlv1.ServiceClientCertificateDecision, error) {
	c, err := m.control(service)
	if err != nil {
		return controlv1.ServiceClientCertificateDecision{}, err
	}
	return c.AuthorizeServiceConnector(ctx, service, run, token, body)
}

func (m *ManagedControl) AuthorizeManagedHTTPVisitor(ctx context.Context, service, run string, token credentials.ManagedRunToken, body controlv1.ManagedHTTPVisitorRequest) (controlv1.ServiceClientCertificateDecision, error) {
	c, err := m.control(service)
	if err != nil {
		return controlv1.ServiceClientCertificateDecision{}, err
	}
	return c.AuthorizeManagedHTTPVisitor(ctx, service, run, token, body)
}

func (m *ManagedControl) RedeemManagedBrowserHandoff(ctx context.Context, service, run string, token credentials.ManagedRunToken, body controlv1.ManagedBrowserRequest) (controlv1.BrowserHandoffResponse, error) {
	c, err := m.control(service)
	if err != nil {
		return controlv1.BrowserHandoffResponse{}, err
	}
	return c.RedeemManagedBrowserHandoff(ctx, service, run, token, body)
}

func (m *ManagedControl) CheckManagedBrowserSession(ctx context.Context, service, run string, token credentials.ManagedRunToken, body controlv1.ManagedBrowserRequest) (controlv1.BrowserAccessResponse, error) {
	c, err := m.control(service)
	if err != nil {
		return controlv1.BrowserAccessResponse{}, err
	}
	return c.CheckManagedBrowserSession(ctx, service, run, token, body)
}

func (m *ManagedControl) RevokeManagedBrowserSession(ctx context.Context, service, run string, token credentials.ManagedRunToken, body controlv1.ManagedBrowserRequest) error {
	c, err := m.control(service)
	if err != nil {
		return err
	}
	return c.RevokeManagedBrowserSession(ctx, service, run, token, body)
}

// legacyManagedControl converts only at the public compatibility boundary. its
// heartbeat delegates directly so Native performs runtime renewal exactly once.
type legacyManagedControl struct{ managedControl }

func (c legacyManagedControl) HeartbeatPrivateServiceRun(ctx context.Context, service, run string, token credentials.PublishRunToken) (controlv1.PrivateServiceRunState, error) {
	return c.managedControl.HeartbeatPrivateServiceRun(ctx, service, run, credentials.ManagedRunToken(token))
}
func (c legacyManagedControl) HeartbeatPrivateServiceRunHealth(ctx context.Context, service, run string, token credentials.PublishRunToken, health controlv1.PrivateServiceRunHeartbeat) (controlv1.PrivateServiceRunState, error) {
	return c.managedControl.HeartbeatPrivateServiceRunHealth(ctx, service, run, credentials.ManagedRunToken(token), health)
}
func (c legacyManagedControl) ClosePrivateServiceRun(ctx context.Context, service, run string, token credentials.PublishRunToken) error {
	return c.managedControl.ClosePrivateServiceRun(ctx, service, run, credentials.ManagedRunToken(token))
}
func (c legacyManagedControl) CreatePrivateCertificateIssuance(ctx context.Context, service, run string, number int64, token credentials.PublishRunToken, csr []byte, key string) (controlv1.PrivateCertificateIssuance, error) {
	return c.managedControl.CreatePrivateCertificateIssuance(ctx, service, run, number, credentials.ManagedRunToken(token), csr, key)
}
func (c legacyManagedControl) GetPrivateCertificateIssuance(ctx context.Context, service, run, issuance string, token credentials.PublishRunToken) (controlv1.PrivateCertificateIssuance, error) {
	return c.managedControl.GetPrivateCertificateIssuance(ctx, service, run, issuance, credentials.ManagedRunToken(token))
}
func (c legacyManagedControl) MarkPrivateCertificateInstalled(ctx context.Context, service, run string, number int64, issuance string, expires time.Time, token credentials.PublishRunToken) error {
	return c.managedControl.MarkPrivateCertificateInstalled(ctx, service, run, number, issuance, expires, credentials.ManagedRunToken(token))
}
func (c legacyManagedControl) AuthorizeServiceClientCertificate(ctx context.Context, service, run string, token credentials.PublishRunToken, body controlv1.AuthorizeServiceClientCertificateRequest) (controlv1.ServiceClientCertificateDecision, error) {
	return c.managedControl.AuthorizeServiceClientCertificate(ctx, service, run, credentials.ManagedRunToken(token), body)
}
func (c legacyManagedControl) AuthorizeServiceConnector(ctx context.Context, service, run string, token credentials.PublishRunToken, body controlv1.AuthorizeServiceConnectorRequest) (controlv1.ServiceClientCertificateDecision, error) {
	return c.managedControl.AuthorizeServiceConnector(ctx, service, run, credentials.ManagedRunToken(token), body)
}
func (c legacyManagedControl) AuthorizeManagedHTTPVisitor(ctx context.Context, service, run string, token credentials.PublishRunToken, body controlv1.ManagedHTTPVisitorRequest) (controlv1.ServiceClientCertificateDecision, error) {
	return c.managedControl.AuthorizeManagedHTTPVisitor(ctx, service, run, credentials.ManagedRunToken(token), body)
}
func (c legacyManagedControl) RedeemManagedBrowserHandoff(ctx context.Context, service, run string, token credentials.PublishRunToken, body controlv1.ManagedBrowserRequest) (controlv1.BrowserHandoffResponse, error) {
	return c.managedControl.RedeemManagedBrowserHandoff(ctx, service, run, credentials.ManagedRunToken(token), body)
}
func (c legacyManagedControl) CheckManagedBrowserSession(ctx context.Context, service, run string, token credentials.PublishRunToken, body controlv1.ManagedBrowserRequest) (controlv1.BrowserAccessResponse, error) {
	return c.managedControl.CheckManagedBrowserSession(ctx, service, run, credentials.ManagedRunToken(token), body)
}
func (c legacyManagedControl) RevokeManagedBrowserSession(ctx context.Context, service, run string, token credentials.PublishRunToken, body controlv1.ManagedBrowserRequest) error {
	return c.managedControl.RevokeManagedBrowserSession(ctx, service, run, credentials.ManagedRunToken(token), body)
}
