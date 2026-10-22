package identity

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type ServiceCertificateControl interface {
	CreateServiceCertificateIssuance(context.Context, string, string, int64, credentials.ServiceRunToken, []byte, string) (controlv1.ServiceCertificateIssuance, error)
	GetServiceCertificateIssuance(context.Context, string, string, string, credentials.ServiceRunToken) (controlv1.ServiceCertificateIssuance, error)
	MarkServiceCertificateInstalled(context.Context, string, string, int64, string, time.Time, credentials.ServiceRunToken) error
}

func (n *Native) serviceCertificates(service string) (ServiceCertificateControl, error) {
	if n.identity.kind != authorityv1.Service || n.identity.serviceID != service {
		return nil, ErrScope
	}
	control, ok := n.NativeControl.(ServiceCertificateControl)
	if !ok {
		return nil, ErrScope
	}
	return control, nil
}

func (n *Native) CreateServiceCertificateIssuance(ctx context.Context, service, run string, number int64, token credentials.ServiceRunToken, csr []byte, key string) (controlv1.ServiceCertificateIssuance, error) {
	control, err := n.serviceCertificates(service)
	if err != nil {
		return controlv1.ServiceCertificateIssuance{}, err
	}
	return control.CreateServiceCertificateIssuance(ctx, service, run, number, token, csr, key)
}

func (n *Native) GetServiceCertificateIssuance(ctx context.Context, service, run, issuance string, token credentials.ServiceRunToken) (controlv1.ServiceCertificateIssuance, error) {
	control, err := n.serviceCertificates(service)
	if err != nil {
		return controlv1.ServiceCertificateIssuance{}, err
	}
	return control.GetServiceCertificateIssuance(ctx, service, run, issuance, token)
}

func (n *Native) MarkServiceCertificateInstalled(ctx context.Context, service, run string, number int64, issuance string, expires time.Time, token credentials.ServiceRunToken) error {
	control, err := n.serviceCertificates(service)
	if err != nil {
		return err
	}
	return control.MarkServiceCertificateInstalled(ctx, service, run, number, issuance, expires, token)
}

func (n *Native) StartServiceRun(ctx context.Context, service, run, access string, number int64) (controlv1.ServiceRunSetup, error) {
	if _, err := n.serviceCertificates(service); err != nil {
		return controlv1.ServiceRunSetup{}, err
	}
	control, ok := n.NativeControl.(interface {
		StartServiceRun(context.Context, string, string, string, int64) (controlv1.ServiceRunSetup, error)
	})
	if !ok {
		return controlv1.ServiceRunSetup{}, ErrScope
	}
	return control.StartServiceRun(ctx, service, run, access, number)
}

func (n *Native) AuthorizeServiceClientCertificate(ctx context.Context, service, run string, token credentials.ServiceRunToken, body controlv1.AuthorizeServiceClientCertificateRequest) (controlv1.ServiceClientCertificateDecision, error) {
	if _, err := n.serviceCertificates(service); err != nil {
		return controlv1.ServiceClientCertificateDecision{}, err
	}
	control, ok := n.NativeControl.(interface {
		AuthorizeServiceClientCertificate(context.Context, string, string, credentials.ServiceRunToken, controlv1.AuthorizeServiceClientCertificateRequest) (controlv1.ServiceClientCertificateDecision, error)
	})
	if !ok {
		return controlv1.ServiceClientCertificateDecision{}, ErrScope
	}
	return control.AuthorizeServiceClientCertificate(ctx, service, run, token, body)
}

func (n *Native) AuthorizeServiceConnector(ctx context.Context, service, run string, token credentials.ServiceRunToken, body controlv1.AuthorizeServiceConnectorRequest) (controlv1.ServiceClientCertificateDecision, error) {
	if _, err := n.serviceCertificates(service); err != nil {
		return controlv1.ServiceClientCertificateDecision{}, err
	}
	control, ok := n.NativeControl.(interface {
		AuthorizeServiceConnector(context.Context, string, string, credentials.ServiceRunToken, controlv1.AuthorizeServiceConnectorRequest) (controlv1.ServiceClientCertificateDecision, error)
	})
	if !ok {
		return controlv1.ServiceClientCertificateDecision{}, ErrScope
	}
	return control.AuthorizeServiceConnector(ctx, service, run, token, body)
}
