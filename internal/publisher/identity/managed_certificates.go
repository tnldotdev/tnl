package native

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type ManagedCertificateControl interface {
	CreatePrivateCertificateIssuance(context.Context, string, string, int64, credentials.PublishRunToken, []byte, string) (controlv1.PrivateCertificateIssuance, error)
	GetPrivateCertificateIssuance(context.Context, string, string, string, credentials.PublishRunToken) (controlv1.PrivateCertificateIssuance, error)
	MarkPrivateCertificateInstalled(context.Context, string, string, int64, string, time.Time, credentials.PublishRunToken) error
}

func (n *Native) managedCertificates(service string) (ManagedCertificateControl, error) {
	if n.identity.kind != authorityv1.PrivateService || n.identity.privateServiceID != service {
		return nil, ErrScope
	}
	if control, ok := n.NativeControl.(managedControl); ok {
		return legacyManagedControl{control}, nil
	}
	control, ok := n.NativeControl.(ManagedCertificateControl)
	if !ok {
		return nil, ErrScope
	}
	return control, nil
}

func (n *Native) CreatePrivateCertificateIssuance(ctx context.Context, service, run string, number int64, token credentials.PublishRunToken, csr []byte, key string) (controlv1.PrivateCertificateIssuance, error) {
	control, err := n.managedCertificates(service)
	if err != nil {
		return controlv1.PrivateCertificateIssuance{}, err
	}
	return control.CreatePrivateCertificateIssuance(ctx, service, run, number, token, csr, key)
}

func (n *Native) GetPrivateCertificateIssuance(ctx context.Context, service, run, issuance string, token credentials.PublishRunToken) (controlv1.PrivateCertificateIssuance, error) {
	control, err := n.managedCertificates(service)
	if err != nil {
		return controlv1.PrivateCertificateIssuance{}, err
	}
	return control.GetPrivateCertificateIssuance(ctx, service, run, issuance, token)
}

func (n *Native) MarkPrivateCertificateInstalled(ctx context.Context, service, run string, number int64, issuance string, expires time.Time, token credentials.PublishRunToken) error {
	control, err := n.managedCertificates(service)
	if err != nil {
		return err
	}
	return control.MarkPrivateCertificateInstalled(ctx, service, run, number, issuance, expires, token)
}

func (n *Native) StartManagedServiceRun(ctx context.Context, service, run, access string, number int64) (controlv1.PrivateServiceRunSetup, error) {
	if _, err := n.managedCertificates(service); err != nil {
		return controlv1.PrivateServiceRunSetup{}, err
	}
	control, ok := n.NativeControl.(interface {
		StartManagedServiceRun(context.Context, string, string, string, int64) (controlv1.PrivateServiceRunSetup, error)
	})
	if !ok {
		return controlv1.PrivateServiceRunSetup{}, ErrScope
	}
	return control.StartManagedServiceRun(ctx, service, run, access, number)
}

func (n *Native) AuthorizeServiceClientCertificate(ctx context.Context, service, run string, token credentials.PublishRunToken, body controlv1.AuthorizeServiceClientCertificateRequest) (controlv1.ServiceClientCertificateDecision, error) {
	if _, err := n.managedCertificates(service); err != nil {
		return controlv1.ServiceClientCertificateDecision{}, err
	}
	if control, ok := n.NativeControl.(managedControl); ok {
		return control.AuthorizeServiceClientCertificate(ctx, service, run, credentials.ManagedRunToken(token), body)
	}
	control, ok := n.NativeControl.(interface {
		AuthorizeServiceClientCertificate(context.Context, string, string, credentials.PublishRunToken, controlv1.AuthorizeServiceClientCertificateRequest) (controlv1.ServiceClientCertificateDecision, error)
	})
	if !ok {
		return controlv1.ServiceClientCertificateDecision{}, ErrScope
	}
	return control.AuthorizeServiceClientCertificate(ctx, service, run, token, body)
}

func (n *Native) AuthorizeServiceConnector(ctx context.Context, service, run string, token credentials.PublishRunToken, body controlv1.AuthorizeServiceConnectorRequest) (controlv1.ServiceClientCertificateDecision, error) {
	if _, err := n.managedCertificates(service); err != nil {
		return controlv1.ServiceClientCertificateDecision{}, err
	}
	if control, ok := n.NativeControl.(managedControl); ok {
		return control.AuthorizeServiceConnector(ctx, service, run, credentials.ManagedRunToken(token), body)
	}
	control, ok := n.NativeControl.(interface {
		AuthorizeServiceConnector(context.Context, string, string, credentials.PublishRunToken, controlv1.AuthorizeServiceConnectorRequest) (controlv1.ServiceClientCertificateDecision, error)
	})
	if !ok {
		return controlv1.ServiceClientCertificateDecision{}, ErrScope
	}
	return control.AuthorizeServiceConnector(ctx, service, run, token, body)
}
