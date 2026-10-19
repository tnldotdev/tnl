package privatepublisher

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/clientstate"
	serviceconfig "github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/httpsubject"
	"github.com/tnldotdev/tnl/internal/privatetrust"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/tcptarget"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ManagedControl interface {
	publisher.ManagedCertificateControl
	publisher.ManagedHTTPControl
	StartManagedServiceRun(context.Context, string, string, string, int64) (controlv1.PrivateServiceRunSetup, error)
	AuthorizeServiceConnector(context.Context, string, string, credentials.PublishRunToken, controlv1.AuthorizeServiceConnectorRequest) (controlv1.ServiceClientCertificateDecision, error)
	AuthorizeServiceClientCertificate(context.Context, string, string, credentials.PublishRunToken, controlv1.AuthorizeServiceClientCertificateRequest) (controlv1.ServiceClientCertificateDecision, error)
}

func newManagedPrepared(preparation controlv1.PrivateServiceRunPreparation, approved controlv1.PrivateService, cfg RunConfig) (*Prepared, error) {
	if approved.ManagedTls == nil || approved.ManagedTls.Port < 1024 || approved.ManagedTls.Port > 65535 || preparation.CertificatePlan == nil || preparation.PrivateServiceId != approved.Id || preparation.TeamId != approved.TeamId || preparation.PublisherIdentityId != cfg.Identity.ClientId || preparation.PublisherGrantId != cfg.Identity.GrantId || preparation.PublisherKeyId != cfg.Identity.KeyId || preparation.RunNumber < 1 || !preparation.ExpiresAt.After(time.Now()) {
		return nil, ErrPrivateStream
	}
	if preparation.Hostname != approved.ManagedTls.Hostname || preparation.ServicePort != approved.ManagedTls.Port || preparation.DomainId == "" || approved.DomainId != nil && preparation.DomainId != *approved.DomainId {
		return nil, ErrPrivateStream
	}
	plan, err := certificateidentity.CanonicalPlan(*preparation.CertificatePlan)
	if err != nil || !certificateidentity.Covers(plan.Identifiers, approved.ManagedTls.Hostname) || plan.ChallengeMethod != controlv1.Dns01 {
		return nil, ErrPrivateStream
	}
	target, err := tcptarget.Normalize(cfg.Target)
	if err != nil {
		return nil, err
	}
	prepared := &Prepared{Preparation: preparation, target: target, managedHostname: approved.ManagedTls.Hostname, managedPort: uint16(approved.ManagedTls.Port), managedProtocol: serviceconfig.ProtocolName(approved.Protocol), clock: time.Now, preparedCertificate: &preparedCertificate{}}
	if prepared.managedProtocol == serviceconfig.ProtocolHTTP {
		prepared.managedHTTPRequests, err = publisher.NewManagedHTTPRequestLimits(approved.HttpLimits)
		if err != nil {
			return nil, err
		}
	}
	trust, err := targetTrust(approved)
	if err != nil {
		return nil, err
	}
	if trust != nil {
		prepared.managedTargetTLS, err = trust.Verifier()
		if err != nil {
			return nil, err
		}
	}
	return prepared, nil
}

func targetTrust(approved controlv1.PrivateService) (*privatetrust.Snapshot, error) {
	if approved.TargetTls == nil {
		return nil, nil
	}
	value := approved.TargetTls
	trust := &privatetrust.Snapshot{Hostname: value.Hostname, System: value.System, Digest: value.Digest}
	if value.Pem != nil {
		trust.PEM = []byte(*value.Pem)
	}
	_, err := trust.Verifier()
	return trust, err
}

func (p *Prepared) installManagedCertificate(certificate tls.Certificate) error {
	if p == nil || p.Preparation.CertificatePlan == nil {
		return ErrPrivateStream
	}
	leaf, err := certificateidentity.ValidateCertificate(certificate, p.managedHostname, p.Preparation.CertificatePlan.Identifiers)
	if err != nil {
		return err
	}
	certificate.Leaf = leaf
	p.certMu.Lock()
	p.certificate, p.certValidTo = certificate, leaf.NotAfter
	p.certMu.Unlock()
	return nil
}

func configureManagedRun(ctx context.Context, config RunConfig, prepared *Prepared, setup controlv1.PrivateServiceRunSetup, control ManagedControl, profile *clientstate.Store) (func() error, func(), error) {
	if profile == nil || prepared.Preparation.CertificatePlan == nil {
		return nil, nil, ErrPrivateStream
	}
	decision := func(result controlv1.ServiceClientCertificateDecision, err error) (publisher.ManagedVisitorDecision, error) {
		if errors.Is(err, controlclient.ErrNotFound) || errors.Is(err, controlclient.ErrUnauthenticated) {
			return publisher.ManagedVisitorDecision{}, nil
		}
		return publisher.ManagedVisitorDecision{Allowed: result.Allowed, ValidUntil: result.ValidUntil}, err
	}
	prepared.managedVisitor = func(header tunnelv1.PrivateForwardingHeader) publisher.ManagedVisitorAuthentication {
		if header.Connector != nil && header.Direct == nil {
			return publisher.ConnectorVisitor{Check: func(check context.Context) (publisher.ManagedVisitorDecision, error) {
				return decision(control.AuthorizeServiceConnector(check, setup.PrivateServiceId, setup.PrivateRunId, credentials.PublishRunToken(setup.RunToken), controlv1.AuthorizeServiceConnectorRequest{RunNumber: setup.RunNumber, VisitorConnectionId: header.VisitorConnectionID, SourceIp: header.SourceIP, ConnectorSessionId: header.Connector.SessionID, IdentityId: header.Connector.IdentityID, DeviceId: header.Connector.DeviceID}))
			}}
		}
		if header.Direct != nil && header.Connector == nil {
			if prepared.managedProtocol == serviceconfig.ProtocolHTTP {
				return publisher.PublicHTTPVisitor{Frontend: publisher.ManagedHTTP{
					Control: control, Subject: httpsubject.Subject{Kind: httpsubject.ManagedService, ID: setup.PrivateServiceId},
					RunID: setup.PrivateRunId, Number: setup.RunNumber, Token: credentials.PublishRunToken(setup.RunToken),
					Hostname: prepared.managedHostname, Port: prepared.managedPort, Header: header,
					Requests: prepared.managedHTTPRequests,
				}}
			}
			return publisher.CertificateVisitor{Check: func(check context.Context, leaf *x509.Certificate) (publisher.ManagedVisitorDecision, error) {
				for {
					result, err := control.AuthorizeServiceClientCertificate(check, setup.PrivateServiceId, setup.PrivateRunId, credentials.PublishRunToken(setup.RunToken), controlv1.AuthorizeServiceClientCertificateRequest{RunNumber: setup.RunNumber, VisitorConnectionId: header.VisitorConnectionID, SourceIp: header.SourceIP, Certificate: leaf.Raw})
					if err != nil || !result.Allowed || result.Admitted {
						return decision(result, err)
					}
					timer := time.NewTimer(25 * time.Millisecond)
					select {
					case <-check.Done():
						timer.Stop()
						return publisher.ManagedVisitorDecision{}, context.Cause(check)
					case <-timer.C:
					}
				}
			}}
		}
		return nil
	}
	cache, err := profile.CertificatesForPublisher(prepared.Preparation.TeamId, config.Identity.ClientId, *prepared.Preparation.CertificatePlan)
	if err != nil {
		return nil, nil, err
	}
	certificates := publisher.ManagedCertificates{Control: control, Cache: cache, ServiceID: setup.PrivateServiceId, RunID: setup.PrivateRunId, PublisherID: config.Identity.ClientId, RunNumber: setup.RunNumber, Token: credentials.PublishRunToken(setup.RunToken), Hostname: prepared.managedHostname, Plan: *prepared.Preparation.CertificatePlan, Install: prepared.installManagedCertificate}
	certificateCtx, cancel := context.WithCancel(ctx)
	return func() error { return certificates.Maintain(certificateCtx) }, cancel, nil
}
