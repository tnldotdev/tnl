package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	serviceconfig "github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/tcptarget"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisher/visitorpolicy"
	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ManagedControl interface {
	visitorpolicy.Client
	publisher.ServiceCertificateControl
	publisher.ServiceHTTPControl
	StartServiceRun(context.Context, string, string, string, int64) (controlv1.ServiceRunSetup, error)
	AuthorizeServiceClientCertificate(context.Context, string, string, credentials.ServiceRunToken, controlv1.AuthorizeServiceClientCertificateRequest) (controlv1.ServiceClientCertificateDecision, error)
}

func newManagedPrepared(preparation controlv1.ServiceRunPreparation, approved controlv1.Service, cfg RunConfig) (*Prepared, error) {
	if approved.Endpoint == nil || approved.Endpoint.Port < 1024 || approved.Endpoint.Port > 65535 || preparation.CertificatePlan == nil || preparation.ServiceId != approved.Id || preparation.TeamId != approved.TeamId || preparation.PublisherIdentityId != cfg.Identity.ClientId || preparation.PublisherGrantId != cfg.Identity.GrantId || preparation.PublisherKeyId != cfg.Identity.KeyId || preparation.RunNumber < 1 || !preparation.ExpiresAt.After(time.Now()) {
		return nil, ErrPrivateStream
	}
	if preparation.Hostname != approved.Endpoint.Hostname || preparation.ServicePort != approved.Endpoint.Port || preparation.DomainId == "" || approved.DomainId != nil && preparation.DomainId != *approved.DomainId {
		return nil, ErrPrivateStream
	}
	plan, err := certificateidentity.CanonicalPlan(*preparation.CertificatePlan)
	if err != nil || !certificateidentity.Covers(plan.Identifiers, approved.Endpoint.Hostname) || plan.ChallengeMethod != controlv1.Dns01 {
		return nil, ErrPrivateStream
	}
	target, err := tcptarget.Normalize(cfg.Target)
	if err != nil {
		return nil, err
	}
	prepared := &Prepared{Preparation: preparation, target: target, managedHostname: approved.Endpoint.Hostname, servicePort: uint16(approved.Endpoint.Port), managedProtocol: serviceconfig.ProtocolName(approved.Protocol), metadataRevision: approved.TrustRevision, clock: time.Now, preparedCertificate: &preparedCertificate{}}
	prepared.managedPublic = approved.Endpoint.Public
	prepared.targetResolver = cfg.TargetResolver
	if prepared.managedProtocol == serviceconfig.ProtocolHTTP || prepared.managedProtocol == serviceconfig.ProtocolKubernetes {
		prepared.serviceHTTPRequests, err = publisher.NewServiceHTTPRequestLimits(approved.HttpLimits)
		if err != nil {
			return nil, err
		}
	}
	trust, err := targetTrust(approved)
	if err != nil {
		return nil, err
	}
	if cfg.TargetResolver != nil {
		if trust != nil {
			return nil, ErrPrivateStream
		}
		if cfg.resolvedTargetTLS == nil {
			return nil, ErrPrivateStream
		}
		prepared.managedTargetTLS = cfg.resolvedTargetTLS.Clone()
	} else {
		transport, err := targettransport.FromTrust(prepared.managedProtocol, trust)
		if err != nil {
			return nil, err
		}
		prepared.managedTargetTLS = transport.TLS
	}
	return prepared, nil
}

func targetTrust(approved controlv1.Service) (*targettrust.Snapshot, error) {
	if approved.TargetTls == nil {
		return nil, nil
	}
	value := approved.TargetTls
	trust := &targettrust.Snapshot{Hostname: value.Hostname, System: value.System, Digest: value.Digest}
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

func configureServiceRun(ctx context.Context, config RunConfig, prepared *Prepared, setup controlv1.ServiceRunSetup, control ManagedControl, profile *clientstate.Store) (func() error, func(), error) {
	if profile == nil || prepared.Preparation.CertificatePlan == nil {
		return nil, nil, ErrPrivateStream
	}
	decision := func(result controlv1.ServiceClientCertificateDecision, err error) (publisher.ServiceVisitorDecision, error) {
		if errors.Is(err, clientcontrol.ErrNotFound) || errors.Is(err, clientcontrol.ErrUnauthenticated) {
			return publisher.ServiceVisitorDecision{}, nil
		}
		return publisher.ServiceVisitorDecision{Allowed: result.Allowed, ValidUntil: result.ValidUntil}, err
	}
	awaitAdmission := func(ctx context.Context, authorize func(context.Context) (controlv1.ServiceClientCertificateDecision, error)) (publisher.ServiceVisitorDecision, error) {
		for {
			result, err := authorize(ctx)
			if err != nil || !result.Allowed || result.Admitted {
				return decision(result, err)
			}
			observability.PublisherAuthorization(ctx, true, false, nil)
			_, endWait := observability.Start(ctx, "publisher.admission_retry_wait")
			timer := time.NewTimer(25 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				endWait(context.Cause(ctx))
				return publisher.ServiceVisitorDecision{}, context.Cause(ctx)
			case <-timer.C:
				endWait(nil)
			}
		}
	}
	prepared.managedVisitor = func(header tunnelv1.ServiceForwardingHeader) publisher.ServiceVisitorAuthentication {
		if header.Direct != nil && header.Connector == nil {
			if prepared.managedProtocol == serviceconfig.ProtocolHTTP {
				return publisher.PublicHTTPVisitor{Frontend: publisher.ServiceHTTP{
					Control: control, Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: setup.ServiceId},
					RunID: setup.ServiceRunId, Number: setup.RunNumber, Token: credentials.ServiceRunToken(setup.RunToken),
					Hostname: prepared.managedHostname, Port: prepared.servicePort, Header: header,
					Requests: prepared.serviceHTTPRequests,
				}}
			}
			return publisher.CertificateVisitor{Check: func(check context.Context, leaf *x509.Certificate) (publisher.ServiceVisitorDecision, error) {
				return awaitAdmission(check, func(ctx context.Context) (controlv1.ServiceClientCertificateDecision, error) {
					return control.AuthorizeServiceClientCertificate(ctx, setup.ServiceId, setup.ServiceRunId, credentials.ServiceRunToken(setup.RunToken), controlv1.AuthorizeServiceClientCertificateRequest{RunNumber: setup.RunNumber, VisitorConnectionId: header.VisitorConnectionID, SourceIp: header.SourceIP, Certificate: leaf.Raw})
				})
			}}
		}
		return nil
	}
	cache, err := profile.CertificatesForPublisher(prepared.Preparation.TeamId, config.Identity.ClientId, *prepared.Preparation.CertificatePlan)
	if err != nil {
		return nil, nil, err
	}
	certificates := publisher.ServiceCertificates{Control: control, Cache: cache, ServiceID: setup.ServiceId, RunID: setup.ServiceRunId, PublisherIdentityID: config.Identity.ClientId, RunNumber: setup.RunNumber, Token: credentials.ServiceRunToken(setup.RunToken), Hostname: prepared.managedHostname, Plan: *prepared.Preparation.CertificatePlan, Install: prepared.installManagedCertificate}
	certificateCtx, cancel := context.WithCancel(ctx)
	return func() error { return certificates.Maintain(certificateCtx) }, cancel, nil
}
