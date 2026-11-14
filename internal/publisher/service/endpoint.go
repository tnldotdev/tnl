package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"

	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"

	serviceconfig "github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/serviceendpoint"
	"github.com/tnldotdev/tnl/internal/policy/tcptarget"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ManagedControl interface {
	CertificateControl
	HTTPControl
	StartServiceRun(context.Context, string, string, string, int64) (controlv1.ServiceRunSetup, error)
	AuthorizeServiceClientCertificate(context.Context, string, string, credentials.ServiceRunToken, controlv1.AuthorizeServiceClientCertificateRequest) (controlv1.ServiceClientCertificateDecision, error)
}

func newManagedPrepared(preparation controlv1.ServiceRunPreparation, approved controlv1.Service, cfg RunConfig) (*Prepared, error) {
	traffic, err := serviceTraffic(preparation.Traffic)
	if err != nil {
		return nil, err
	}
	if approved.Endpoint == nil || !serviceendpoint.Valid(string(approved.Protocol), approved.Endpoint.Hostname, approved.Endpoint.Port, approved.Endpoint.Public) || preparation.CertificatePlan == nil || preparation.ServiceId != approved.Id || !opaqueid.Valid(preparation.ServiceRunId, opaqueid.ServiceRunPrefix) || preparation.TeamId != approved.TeamId || preparation.PublisherIdentityId != cfg.Identity.ClientId || preparation.PublisherGrantId != cfg.Identity.GrantId || preparation.PublisherKeyId != cfg.Identity.KeyId || preparation.RunNumber < 1 || !preparation.ExpiresAt.After(time.Now()) {
		return nil, ErrPrivateStream
	}
	if preparation.Hostname != approved.Endpoint.Hostname || preparation.DomainId == "" || approved.DomainId != nil && preparation.DomainId != *approved.DomainId {
		return nil, ErrPrivateStream
	}
	plan, err := certificateidentity.CanonicalPlan(*preparation.CertificatePlan)
	if err != nil || !certificateidentity.Covers(plan.Identifiers, approved.Endpoint.Hostname) || plan.ChallengeMethod != controlv1.Dns01 {
		return nil, ErrPrivateStream
	}
	target := ""
	if cfg.Handler != nil {
		if approved.Protocol != controlv1.ServiceProtocolHTTP || cfg.Target != "" || cfg.TargetResolver != nil || approved.TargetTls != nil {
			return nil, ErrPrivateStream
		}
	} else {
		target, err = tcptarget.Normalize(cfg.Target)
		if err != nil {
			return nil, err
		}
	}
	preparation.Traffic = cloneTrafficApproval(preparation.Traffic)
	prepared := &Prepared{Preparation: preparation, traffic: traffic, target: target, handler: cfg.Handler, managedHostname: approved.Endpoint.Hostname, servicePort: uint16(approved.Endpoint.Port), managedProtocol: serviceconfig.ProtocolName(approved.Protocol), clock: time.Now, preparedCertificate: &preparedCertificate{}}
	prepared.inspectionMode, prepared.observeSummary = cfg.InspectionMode, cfg.ObserveSummary
	prepared.admitRequest = cfg.AdmitRequest
	prepared.managedPublic = approved.Endpoint.Public
	prepared.metadataRevision = approved.TrustRevision
	prepared.targetResolver = cfg.TargetResolver
	if prepared.managedProtocol == serviceconfig.ProtocolHTTP || prepared.managedProtocol == serviceconfig.ProtocolKubernetes {
		prepared.serviceHTTPRequests, err = requestlimit.NewHTTP(approved.HttpLimits)
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

func configureServiceRun(ctx context.Context, config RunConfig, prepared *Prepared, setup controlv1.ServiceRunSetup, control ManagedControl, profile *clientstate.Store, audit serviceaudit.Sink) (func() error, func(), error) {
	if profile == nil || prepared.Preparation.CertificatePlan == nil {
		return nil, nil, ErrPrivateStream
	}
	closeHTTP := func() {}
	var httpFrontend HTTP
	if prepared.managedProtocol == serviceconfig.ProtocolHTTP {
		var proof *httpaccess.ReadinessProof
		if config.ReadinessProof != nil {
			proof = config.ReadinessProof(httpaccess.ReadinessRun{Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: setup.ServiceId},
				ID: setup.ServiceRunId, Number: uint64(setup.RunNumber), Hostname: prepared.managedHostname})
			if proof == nil {
				return nil, nil, ErrPrivateStream
			}
		}
		var err error
		httpFrontend, closeHTTP, err = PrepareHTTP(ctx, HTTP{
			AuditSink:      audit,
			InspectionMode: config.InspectionMode, ObserveSummary: config.ObserveSummary,
			AdmitRequest: config.AdmitRequest, ReadinessProof: proof,
			Control: control, Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: setup.ServiceId},
			RunID: setup.ServiceRunId, Number: setup.RunNumber, Token: credentials.ServiceRunToken(setup.RunToken),
			Hostname: prepared.managedHostname, Port: prepared.servicePort, Requests: prepared.serviceHTTPRequests,
		})
		if err != nil {
			return nil, nil, err
		}
	}
	decision := func(result controlv1.ServiceClientCertificateDecision, err error) (servicestream.Decision, error) {
		if errors.Is(err, clientcontrol.ErrNotFound) || errors.Is(err, clientcontrol.ErrUnauthenticated) {
			return servicestream.Decision{}, nil
		}
		return servicestream.Decision{Allowed: result.Allowed, ValidUntil: result.ValidUntil}, err
	}
	prepared.managedVisitor = func(header tunnelv1.ServiceForwardingHeader) servicestream.Authentication {
		if header.PublicService != nil {
			if prepared.managedProtocol == serviceconfig.ProtocolHTTP {
				frontend := httpFrontend
				frontend.Header = header
				return servicestream.HTTPVisitor{Frontend: frontend}
			}
			return servicestream.CertificateVisitor{Check: func(check context.Context, leaf *x509.Certificate) (servicestream.Decision, error) {
				result, err := awaitServiceVisitorAdmission(check, func(ctx context.Context) (controlv1.ServiceClientCertificateDecision, error) {
					return control.AuthorizeServiceClientCertificate(ctx, setup.ServiceId, setup.ServiceRunId, credentials.ServiceRunToken(setup.RunToken), controlv1.AuthorizeServiceClientCertificateRequest{RunNumber: setup.RunNumber, VisitorConnectionId: header.VisitorConnectionID, SourceIp: header.SourceIP, DestinationPort: int(header.PublicService.DestinationPort), Certificate: leaf.Raw})
				})
				return decision(result, err)
			}}
		}
		return nil
	}
	cache, err := profile.CertificatesForPublisher(prepared.Preparation.TeamId, config.Identity.ClientId, *prepared.Preparation.CertificatePlan)
	if err != nil {
		closeHTTP()
		return nil, nil, err
	}
	certificates := Certificates{Control: control, Cache: cache, ServiceID: setup.ServiceId, RunID: setup.ServiceRunId, PublisherIdentityID: config.Identity.ClientId, RunNumber: setup.RunNumber, Token: credentials.ServiceRunToken(setup.RunToken), Hostname: prepared.managedHostname, Plan: *prepared.Preparation.CertificatePlan, Install: prepared.installManagedCertificate}
	certificateCtx, cancel := context.WithCancel(ctx)
	return func() error { return certificates.Maintain(certificateCtx) }, func() { cancel(); closeHTTP() }, nil
}
