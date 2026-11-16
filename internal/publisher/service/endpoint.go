package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/netip"
	"slices"
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
	"github.com/tnldotdev/tnl/internal/security/tlspolicy"
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
	if preparation.RunToken == "" {
		return nil, ErrPrivateStream
	}
	if (len(cfg.Mounts) != 0 || cfg.ResolveHTTPTarget != nil) &&
		(approved.Protocol != controlv1.ServiceProtocolHTTP || cfg.Handler != nil || cfg.TargetResolver != nil) {
		return nil, ErrPrivateStream
	}
	traffic, err := serviceTraffic(preparation.Traffic)
	if err != nil {
		return nil, err
	}
	if approved.Endpoint == nil || !serviceendpoint.Valid(string(approved.Protocol), approved.Endpoint.Hostname, approved.Endpoint.Port, approved.Endpoint.Public) || preparation.CertificatePlan == nil || preparation.ServiceId != approved.Id || !opaqueid.Valid(preparation.ServiceRunId, opaqueid.ServiceRunPrefix) || preparation.TeamId != approved.TeamId || preparation.PublisherIdentityId != cfg.PublisherIdentityID || preparation.PublisherGrantId != cfg.PublisherGrantID || preparation.PublisherKeyId != cfg.PublisherKeyID || preparation.RunNumber < 1 || !preparation.ExpiresAt.After(time.Now()) {
		return nil, ErrPrivateStream
	}
	if preparation.Hostname != approved.Endpoint.Hostname || preparation.DomainId == "" || approved.DomainId != nil && preparation.DomainId != *approved.DomainId || preparation.RequirePostQuantum != approved.RequirePostQuantum {
		return nil, ErrPrivateStream
	}
	capturedPlan := *preparation.CertificatePlan
	capturedPlan.Identifiers = slices.Clone(capturedPlan.Identifiers)
	preparation.CertificatePlan = &capturedPlan
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
	prepared.visitorTLS = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return prepared.currentCertificate() }}
	if preparation.RequirePostQuantum {
		prepared.visitorTLS = tlspolicy.RequirePostQuantum(prepared.visitorTLS)
	}
	prepared.inspectionMode, prepared.observeSummary = cfg.InspectionMode, cfg.ObserveSummary
	prepared.admitRequest = cfg.AdmitRequest
	if cfg.HTTPAdmitRequest != nil {
		if approved.Protocol != controlv1.ServiceProtocolHTTP {
			return nil, ErrPrivateStream
		}
		run := HTTPRun{ServiceID: preparation.ServiceId, RunID: preparation.ServiceRunId,
			Number: preparation.RunNumber, Hostname: preparation.Hostname}
		prepared.admitRequest = func(request *http.Request) error {
			if cfg.AdmitRequest != nil {
				if err := cfg.AdmitRequest(request); err != nil {
					return err
				}
			}
			return cfg.HTTPAdmitRequest(request, run)
		}
	}
	prepared.managedPublic = approved.Endpoint.Public
	prepared.metadataRevision = approved.TrustRevision
	prepared.targetResolver = cfg.TargetResolver
	prepared.mounts = slices.Clone(cfg.Mounts)
	prepared.resolveHTTPTarget = cfg.ResolveHTTPTarget
	if cfg.HTTPResponseHooks != nil {
		if prepared.managedProtocol != serviceconfig.ProtocolHTTP || cfg.Handler != nil {
			return nil, ErrPrivateStream
		}
	}
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
	if cfg.HTTPResponseHooks != nil {
		prepared.httpResponseHooks = cfg.HTTPResponseHooks(HTTPRun{
			ServiceID: preparation.ServiceId, RunID: preparation.ServiceRunId,
			Number: preparation.RunNumber, Hostname: preparation.Hostname,
		})
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

func configureServiceRun(ctx context.Context, config RunConfig, prepared *Prepared, setup controlv1.ServiceRunSetup, control ManagedControl, profile *clientstate.Store, audit serviceaudit.Sink) (func() error, func() error, error) {
	if profile == nil || prepared.Preparation.CertificatePlan == nil {
		return nil, nil, ErrPrivateStream
	}
	if len(setup.VisitorSourceKey) != len(prepared.sourceKey) {
		return nil, nil, ErrPrivateStream
	}
	copy(prepared.sourceKey[:], setup.VisitorSourceKey)
	if prepared.sourceKey == [32]byte{} {
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
			AdmitRequest: prepared.admitRequest, ReadinessProof: proof,
			ResponseHooks: prepared.httpResponseHooks,
			Feedback:      config.Feedback, PreviewID: config.PreviewID,
			ProjectService: config.ProjectService, ProjectRoot: config.ProjectRoot, Demo: config.Demo,
			Control: control, Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: setup.ServiceId},
			RunID: setup.ServiceRunId, Number: setup.RunNumber, Token: credentials.ServiceRunToken(setup.RunToken),
			Hostname: prepared.managedHostname, Port: prepared.servicePort, Requests: prepared.serviceHTTPRequests,
		})
		if err != nil {
			return nil, nil, err
		}
		prepared.connectorHTTP = httpFrontend
		prepared.policy = httpFrontend.Policy
		prepared.httpResponseHooks = httpFrontend.ResponseHooks
		if prepared.handler == nil && prepared.targetResolver == nil {
			target := servicestream.HTTPTarget{Address: prepared.target, Mounts: prepared.mounts, ResolveTarget: prepared.resolveHTTPTarget,
				Transport:   targettransport.Transport{Protocol: prepared.managedProtocol, TLS: prepared.managedTargetTLS},
				Connections: prepared.serviceHTTPRequests.Limits().Concurrency}
			prepared.httpProxy, err = target.NewHTTPProxy(ctx, prepared.managedHostname, prepared.httpResponseHooks)
			if err != nil {
				closeHTTP()
				return nil, nil, err
			}
		}
	}
	decision := func(result controlv1.ServiceClientCertificateDecision, err error) (servicestream.Decision, error) {
		if errors.Is(err, clientcontrol.ErrNotFound) || errors.Is(err, clientcontrol.ErrUnauthenticated) {
			return servicestream.Decision{}, nil
		}
		return servicestream.Decision{Allowed: result.Allowed, ValidUntil: result.ValidUntil}, err
	}
	prepared.managedVisitor = func(header tunnelv1.ServiceForwardingHeader, source netip.AddrPort, reserveCapacity func(context.Context) error) servicestream.Authentication {
		if header.PublicService != nil {
			if prepared.managedProtocol == serviceconfig.ProtocolHTTP {
				frontend := httpFrontend
				frontend.Header = header
				frontend.Source = source
				frontend.ReserveCapacity = reserveCapacity
				return servicestream.HTTPVisitor{Frontend: frontend}
			}
			return servicestream.CertificateVisitor{Check: func(check context.Context, leaf *x509.Certificate) (servicestream.Decision, error) {
				result, err := control.AuthorizeServiceClientCertificate(check, setup.ServiceId, setup.ServiceRunId, credentials.ServiceRunToken(setup.RunToken), controlv1.AuthorizeServiceClientCertificateRequest{RunNumber: setup.RunNumber, VisitorConnectionId: header.VisitorConnectionID, SourceIp: header.SourceIP, DestinationPort: int(header.PublicService.DestinationPort), Certificate: leaf.Raw})
				if err == nil && result.Allowed {
					if reserveCapacity == nil || !result.ValidUntil.After(time.Now()) {
						return servicestream.Decision{}, servicestream.ErrEndpoint
					}
					err = reserveCapacity(check)
				}
				return decision(result, err)
			}}
		}
		return nil
	}
	cache, err := profile.CertificatesForPublisher(prepared.Preparation.TeamId, config.PublisherIdentityID, *prepared.Preparation.CertificatePlan)
	if err != nil {
		closeHTTP()
		if prepared.httpProxy != nil {
			err = errors.Join(err, prepared.httpProxy.Close())
		}
		return nil, nil, err
	}
	installed := make(chan struct{}, 1)
	prepared.certificateInstalled = installed
	certificates := Certificates{Control: control, Cache: cache, ServiceID: setup.ServiceId, RunID: setup.ServiceRunId, PublisherIdentityID: config.PublisherIdentityID, RunNumber: setup.RunNumber, Token: credentials.ServiceRunToken(setup.RunToken), Hostname: prepared.managedHostname, Plan: *prepared.Preparation.CertificatePlan, Install: prepared.installManagedCertificate, installed: installed}
	certificateCtx, cancel := context.WithCancel(ctx)
	return func() error { return certificates.Maintain(certificateCtx) }, func() error {
		cancel()
		closeHTTP()
		if prepared.httpProxy != nil {
			return prepared.httpProxy.Close()
		}
		return nil
	}, nil
}
