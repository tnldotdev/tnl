package publisher

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func runSession(
	ctx context.Context,
	config Config,
	setup controlv1.PublishRunSetup,
	ready func() error,
) (result error) {
	authority, err := bindPublicRun(config, setup)
	if err != nil {
		return err
	}
	plan := authority.plan
	observability.PublisherLease(ctx, setup.PublishRun.ExpiresAt)
	setup.CertificatePlan = plan
	config.PublisherIdentityID, err = configuredPublisherIdentityID(config)
	if err != nil {
		return err
	}
	state, err := config.State.CertificatesForPublisher(setup.PublicUrl.TeamId, config.PublisherIdentityID, plan)
	if err != nil {
		return err
	}
	publishRunToken := authority.token
	version := authority.identity.Number
	var auditSink serviceaudit.Sink
	if reporter, ok := config.Control.(interface {
		ReportPublisherServiceObservations(context.Context, string, uint64, credentials.PublishRunToken, serviceaudit.Batch) error
	}); ok {
		queue, err := serviceaudit.NewQueue(context.WithoutCancel(ctx), serviceaudit.QueueConfig{
			Report: func(ctx context.Context, batch serviceaudit.Batch) error {
				return reporter.ReportPublisherServiceObservations(ctx, setup.PublishRun.Id, version, publishRunToken, batch)
			},
			Dropped: func(count uint64) {
				if config.Logf != nil {
					config.Logf("publisher: service audit dropped %d observations", count)
				}
			},
		})
		if err != nil {
			return err
		}
		auditSink = queue
		defer func() {
			flush, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if queue.Close(flush) != nil && config.Logf != nil {
				config.Logf("publisher: service audit flush incomplete")
			}
		}()
	}
	progress := func(stage string) error {
		return observe(config, Event{Type: EventProvisioningStep, PublicURLID: setup.PublicUrl.Id,
			Hostname: setup.PublicUrl.CanonicalHostname, PublishRunNumber: version, ProvisioningStage: stage})
	}
	parentCtx := ctx
	sessionCtx, cancelSession := context.WithCancelCause(ctx)
	defer cancelSession(nil)
	provisioningCtx, cancelProvisioning := context.WithCancel(sessionCtx)
	provisioningDone := make(chan struct{})
	go func(provisioningConfig Config, provisioningSetup controlv1.PublishRunSetup) {
		defer close(provisioningDone)
		if err := observeProvisioningStall(provisioningCtx, provisioningConfig, provisioningSetup); err != nil {
			cancelSession(fmt.Errorf("publisher: observe provisioning warning: %w", err))
		}
	}(config, setup)
	defer func() {
		cancelProvisioning()
		<-provisioningDone
	}()
	// refresh before setup consumes the publish run; the heartbeat loop takes over after the connections start.
	if err := progress("heartbeat"); err != nil {
		return err
	}
	heartbeat, observedHeartbeat, err := heartbeatResponseOnce(
		sessionCtx, authority, setup.PublishRun.ExpiresAt,
	)
	if err != nil {
		cancelSession(nil)
		return fmt.Errorf("publisher: heartbeat: %w", err)
	}
	if sessionCtx.Err() != nil {
		cancelSession(nil)
		if parentCtx.Err() == nil {
			return context.Cause(sessionCtx)
		}
		return nil
	}
	if len(heartbeat.PublisherConnections) != 0 {
		setup.PublisherConnections = heartbeat.PublisherConnections
	}
	var observedPolicyDenials uint64
	observePolicyDenials := func(value int64) error {
		return observeHeartbeatPolicyDenials(config, setup, value, &observedPolicyDenials)
	}
	if observedHeartbeat {
		if err := observePolicyDenials(heartbeat.PolicyDenials); err != nil {
			return err
		}
	}
	ctx = sessionCtx
	var visitorClient any = config.Control
	if config.VisitorControl != nil {
		visitorClient = config.VisitorControl
	}
	policyClient, ok := visitorClient.(visitorPolicyClient)
	if !ok {
		return errors.New("publisher visitor policy client is required")
	}
	policy, err := prepareVisitorPolicy(ctx, policyClient, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: setup.PublicUrl.Id}, setup.PublishRun.Id,
		int64(version), publishRunToken.String(), func(error) {
			if config.Logf != nil {
				config.Logf("publisher: visitor policy renewal failed")
			}
		})
	if err != nil {
		return err
	}
	defer policy.Close()
	if config.Demo && config.Feedback {
		client, ok := config.Control.(interface {
			CreatePublishRunPreview(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.Preview, error)
		})
		if !ok {
			return errors.New("publisher: demo feedback requires a preview-capable control client")
		}
		preview, err := client.CreatePublishRunPreview(ctx, setup.PublishRun.Id, version, publishRunToken)
		if err != nil {
			return fmt.Errorf("publisher: create demo feedback preview: %w", err)
		}
		if preview.SchemaVersion != 1 || len(preview.PublicUrlIds) != 1 || preview.PublicUrlIds[0] != setup.PublicUrl.Id {
			return errors.New("publisher: invalid demo preview")
		}
		config.PreviewID = preview.Id
	}
	var shareRuntime *shareAccess
	if setup.PublicUrl.ServiceProtocol == controlv1.Http && (setup.PublicUrl.Purpose == controlv1.App || setup.PublicUrl.Purpose == controlv1.Alias || setup.PublicUrl.Purpose == controlv1.Demo) {
		if err := progress("share_access"); err != nil {
			return err
		}
		client, ok := config.Control.(shareAccessClient)
		if !ok {
			return errors.New("publisher: share-capable control client is required for HTTP public URLs")
		}
		previewID := config.PreviewID
		if config.Demo {
			previewID = ""
		}
		if err := client.EnableShareAccess(ctx, setup.PublishRun.Id, version, previewID, publishRunToken); err != nil {
			return fmt.Errorf("publisher: enable share access: %w", err)
		}
		shareRuntime = &shareAccess{client: client, runID: setup.PublishRun.Id, version: version, token: publishRunToken}
	}
	var material clientstate.Material
	identity := authority.identity
	var readiness *ReadinessProof
	if config.ReadinessProof != nil {
		readiness = config.ReadinessProof(identity)
	}
	feedback, err := newFeedbackRuntime(config, setup, publishRunToken)
	if err != nil {
		return err
	}
	browser := browserAccessForRun(config, setup, publishRunToken)
	var browserRenewal *browserTokens
	if browser != nil {
		issuer, ok := visitorClient.(browserTokenClient)
		if !ok {
			return errors.New("publisher visitor token client is required")
		}
		browserRenewal, err = startBrowserTokens(ctx, issuer, policy.lease, func(error) {
			if config.Logf != nil {
				config.Logf("publisher: browser visitor token renewal failed")
			}
		})
		if err != nil {
			return err
		}
		defer browserRenewal.Close()
		browser.tokens, browser.policy = browserRenewal, policy
		if shareRuntime != nil {
			shareRuntime.browser = browser
		}
	}
	streamCapacity := 0
	if setup.Traffic != nil {
		streamCapacity = setup.Traffic.Connections
	}
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Context:               ctx,
		AuditSink:             auditSink,
		BrowserAccess:         browser,
		VisitorPolicy:         policy.lease,
		VisitorSourceKey:      policy.sourceKey,
		VisitorTokens:         browserRenewal,
		BrowserLoginAvailable: config.BrowserLoginAvailable,
		PreviewID:             config.PreviewID, PublicURLID: setup.PublicUrl.Id, PublishRunID: setup.PublishRun.Id, PublishRunNumber: version,
		Hostname: setup.PublicUrl.CanonicalHostname, Target: config.Target, ResolveTarget: config.ResolveTarget, TargetOptions: config.TargetOptions, CertificatePlan: plan,
		ServiceProtocol: setup.PublicUrl.ServiceProtocol, TargetTLSName: config.TargetTLSName,
		Purpose:        setup.PublicUrl.Purpose,
		AccessMode:     setup.PublicUrl.AccessMode,
		PromoteVisitor: config.PromoteVisitor,
		AdmitVisitor:   config.AdmitVisitor,
		ReadinessProof: readiness,
		OnWarning:      config.OnWarning,
		Mounts:         config.Mounts,
		ShareAccess:    shareRuntime,
		Feedback:       feedback,
		Limits:         config.Limits,
		StreamCapacity: streamCapacity,
		ObserveSummary: config.ObserveSummary,
		InspectionMode: config.InspectionMode,
		Handler:        config.Handler,
		AdmitRequest: func(request *http.Request) error {
			if config.AdmitRequest == nil {
				return nil
			}
			return config.AdmitRequest(request, identity)
		},
		ObserveResponse: func(response *http.Response) error {
			if config.ObserveResponse == nil {
				return nil
			}
			return config.ObserveResponse(response, identity)
		},
		OnTargetFailure: func() {
			_ = observe(config, Event{Type: EventTargetUnavailable, PublicURLID: setup.PublicUrl.Id,
				Hostname: setup.PublicUrl.CanonicalHostname, PublishRunNumber: version})
		},
	})
	if err != nil {
		return err
	}
	defer route.Close()
	if err := route.Start(); err != nil {
		return err
	}
	if err := progress("publisher_connections"); err != nil {
		return err
	}
	// sessionCtx stops admission, heartbeats, and certificate renewals.
	// transportCtx keeps publisher connections and the expiration watcher alive
	// during ordinary drain so established visitor connections can finish.
	transportCtx, cancelTransports := context.WithCancel(context.WithoutCancel(parentCtx))
	stopAdmissions := context.AfterFunc(sessionCtx, func() {
		route.stopAdmissions()
		if !parentCanceledSession(parentCtx, sessionCtx) {
			cancelTransports()
		}
	})
	defer stopAdmissions()
	connections, err := authority.connections(transportCtx, publisherConnectionManagerConfig{
		QUICConnector: config.QUICConnector, TCPConnector: config.TCPConnector,
		FallbackDelay: config.FallbackDelay, ReconnectDelay: activationRetry,
		Report: func(err error) {
			if config.Logf != nil {
				config.Logf("%v", err)
			}
		},
	}, route)
	if err != nil {
		cancelTransports()
		return err
	}
	fallbackDone := make(chan struct{})
	go func() {
		defer close(fallbackDone)
		select {
		case <-sessionCtx.Done():
		case <-connections.Fallback():
			if err := observe(config, Event{
				Type: EventTransportFallback, PublicURLID: setup.PublicUrl.Id, Hostname: setup.PublicUrl.CanonicalHostname,
				PublishRunNumber: version, Transport: tunnel.TransportTLSTCP,
			}); err != nil {
				cancelSession(fmt.Errorf("publisher: observe transport fallback: %w", err))
			}
		}
	}()
	defer func() {
		cancelSession(nil)
		<-fallbackDone
	}()
	heartbeatDone := make(chan error, 1)
	expirationDone := make(chan struct{})
	cleanup := publishRunCleanup{
		parentCtx: parentCtx, sessionCtx: sessionCtx,
		cancelSession: cancelSession, cancelTransports: cancelTransports,
		connections: connections, route: route, config: config, setup: setup, version: version,
		heartbeatDone: heartbeatDone, expirationDone: expirationDone,
	}
	defer func() { result = cleanup.finish(result) }()
	go func() {
		defer close(expirationDone)
		select {
		case <-transportCtx.Done():
		case <-route.certificateExpiration():
			cleanup.abort(errCertificateExpired)
		}
	}()
	if err := connections.Update(setup.PublisherConnections); err != nil {
		return err
	}
	go func() {
		err := heartbeatSessionAfterUpdate(
			sessionCtx, authority, heartbeat.PublishRun.ExpiresAt,
			connections.Update, observePolicyDenials, config.heartbeatInterval,
		)
		if err != nil && parentCanceledSession(parentCtx, sessionCtx) {
			err = nil
		}
		if err != nil {
			err = fmt.Errorf("publisher: heartbeat: %w", err)
			cleanup.abort(err)
		}
		heartbeatDone <- err
	}()
	cleanup.heartbeatStarted = true
	if err := connections.WaitReady(ctx, 1); err != nil {
		return err
	}
	if err := progress("certificate"); err != nil {
		return err
	}
	material, err = issueInitialCertificate(ctx, authority, route, state)
	if err != nil {
		return err
	}
	if err := connections.WaitReady(ctx, 2); err != nil {
		return err
	}
	if err := progress("ready_confirmation"); err != nil {
		return err
	}
	select {
	case <-connections.Fallback():
		<-fallbackDone
		if sessionCtx.Err() != nil && parentCtx.Err() == nil {
			return context.Cause(sessionCtx)
		}
	default:
	}
	if err := confirmPublishRunReady(ctx, authority, route, ready); err != nil {
		return err
	}
	cancelProvisioning()
	return runCertificateRenewals(ctx, config, authority, route, state, material)
}
