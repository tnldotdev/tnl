package publisher

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const activationRetry = 2 * time.Second

func createPublishRun(ctx context.Context, config Config, route controlv1.PublicURL) (controlv1.PublishRunSetup, error) {
	idempotencyKey, err := opaqueID(opaqueid.IdempotencyPrefix)
	if err != nil {
		return controlv1.PublishRunSetup{}, err
	}
	for {
		setup, err := config.Control.CreatePublishRun(ctx, route.Id, idempotencyKey)
		if err == nil {
			return setup, nil
		}
		if !errors.Is(err, controlclient.ErrUnavailable) {
			return setup, classifyPublicURLConflict(err)
		}
		select {
		case <-ctx.Done():
			return controlv1.PublishRunSetup{}, context.Cause(ctx)
		case <-time.After(activationRetry):
		}
	}
}

func runSession(
	ctx context.Context,
	config Config,
	setup controlv1.PublishRunSetup,
	ready func() error,
) (result error) {
	if setup.PublicUrl.Id == "" || setup.PublishRun.Id == "" || setup.PublishRun.PublishRunNumber <= 0 || setup.PublishRunToken == "" {
		return errors.New("publisher: server returned incomplete publish run setup")
	}
	if err := validateRouteIdentity(setup.PublicUrl, config); err != nil {
		return err
	}
	if setup.PublicUrl.CanonicalHostname != config.Hostname || setup.PublishRun.PublicUrlId != setup.PublicUrl.Id ||
		setup.PublishRun.TeamId != setup.PublicUrl.TeamId {
		return errors.New("publisher: server returned a different publish run")
	}
	plan, err := certificateidentity.CanonicalPlan(setup.CertificatePlan)
	if err != nil || !certificateidentity.Covers(plan.Identifiers, setup.PublicUrl.CanonicalHostname) {
		return errors.New("publisher: server returned an invalid certificate plan")
	}
	setup.CertificatePlan = plan
	state, err := config.State.Certificates(setup.PublicUrl.TeamId, plan)
	if err != nil {
		return err
	}
	publishRunToken := credentials.PublishRunToken(setup.PublishRunToken)
	if _, _, err := credentials.ParsePublishRunToken(publishRunToken); err != nil {
		return errors.New("publisher: server returned invalid publish run token")
	}
	version := uint64(setup.PublishRun.PublishRunNumber)
	parentCtx := ctx
	sessionCtx, cancelSession := context.WithCancelCause(ctx)
	defer cancelSession(nil)
	provisioningCtx, cancelProvisioning := context.WithCancel(sessionCtx)
	provisioningDone := make(chan struct{})
	go func(provisioningSetup controlv1.PublishRunSetup) {
		defer close(provisioningDone)
		if err := observeProvisioningStall(provisioningCtx, config, provisioningSetup); err != nil {
			cancelSession(fmt.Errorf("publisher: observe provisioning warning: %w", err))
		}
	}(setup)
	defer func() {
		cancelProvisioning()
		<-provisioningDone
	}()
	// refresh before setup consumes the publish run; the heartbeat loop takes over after the connections start.
	heartbeat, observedHeartbeat, err := heartbeatResponseOnce(
		sessionCtx, config.Control, setup.PublishRun.Id, version, publishRunToken, setup.PublishRun.ExpiresAt,
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
	var shareRuntime *shareAccess
	if config.PreviewID != "" {
		client, ok := config.Control.(shareAccessClient)
		if !ok {
			return errors.New("publisher: share-capable control client is required for this preview")
		}
		if err := client.EnableShareAccess(ctx, setup.PublishRun.Id, version, config.PreviewID, publishRunToken); err != nil {
			return fmt.Errorf("publisher: enable share access: %w", err)
		}
		shareRuntime = &shareAccess{client: client, runID: setup.PublishRun.Id, version: version, token: publishRunToken}
		if err := shareRuntime.refresh(ctx); err != nil {
			return fmt.Errorf("publisher: read share access: %w", err)
		}
		refreshDone := make(chan struct{})
		go func() {
			defer close(refreshDone)
			ticker := time.NewTicker(shareRefreshPeriod)
			defer ticker.Stop()
			for {
				select {
				case <-sessionCtx.Done():
					return
				case <-ticker.C:
					if err := shareRuntime.refresh(sessionCtx); err != nil && config.Logf != nil && sessionCtx.Err() == nil {
						config.Logf("publisher: refresh share access: %v", err)
					}
				}
			}
		}()
		defer func() { cancelSession(nil); <-refreshDone }()
	}
	var material clientstate.Material
	feedback, err := newFeedbackRuntime(config, setup, publishRunToken)
	if err != nil {
		return err
	}
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: setup.PublicUrl.CanonicalHostname, Target: config.Target, CertificatePlan: plan,
		Mounts:       config.Mounts,
		ShareAccess:  shareRuntime,
		Feedback:     feedback,
		RequestLimit: config.RequestLimit,
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
	connections, err := newPublisherConnectionManager(transportCtx, publisherConnectionManagerConfig{
		QUICConnector: config.QUICConnector, TCPConnector: config.TCPConnector,
		FallbackDelay: config.FallbackDelay, ReconnectDelay: activationRetry,
		Report: func(err error) {
			if config.Logf != nil {
				config.Logf("%v", err)
			}
		},
	}, route, setup.PublishRun.Id, setup.PublicUrl.Id, version)
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
			sessionCtx, config.Control, setup.PublishRun.Id, version, publishRunToken, heartbeat.PublishRun.ExpiresAt,
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
	material, err = issueInitialCertificate(ctx, config.Control, route, state, setup)
	if err != nil {
		return err
	}
	if err := connections.WaitReady(ctx, 2); err != nil {
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
	if err := confirmPublishRunReady(ctx, config.Control, setup, route, publishRunToken, ready); err != nil {
		return err
	}
	cancelProvisioning()
	return runCertificateRenewals(ctx, config, setup, route, state, material)
}

func confirmPublishRunReady(
	ctx context.Context,
	control PublicURLControlClient,
	setup controlv1.PublishRunSetup,
	route *PublicURLServer,
	token credentials.PublishRunToken,
	ready func() error,
) error {
	for {
		confirmed := false
		err := route.withValidCertificate(func() error {
			if err := control.MarkPublishRunReady(ctx, setup.PublishRun.Id, uint64(setup.PublishRun.PublishRunNumber), token); err != nil {
				return err
			}
			confirmed = true
			return ready()
		})
		if err == nil || confirmed {
			return err
		}
		if !errors.Is(err, controlclient.ErrUnavailable) && !errors.Is(err, controlclient.ErrStatusConflict) {
			return err
		}
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-time.After(activationRetry):
		}
	}
}

// publishRunCleanup joins the workers started after the public URL server and
// connection manager. parent cancellation drains before transport cancellation;
// heartbeat and certificate failures close transports immediately.
type publishRunCleanup struct {
	parentCtx, sessionCtx context.Context
	cancelSession         context.CancelCauseFunc
	cancelTransports      context.CancelFunc
	connections           *publisherConnectionManager
	route                 *PublicURLServer
	config                Config
	setup                 controlv1.PublishRunSetup
	version               uint64
	heartbeatDone         <-chan error
	expirationDone        <-chan struct{}
	heartbeatStarted      bool
}

func (s *publishRunCleanup) finish(result error) error {
	s.cancelSession(nil)
	if s.heartbeatStarted && parentCanceledSession(s.parentCtx, s.sessionCtx) &&
		!errors.Is(result, controlclient.ErrStatusConflict) && !errors.Is(result, controlclient.ErrUnauthenticated) &&
		!errors.Is(result, errCertificateExpired) {
		result = s.drain(result)
	}
	s.cancelTransports()
	if s.heartbeatStarted {
		result = errors.Join(result, <-s.heartbeatDone)
		if s.parentCtx.Err() == nil {
			cause := context.Cause(s.sessionCtx)
			if cause != nil && !errors.Is(cause, context.Canceled) {
				result = cause
			}
		}
	}
	s.connections.Close()
	<-s.expirationDone
	return result
}

func (s *publishRunCleanup) abort(err error) {
	s.cancelSession(err)
	s.cancelTransports()
	_ = s.route.Close()
}

func parentCanceledSession(parent, session context.Context) bool {
	return parent.Err() != nil && errors.Is(context.Cause(session), context.Cause(parent))
}

func (s *publishRunCleanup) drain(result error) error {
	if errors.Is(result, context.Canceled) || errors.Is(result, context.DeadlineExceeded) {
		result = nil
	}
	s.route.stopAdmissions()
	result = errors.Join(result, observe(s.config, Event{
		Type: EventDraining, PublicURLID: s.setup.PublicUrl.Id,
		Hostname: s.setup.PublicUrl.CanonicalHostname, PublishRunNumber: s.version,
	}))
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), s.config.DrainTime)
	connectionDrainErr := s.connections.Drain(drainCtx)
	publicURLDrainErr := s.route.Drain(drainCtx)
	cancelDrain()
	result = errors.Join(result, connectionDrainErr, publicURLDrainErr)
	select {
	case <-s.route.certificateExpiration():
		result = errors.Join(result, errCertificateExpired)
	default:
	}
	return result
}

func runCertificateRenewals(
	ctx context.Context,
	config Config,
	setup controlv1.PublishRunSetup,
	route *PublicURLServer,
	state *clientstate.CertificateCache,
	material clientstate.Material,
) error {
	// keep the cache lock across retries of one renewal, then release it before
	// waiting for the next renewal so another worktree can use the certificate.
	var renewalLock *clientstate.Lock
	defer func() { _ = renewalLock.Close() }()
	renewalTimer := time.NewTimer(max(time.Until(material.RenewAt), 0))
	renewal := renewalTimer.C
	defer renewalTimer.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = renewalLock.Close()
			return context.Cause(ctx)
		case <-renewal:
			if renewalLock == nil {
				lock, err := state.Lock(ctx)
				if err != nil {
					return err
				}
				renewalLock = lock
			}
			replacement, renewalErr := attemptCertificateTransaction(
				ctx, config.Control, route, state, setup, true,
			)
			if renewalErr == nil {
				material = replacement
			}
			if renewalErr != nil {
				if errors.Is(renewalErr, controlclient.ErrStatusConflict) || errors.Is(renewalErr, controlclient.ErrUnauthenticated) {
					return renewalErr
				}
				if ctx.Err() != nil {
					return context.Cause(ctx)
				}
				if !material.Certificate.Leaf.NotAfter.After(time.Now()) {
					return fmt.Errorf("publisher: renew expired certificate: %w", renewalErr)
				}
				logRenewalFailure(config.Logf, renewalErr)
				retryIn := certificateRenewalRetryDelay(renewalErr, material.Certificate.Leaf.NotAfter)
				expiresIn := time.Until(material.Certificate.Leaf.NotAfter)
				if retryIn >= expiresIn {
					renewal = nil
				} else {
					renewalTimer.Reset(retryIn)
				}
				continue
			}
			_ = renewalLock.Close()
			renewalLock = nil
			renewalTimer.Reset(max(time.Until(material.RenewAt), 0))
		}
	}
}

func observeProvisioningStall(ctx context.Context, config Config, setup controlv1.PublishRunSetup) error {
	timer := time.NewTimer(config.ProvisioningStalledDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil
	case <-timer.C:
		return observe(config, Event{
			Type: EventProvisioningStalled, PublicURLID: setup.PublicUrl.Id, Hostname: setup.PublicUrl.CanonicalHostname,
			PublishRunNumber: uint64(setup.PublishRun.PublishRunNumber),
		})
	}
}
