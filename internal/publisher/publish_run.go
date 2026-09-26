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
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const activationRetry = 2 * time.Second

func createPublishRun(ctx context.Context, config Config, route controlv1.PublicURL) (controlv1.PublishRunSetup, error) {
	idempotencyKey, err := opaqueID("publish_run_")
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
		return errors.New("publisher: server returned incomplete session setup")
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
	// Refresh before setup consumes the session, then continue heartbeats in the background.
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
	var material clientstate.Material
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: setup.PublicUrl.CanonicalHostname, Target: config.Target, CertificatePlan: plan,
		RequestLimit: config.RequestLimit,
	})
	if err != nil {
		return err
	}
	defer route.Close()
	if err := route.Start(); err != nil {
		return err
	}
	// Stop admitting work on session cancellation, but retain transports until HTTP drains.
	transportCtx, cancelTransports := context.WithCancel(context.WithoutCancel(parentCtx))
	stopAdmissions := context.AfterFunc(sessionCtx, func() {
		route.stopAdmissions()
		if parentCtx.Err() == nil || !errors.Is(context.Cause(sessionCtx), context.Cause(parentCtx)) {
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
	expirationDone := make(chan struct{})
	go func() {
		defer close(expirationDone)
		select {
		case <-transportCtx.Done():
		case <-route.certificateExpiration():
			cancelSession(errCertificateExpired)
			cancelTransports()
			_ = route.Close()
		}
	}()
	heartbeatDone := make(chan error, 1)
	heartbeatStarted := false
	defer func() {
		cancelSession(nil)
		if heartbeatStarted {
			normalParentCancellation := parentCtx.Err() != nil && errors.Is(context.Cause(sessionCtx), context.Cause(parentCtx)) &&
				!errors.Is(result, controlclient.ErrStatusConflict) && !errors.Is(result, controlclient.ErrUnauthenticated) && !errors.Is(result, errCertificateExpired)
			if normalParentCancellation {
				if errors.Is(result, context.Canceled) || errors.Is(result, context.DeadlineExceeded) {
					result = nil
				}
				route.stopAdmissions()
				result = errors.Join(result, observe(config, Event{
					Type: EventDraining, PublicURLID: setup.PublicUrl.Id, Hostname: setup.PublicUrl.CanonicalHostname, PublishRunNumber: version,
				}))
				drainCtx, cancelDrain := context.WithTimeout(context.Background(), config.DrainTime)
				connectionDrainErr := connections.Drain(drainCtx)
				publicURLDrainErr := route.Drain(drainCtx)
				cancelDrain()
				result = errors.Join(result, connectionDrainErr, publicURLDrainErr)
				select {
				case <-route.certificateExpiration():
					result = errors.Join(result, errCertificateExpired)
				default:
				}
			}
		}
		cancelTransports()
		if heartbeatStarted {
			result = errors.Join(result, <-heartbeatDone)
			if parentCtx.Err() == nil {
				cause := context.Cause(sessionCtx)
				if cause != nil && !errors.Is(cause, context.Canceled) {
					result = cause
				}
			}
		}
		connections.Close()
		<-expirationDone
	}()
	if err := connections.Update(setup.PublisherConnections); err != nil {
		return err
	}
	go func() {
		err := heartbeatSessionAfterUpdate(
			sessionCtx, config.Control, setup.PublishRun.Id, version, publishRunToken, heartbeat.PublishRun.ExpiresAt,
			connections.Update, observePolicyDenials, config.heartbeatInterval,
		)
		if err != nil && parentCtx.Err() != nil && errors.Is(context.Cause(sessionCtx), context.Cause(parentCtx)) {
			err = nil
		}
		if err != nil {
			err = fmt.Errorf("publisher: heartbeat: %w", err)
			cancelSession(err)
			cancelTransports()
			_ = route.Close()
		}
		heartbeatDone <- err
	}()
	heartbeatStarted = true
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
	for {
		serverReady := false
		err = route.withValidCertificate(func() error {
			if err := config.Control.MarkPublishRunReady(ctx, setup.PublishRun.Id, version, publishRunToken); err != nil {
				return err
			}
			serverReady = true
			return ready()
		})
		if err == nil {
			cancelProvisioning()
			break
		}
		if serverReady || !errors.Is(err, controlclient.ErrUnavailable) && !errors.Is(err, controlclient.ErrStatusConflict) {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(activationRetry):
		}
	}
	var renewalTimer *time.Timer
	var renewal <-chan time.Time
	// Keep renewal ownership across retry waits, but release it before the next renewal is due.
	var renewalLock *clientstate.Lock
	defer func() { _ = renewalLock.Close() }()
	renewalTimer = time.NewTimer(max(time.Until(material.RenewAt), 0))
	renewal = renewalTimer.C
	defer renewalTimer.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = renewalLock.Close()
			return context.Cause(ctx)
		case <-renewal:
			if renewalLock == nil {
				renewalLock, err = state.Lock(ctx)
				if err != nil {
					return err
				}
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
