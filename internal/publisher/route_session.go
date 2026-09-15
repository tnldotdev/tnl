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
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

var activationRetry = 2 * time.Second

func createRouteSession(ctx context.Context, config Config, route controlv1.Route) (controlv1.RouteSessionSetup, error) {
	idempotencyKey, err := opaqueID("route_session_")
	if err != nil {
		return controlv1.RouteSessionSetup{}, err
	}
	for {
		setup, err := config.Control.CreateRouteSession(ctx, route.Id, idempotencyKey)
		if err == nil {
			return setup, nil
		}
		if !errors.Is(err, controlclient.ErrUnavailable) {
			return setup, classifyRouteConflict(err)
		}
		select {
		case <-ctx.Done():
			return controlv1.RouteSessionSetup{}, context.Cause(ctx)
		case <-time.After(activationRetry):
		}
	}
}

func runSession(
	ctx context.Context,
	config Config,
	setup controlv1.RouteSessionSetup,
	ready func() error,
) (result error) {
	if setup.Route.Id == "" || setup.RouteSession.Id == "" || setup.RouteSession.RouteVersion <= 0 || setup.RouteSessionToken == "" {
		return errors.New("publisher: server returned incomplete session setup")
	}
	if err := validateRouteIdentity(setup.Route, config); err != nil {
		return err
	}
	if setup.Route.CanonicalHostname != config.Hostname || setup.RouteSession.RouteId != setup.Route.Id ||
		setup.RouteSession.TeamId != setup.Route.TeamId {
		return errors.New("publisher: server returned a different route session")
	}
	plan, err := certificateidentity.CanonicalPlan(setup.CertificatePlan)
	if err != nil || !certificateidentity.Covers(plan.Identifiers, setup.Route.CanonicalHostname) {
		return errors.New("publisher: server returned an invalid certificate plan")
	}
	setup.CertificatePlan = plan
	state, err := config.State.Certificates(setup.Route.TeamId, plan)
	if err != nil {
		return err
	}
	routeSessionToken := credentials.RouteSessionToken(setup.RouteSessionToken)
	if _, _, err := credentials.ParseRouteSessionToken(routeSessionToken); err != nil {
		return errors.New("publisher: server returned invalid route session token")
	}
	version := uint64(setup.RouteSession.RouteVersion)
	parentCtx := ctx
	sessionCtx, cancelSession := context.WithCancelCause(ctx)
	defer cancelSession(nil)
	provisioningCtx, cancelProvisioning := context.WithCancel(sessionCtx)
	provisioningDone := make(chan struct{})
	go func(provisioningSetup controlv1.RouteSessionSetup) {
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
		sessionCtx, config.Control, setup.RouteSession.Id, version, routeSessionToken, setup.RouteSession.ExpiresAt,
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
	route, err := NewRouteServer(RouteServerConfig{
		Hostname: setup.Route.CanonicalHostname, Target: config.Target, CertificatePlan: plan,
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
	}, route, setup.RouteSession.Id, setup.Route.Id, version)
	if err != nil {
		cancelTransports()
		return err
	}
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
					Type: EventDraining, RouteID: setup.Route.Id, Hostname: setup.Route.CanonicalHostname, RouteVersion: version,
				}))
				drainCtx, cancelDrain := context.WithTimeout(context.Background(), config.DrainTime)
				connectionDrainErr := connections.Drain(drainCtx)
				routeDrainErr := route.Drain(drainCtx)
				cancelDrain()
				result = errors.Join(result, connectionDrainErr, routeDrainErr)
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
			sessionCtx, config.Control, setup.RouteSession.Id, version, routeSessionToken, heartbeat.RouteSession.ExpiresAt,
			connections.Update, observePolicyDenials,
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
	for {
		serverReady := false
		err = route.withValidCertificate(func() error {
			if err := config.Control.MarkRouteSessionReady(ctx, setup.RouteSession.Id, version, routeSessionToken); err != nil {
				return err
			}
			serverReady = true
			return ready()
		})
		if err == nil {
			cancelProvisioning()
			break
		}
		if serverReady || !errors.Is(err, controlclient.ErrUnavailable) {
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

func observeProvisioningStall(ctx context.Context, config Config, setup controlv1.RouteSessionSetup) error {
	timer := time.NewTimer(config.ProvisioningStalledDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil
	case <-timer.C:
		return observe(config, Event{
			Type: EventProvisioningStalled, RouteID: setup.Route.Id, Hostname: setup.Route.CanonicalHostname,
			RouteVersion: uint64(setup.RouteSession.RouteVersion),
		})
	}
}
