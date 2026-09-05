package publisher

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/tlschallenge"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const heartbeatCallTimeout = 10 * time.Second

var (
	errCertificateExpired = errors.New("publisher: application certificate expired")
	heartbeatInterval     = 15 * time.Second
	activationRetry       = 2 * time.Second
	renewalRetry          = time.Minute
)

type RouteControlClient interface {
	CreateRoute(context.Context, controlv1.CreateRouteRequest, string) (controlv1.Route, error)
	ListRoutes(context.Context, string) ([]controlv1.Route, error)
	CreateRouteSession(context.Context, controlv1.Route, controlv1.CreateRouteSessionRequest, uint64, string) (controlv1.RouteSessionSetup, error)
	CloseRouteSession(context.Context, string, credentials.SessionToken) error
	Ready(context.Context, string, uint64, credentials.SessionToken) error
	Heartbeat(context.Context, string, uint64, credentials.SessionToken) (controlv1.RouteSessionHeartbeat, error)
	CreateCertificateIssuance(context.Context, string, uint64, credentials.SessionToken, []byte, string) (controlv1.CertificateIssuance, error)
	CertificateIssuance(context.Context, string, credentials.SessionToken) (controlv1.CertificateIssuance, error)
	CertificateChallengeReady(context.Context, string, credentials.SessionToken) (controlv1.CertificateIssuance, error)
	CertificateChallengeRemoved(context.Context, string, credentials.SessionToken) error
	CertificateInstalled(context.Context, string, uint64, string, time.Time, credentials.SessionToken) error
}

type Config struct {
	Control           RouteControlClient
	TeamID            string
	DomainID          string
	MembershipID      string
	PolicyRevision    uint64
	RouteScope        controlv1.RouteScope
	CertificatePlan   controlv1.CertificatePlan
	Hostname          string
	Target            string
	AllowedIPPrefixes []string
	Certificate       tls.Certificate
	State             *clientstate.Store
	QUICConnector     muxsession.Connector
	TCPConnector      muxsession.Connector
	FallbackDelay     time.Duration
	DrainTime         time.Duration
	Logf              func(string, ...any)
	Observe           func(Event) error
}

type EventType string

const (
	EventRouteAssigned EventType = "route"
	EventProvisioning  EventType = "provisioning"
	EventReady         EventType = "ready"
	EventDraining      EventType = "draining"
)

type Event struct {
	Type         EventType
	RouteID      string
	Hostname     string
	PublicURL    string
	RouteVersion uint64
}

func Run(ctx context.Context, config Config) (result error) {
	if config.Control == nil {
		return errors.New("publisher: control client is required")
	}
	if config.DrainTime < 0 || config.FallbackDelay < 0 {
		return errors.New("publisher: drain time and fallback delay cannot be negative")
	}
	if config.DrainTime == 0 {
		config.DrainTime = 30 * time.Second
	}
	if config.FallbackDelay == 0 {
		config.FallbackDelay = 250 * time.Millisecond
	}
	if config.QUICConnector == nil || config.TCPConnector == nil {
		return errors.New("publisher: QUIC and TLS/yamux connectors are required")
	}
	hostname, err := naming.CanonicalizeHostname(config.Hostname)
	if err != nil {
		return err
	}
	if len(config.CertificatePlan.Identifiers) == 0 {
		return errors.New("publisher: certificate plan is required")
	}
	automaticCertificates := len(config.Certificate.Certificate) == 0
	if automaticCertificates {
		if config.State == nil {
			return errors.New("publisher: client state is required for automatic certificates")
		}
	} else if err := validateCertificate(config.Certificate, hostname, true); err != nil {
		return err
	}
	config.Target, err = localproxy.NormalizeTarget(config.Target)
	if err != nil {
		return err
	}
	if err := localproxy.Preflight(ctx, config.Target); err != nil {
		return err
	}
	allowedIPPrefixes, err := authorization.CanonicalizeIPPrefixes(config.AllowedIPPrefixes)
	if err != nil {
		return fmt.Errorf("publisher: invalid allowed IP prefixes: %w", err)
	}
	config.AllowedIPPrefixes = allowedIPPrefixes
	if config.State != nil {
		hostLock, err := clientstate.LockHostnameContext(ctx, config.State, hostname)
		if err != nil {
			return err
		}
		defer hostLock.Close()
	}
	route, err := createOrLoadRoute(ctx, config)
	if err != nil {
		return err
	}
	routeID := route.Id
	if err := observe(config, Event{Type: EventRouteAssigned, RouteID: routeID, Hostname: route.CanonicalHostname}); err != nil {
		return err
	}
	var routeState *clientstate.RouteCertificateHandle
	if automaticCertificates {
		routeState, err = clientstate.LockRouteCertificates(ctx, config.State, routeID)
		if err != nil {
			return err
		}
		defer routeState.Close()
	}
	for {
		setup, err := createRouteSession(ctx, config, route)
		if err != nil {
			return err
		}
		if err := observe(config, Event{
			Type: EventProvisioning, RouteID: routeID, Hostname: setup.Route.CanonicalHostname,
			RouteVersion: uint64(setup.RouteSession.RouteVersion),
		}); err != nil {
			return err
		}
		err = runSession(ctx, config, setup, routeState, func() error {
			return observe(config, Event{
				Type: EventReady, RouteID: routeID, Hostname: setup.Route.CanonicalHostname,
				PublicURL: "https://" + setup.Route.CanonicalHostname, RouteVersion: uint64(setup.RouteSession.RouteVersion),
			})
		})
		closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		closeErr := config.Control.CloseRouteSession(closeCtx, setup.RouteSession.Id, credentials.SessionToken(setup.RouteSessionToken))
		cancel()
		if closeErr != nil && !errors.Is(closeErr, controlclient.ErrNotFound) && !errors.Is(closeErr, controlclient.ErrUnauthenticated) {
			err = errors.Join(err, fmt.Errorf("publisher: close route session: %w", closeErr))
		}
		if ctx.Err() != nil {
			return err
		}
		if !errors.Is(err, controlclient.ErrStatusConflict) {
			return err
		}
		route.NextRouteVersion = setup.RouteSession.RouteVersion + 1
	}
}

func createOrLoadRoute(ctx context.Context, config Config) (controlv1.Route, error) {
	routes, err := config.Control.ListRoutes(ctx, config.TeamID)
	if err != nil {
		return controlv1.Route{}, err
	}
	for _, route := range routes {
		if route.CanonicalHostname == config.Hostname {
			return route, nil
		}
	}
	idempotencyKey, err := opaqueID("route_")
	if err != nil {
		return controlv1.Route{}, err
	}
	body := controlv1.CreateRouteRequest{
		TeamId: config.TeamID, DomainId: config.DomainID, CanonicalHostname: config.Hostname,
		Target: config.Target, RouteScope: config.RouteScope,
	}
	if config.RouteScope == controlv1.Member && config.MembershipID != "" {
		body.MembershipId = &config.MembershipID
	}
	if config.AllowedIPPrefixes != nil {
		allowed := slices.Clone(config.AllowedIPPrefixes)
		body.AllowedIpPrefixes = &allowed
	}
	return config.Control.CreateRoute(ctx, body, idempotencyKey)
}

func createRouteSession(ctx context.Context, config Config, route controlv1.Route) (controlv1.RouteSessionSetup, error) {
	idempotencyKey, err := opaqueID("route_session_")
	if err != nil {
		return controlv1.RouteSessionSetup{}, err
	}
	body := controlv1.CreateRouteSessionRequest{
		TeamId: config.TeamID, PolicyRevision: int64(config.PolicyRevision), CertificatePlan: config.CertificatePlan,
		AllowedIpPrefixes: append([]string{}, config.AllowedIPPrefixes...),
	}
	if config.MembershipID != "" {
		body.MembershipId = &config.MembershipID
	}
	for {
		setup, err := config.Control.CreateRouteSession(ctx, route, body, uint64(route.NextRouteVersion), idempotencyKey)
		if err == nil || !errors.Is(err, controlclient.ErrUnavailable) {
			return setup, err
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
	state *clientstate.RouteCertificateHandle,
	ready func() error,
) (result error) {
	if setup.Route.Id == "" || setup.RouteSession.Id == "" || setup.RouteSession.RouteVersion <= 0 || setup.RouteSessionToken == "" {
		return errors.New("publisher: server returned incomplete session setup")
	}
	sessionToken := credentials.SessionToken(setup.RouteSessionToken)
	if _, _, err := credentials.ParseSessionToken(sessionToken); err != nil {
		return errors.New("publisher: server returned invalid session token")
	}
	version := uint64(setup.RouteSession.RouteVersion)
	parentCtx := ctx
	sessionCtx, cancelSession := context.WithCancelCause(ctx)
	defer cancelSession(nil)
	// Refresh before setup consumes the session, then continue heartbeats in the background.
	heartbeat, err := heartbeatResponseOnce(
		sessionCtx, config.Control, setup.RouteSession.Id, version, sessionToken, setup.RouteSession.ExpiresAt,
	)
	if err != nil {
		cancelSession(nil)
		return fmt.Errorf("publisher: heartbeat: %w", err)
	}
	if sessionCtx.Err() != nil {
		cancelSession(nil)
		return nil
	}
	if len(heartbeat.PublisherConnections) != 0 {
		setup.PublisherConnections = heartbeat.PublisherConnections
	}
	ctx = sessionCtx
	certificate := config.Certificate
	var material clientstate.Material
	var hasMaterial bool
	if state != nil {
		material, hasMaterial, err = state.Current(ctx, setup.Route.CanonicalHostname)
		if errors.Is(err, clientstate.ErrCertificateExpired) {
			hasMaterial = false
		} else if err != nil {
			return err
		}
		if hasMaterial {
			certificate = material.Certificate
		}
	}
	route, err := NewRoute(RouteConfig{
		Hostname: setup.Route.CanonicalHostname, Target: config.Target, Certificate: certificate,
		StrictCertificate: true,
	})
	if err != nil {
		return err
	}
	defer route.Close()
	expirationDone := make(chan struct{})
	go func() {
		defer close(expirationDone)
		select {
		case <-ctx.Done():
		case <-route.certificateExpiration():
			cancelSession(errCertificateExpired)
		}
	}()
	defer func() {
		cancelSession(nil)
		<-expirationDone
	}()
	if err := route.Start(); err != nil {
		return err
	}
	connections, err := newPublisherConnectionManager(ctx, publisherConnectionManagerConfig{
		QUICConnector: config.QUICConnector, TCPConnector: config.TCPConnector,
		FallbackDelay: config.FallbackDelay, ReconnectDelay: activationRetry,
		Report: func(err error) {
			if config.Logf != nil {
				config.Logf("%v", err)
			}
		},
	}, route, setup.RouteSession.Id, setup.Route.Id, version)
	if err != nil {
		return err
	}
	defer connections.Close()
	if err := connections.Update(setup.PublisherConnections); err != nil {
		return err
	}
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		if err := heartbeatSessionAfterUpdate(
			sessionCtx, config.Control, setup.RouteSession.Id, version, sessionToken, heartbeat.RouteSession.ExpiresAt,
			connections.Update,
		); err != nil {
			cancelSession(fmt.Errorf("publisher: heartbeat: %w", err))
		}
	}()
	defer func() {
		cancelSession(nil)
		<-heartbeatDone
		if parentCtx.Err() == nil {
			cause := context.Cause(sessionCtx)
			if cause != nil && !errors.Is(cause, context.Canceled) {
				result = cause
			}
		}
	}()
	if state != nil {
		if err := connections.WaitReady(ctx, 1); err != nil {
			return err
		}
		if !hasMaterial {
			material, err = issueInitialCertificate(
				ctx, config.Control, route, state, setup.RouteSession.Id, setup.Route.Id, version, sessionToken,
				setup.Route.CanonicalHostname,
			)
			if err != nil {
				return err
			}
			hasMaterial = true
		} else {
			if err := config.Control.CertificateInstalled(
				ctx, setup.RouteSession.Id, version, material.IssuanceID, material.Certificate.Leaf.NotAfter, sessionToken,
			); err != nil {
				return err
			}
			if !material.Installed {
				material, err = state.MarkInstalled(ctx, setup.Route.CanonicalHostname, material.IssuanceID, material.RouteVersion)
				if err != nil {
					return err
				}
			}
		}
	}
	if err := connections.WaitReady(ctx, 2); err != nil {
		return err
	}
	for {
		serverReady := false
		err = route.withValidCertificate(func() error {
			if err := config.Control.Ready(ctx, setup.RouteSession.Id, version, sessionToken); err != nil {
				return err
			}
			serverReady = true
			return ready()
		})
		if err == nil {
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
	if state != nil {
		nextRenewal := material.RenewAt
		if !material.Installed {
			nextRenewal = time.Now()
		}
		renewalTimer = time.NewTimer(max(time.Until(nextRenewal), 0))
		renewal = renewalTimer.C
		defer renewalTimer.Stop()
	}
	for {
		select {
		case <-ctx.Done():
			if parentCtx.Err() == nil {
				return context.Cause(ctx)
			}
			return errors.Join(
				observe(config, Event{Type: EventDraining, RouteID: setup.Route.Id, Hostname: setup.Route.CanonicalHostname, RouteVersion: version}),
				drainRoute(route, config.DrainTime),
			)
		case <-renewal:
			replacement, renewalErr := attemptCertificateTransaction(
				ctx, config.Control, route, state, setup.RouteSession.Id, setup.Route.Id, version, sessionToken,
				setup.Route.CanonicalHostname,
			)
			if replacement.Certificate.Leaf != nil {
				material = replacement
			}
			if renewalErr != nil {
				if errors.Is(renewalErr, controlclient.ErrStatusConflict) {
					return renewalErr
				}
				if parentCtx.Err() != nil {
					return drainRoute(route, config.DrainTime)
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
			renewalTimer.Reset(max(time.Until(material.RenewAt), 0))
		}
	}
}

func observe(config Config, event Event) error {
	if config.Observe == nil {
		return nil
	}
	return config.Observe(event)
}

func logRenewalFailure(logf func(string, ...any), err error) {
	if logf != nil {
		logf("certificate renewal failed; retrying while the current certificate remains valid: %v", err)
	}
}

func issueInitialCertificate(
	ctx context.Context,
	server RouteControlClient,
	route *Route,
	state *clientstate.RouteCertificateHandle,
	routeSessionID, routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
	hostname string,
) (clientstate.Material, error) {
	var material clientstate.Material
	retriedTerminal := false
	for {
		attempted, err := attemptCertificateTransaction(
			ctx, server, route, state, routeSessionID, routeID, version, sessionToken, hostname,
		)
		if attempted.Certificate.Leaf != nil {
			material = attempted
		}
		if err == nil {
			return attempted, nil
		}
		if ctx.Err() != nil {
			return material, context.Cause(ctx)
		}
		var terminal *terminalCertificateIssuanceError
		if errors.As(err, &terminal) && !retriedTerminal {
			retriedTerminal = true
		} else if !errors.Is(err, controlclient.ErrUnavailable) && !errors.Is(err, controlclient.ErrRateLimited) {
			return material, err
		}
		if err := waitCertificateRetry(ctx, certificateRetryDelay(err)); err != nil {
			return material, err
		}
	}
}

// attemptCertificateTransaction advances every issuance phase at most once.
// Retrying this entire function is safe because CertificateAttempt preserves
// the CSR until the server installation acknowledgement is durable locally.
func attemptCertificateTransaction(
	ctx context.Context,
	server RouteControlClient,
	route *Route,
	state *clientstate.RouteCertificateHandle,
	routeSessionID, routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
	hostname string,
) (clientstate.Material, error) {
	pending, err := state.CertificateAttempt(ctx, hostname)
	if err != nil {
		return clientstate.Material{}, err
	}
	idempotencyKey := certificateIdempotencyKey(pending.CSRDER)
	issuance, err := server.CreateCertificateIssuance(ctx, routeSessionID, version, sessionToken, pending.CSRDER, idempotencyKey)
	if err != nil {
		return clientstate.Material{}, err
	}
	if err := validateCertificateAttempt(
		ctx, server, route, state, issuance, routeSessionID, routeID, version, sessionToken, hostname, "", "",
	); err != nil {
		return clientstate.Material{}, err
	}
	challenge := tlsALPNChallenge(issuance.Challenges, hostname)
	if issuance.CertificatePem == nil && challenge == nil {
		return clientstate.Material{}, &pendingCertificateIssuanceError{retryAt: issuance.RetryAt}
	}
	if issuance.CertificatePem == nil {
		if !certificateIssuanceStateAllowsChallenge(issuance.State) {
			return clientstate.Material{}, &pendingCertificateIssuanceError{retryAt: issuance.RetryAt}
		}
		installedChallenge, err := certificateChallenge(challenge, hostname)
		if err != nil {
			return clientstate.Material{}, err
		}
		if err := route.InstallChallenge(installedChallenge); err != nil {
			return clientstate.Material{}, err
		}
		issuanceID := issuance.Id
		issuance, err = server.CertificateChallengeReady(ctx, issuanceID, sessionToken)
		if err != nil {
			return clientstate.Material{}, err
		}
		if err := validateCertificateAttempt(
			ctx, server, route, state, issuance, routeSessionID, routeID, version, sessionToken,
			hostname, issuanceID, challenge.Token,
		); err != nil {
			return clientstate.Material{}, err
		}
		if issuance.CertificatePem == nil {
			return clientstate.Material{}, &pendingCertificateIssuanceError{retryAt: issuance.RetryAt}
		}
	}
	if challenge != nil {
		route.RemoveChallenge(challenge.Token)
		if err := server.CertificateChallengeRemoved(ctx, issuance.Id, sessionToken); err != nil {
			return clientstate.Material{}, err
		}
	}
	renewAt := certificateRenewAt(*issuance.NotBefore, *issuance.NotAfter)
	material, err := state.Commit(ctx, hostname, pending, []byte(*issuance.CertificatePem), renewAt, issuance.Id, version)
	if err != nil {
		return material, err
	}
	if !material.Certificate.Leaf.NotBefore.Equal(*issuance.NotBefore) ||
		!material.Certificate.Leaf.NotAfter.Equal(*issuance.NotAfter) {
		return material, errors.New("publisher: server certificate validity does not match certificate material")
	}
	if err := route.InstallCertificate(material.Certificate); err != nil {
		return material, err
	}
	if err := server.CertificateInstalled(ctx, routeSessionID, version, issuance.Id, *issuance.NotAfter, sessionToken); err != nil {
		return material, err
	}
	installed, err := state.MarkInstalled(ctx, hostname, issuance.Id, version)
	if err != nil {
		return material, err
	}
	return installed, nil
}

func certificateChallenge(challenge *controlv1.CertificateChallenge, hostname string) (tlschallenge.TLSALPNChallenge, error) {
	digest, err := base64.RawURLEncoding.DecodeString(challenge.Digest)
	if err != nil || len(digest) != 32 || base64.RawURLEncoding.EncodeToString(digest) != challenge.Digest ||
		challenge.Token == "" || challenge.Identifier != hostname || challenge.Method != controlv1.TlsAlpn01 || !challenge.ExpiresAt.After(time.Now()) {
		return tlschallenge.TLSALPNChallenge{}, errors.New("publisher: server returned an invalid TLS-ALPN challenge digest")
	}
	result := tlschallenge.TLSALPNChallenge{
		ID: challenge.Token, Hostname: challenge.Identifier, ExpiresAt: challenge.ExpiresAt,
	}
	copy(result.Digest[:], digest)
	return result, nil
}

func validateCertificateAttempt(
	ctx context.Context,
	server RouteControlClient,
	route *Route,
	state *clientstate.RouteCertificateHandle,
	issuance controlv1.CertificateIssuance,
	routeSessionID, routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
	hostname, expectedID, installedChallengeID string,
) error {
	err := validateCertificateIssuance(issuance, routeSessionID, routeID, version, hostname, expectedID)
	var terminal *terminalCertificateIssuanceError
	if !errors.As(err, &terminal) {
		return err
	}
	if installedChallengeID == "" {
		if challenge := tlsALPNChallenge(issuance.Challenges, hostname); challenge != nil {
			installedChallengeID = challenge.Token
		}
	}
	if installedChallengeID != "" {
		route.RemoveChallenge(installedChallengeID)
		if removeErr := server.CertificateChallengeRemoved(ctx, issuance.Id, sessionToken); removeErr != nil {
			return removeErr
		}
	}
	if _, rotateErr := state.NewPending(ctx, hostname); rotateErr != nil {
		return rotateErr
	}
	return err
}

func validateCertificateIssuance(
	issuance controlv1.CertificateIssuance,
	routeSessionID, routeID string,
	version uint64,
	hostname string,
	expectedID string,
) error {
	if issuance.Id == "" || issuance.RouteSessionId != routeSessionID || issuance.RouteId != routeID ||
		issuance.RouteVersion != int64(version) || expectedID != "" && issuance.Id != expectedID ||
		!slices.Contains(issuance.CertificatePlan.Identifiers, hostname) {
		return errors.New("publisher: server returned a certificate issuance for a different route session")
	}
	if !issuance.State.Valid() {
		return errors.New("publisher: server returned an unknown certificate issuance state")
	}
	if err := certificateIssuanceStateError(issuance.State); err != nil {
		return err
	}
	if issuance.CertificatePem != nil {
		if issuance.State != controlv1.CertificateIssuanceStateWaitingForInstall && issuance.State != controlv1.CertificateIssuanceStateInstalled ||
			issuance.NotBefore == nil || issuance.NotAfter == nil {
			return errors.New("publisher: server returned certificate material in an inconsistent issuance state")
		}
	} else if issuance.State == controlv1.CertificateIssuanceStateWaitingForInstall || issuance.State == controlv1.CertificateIssuanceStateInstalled {
		return errors.New("publisher: server returned an installed issuance without certificate material")
	}
	if issuance.Challenges != nil && len(*issuance.Challenges) != 0 && issuance.CertificatePem == nil {
		if !certificateIssuanceStateAllowsChallenge(issuance.State) {
			return errors.New("publisher: server returned a challenge in an inconsistent issuance state")
		}
	}
	if challenge := tlsALPNChallenge(issuance.Challenges, hostname); challenge != nil {
		digest, err := base64.RawURLEncoding.DecodeString(challenge.Digest)
		if err != nil || len(digest) != 32 || base64.RawURLEncoding.EncodeToString(digest) != challenge.Digest ||
			challenge.Token == "" || challenge.Identifier != hostname || challenge.ExpiresAt.IsZero() {
			return errors.New("publisher: server returned invalid TLS-ALPN challenge material")
		}
	}
	return nil
}

func certificateIssuanceStateError(state controlv1.CertificateIssuanceState) error {
	if state == controlv1.CertificateIssuanceStateFailed || state == controlv1.CertificateIssuanceStateCanceled {
		return &terminalCertificateIssuanceError{state: state}
	}
	return nil
}

func certificateIssuanceStateAllowsChallenge(state controlv1.CertificateIssuanceState) bool {
	switch state {
	case controlv1.CertificateIssuanceStateAuthorizing,
		controlv1.CertificateIssuanceStateReadyToFinalize,
		controlv1.CertificateIssuanceStateFinalizing:
		return true
	default:
		return false
	}
}

func tlsALPNChallenge(challenges *[]controlv1.CertificateChallenge, hostname string) *controlv1.CertificateChallenge {
	if challenges == nil {
		return nil
	}
	for index := range *challenges {
		challenge := &(*challenges)[index]
		if challenge.Method == controlv1.TlsAlpn01 && challenge.Identifier == hostname {
			return challenge
		}
	}
	return nil
}

func certificateRenewAt(notBefore, notAfter time.Time) time.Time {
	return notBefore.Add(notAfter.Sub(notBefore) * 2 / 3).UTC()
}

func certificateIdempotencyKey(csrDER []byte) string {
	digest := sha256.Sum256(csrDER)
	return "certificate_" + base64.RawURLEncoding.EncodeToString(digest[:])
}

func opaqueID(prefix string) (string, error) {
	id, err := opaqueid.New(prefix)
	if err != nil {
		return "", fmt.Errorf("publisher: generate idempotency key: %w", err)
	}
	return id, nil
}

type terminalCertificateIssuanceError struct {
	state controlv1.CertificateIssuanceState
}

func (e *terminalCertificateIssuanceError) Error() string {
	return fmt.Sprintf("publisher: certificate issuance became %s", e.state)
}

type pendingCertificateIssuanceError struct {
	retryAt *time.Time
}

func (*pendingCertificateIssuanceError) Error() string {
	return "publisher: certificate issuance is pending"
}

func (*pendingCertificateIssuanceError) Unwrap() error { return controlclient.ErrUnavailable }

func certificatePendingRetryDelay(err error) (time.Duration, bool) {
	var pending *pendingCertificateIssuanceError
	if !errors.As(err, &pending) {
		return 0, false
	}
	if pending.retryAt != nil && pending.retryAt.After(time.Now()) {
		return time.Until(*pending.retryAt), true
	}
	return activationRetry, true
}

func drainRoute(route *Route, timeout time.Duration) error {
	drainCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return route.Drain(drainCtx)
}

func waitCertificateRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-timer.C:
		return nil
	}
}

func certificateRetryDelay(err error) time.Duration {
	if delay, ok := certificatePendingRetryDelay(err); ok {
		return delay
	}
	var limited *controlclient.RateLimitError
	if errors.As(err, &limited) && limited.RetryAfter > 0 {
		return limited.RetryAfter
	}
	return activationRetry
}

func certificateRenewalRetryDelay(err error, notAfter time.Time) time.Duration {
	delay := renewalRetry
	if pendingDelay, ok := certificatePendingRetryDelay(err); ok {
		delay = pendingDelay
	} else {
		var limited *controlclient.RateLimitError
		if errors.As(err, &limited) && limited.RetryAfter > 0 {
			delay = limited.RetryAfter
		}
	}
	return max(min(delay, time.Until(notAfter)), 0)
}

func heartbeatSessionAfterUpdate(
	ctx context.Context,
	server RouteControlClient,
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
	expiresAt time.Time,
	update func([]controlv1.PublisherConnectionPlan) error,
) error {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		response, err := heartbeatResponseOnce(ctx, server, routeID, version, sessionToken, expiresAt)
		if err != nil || ctx.Err() != nil {
			return err
		}
		expiresAt = response.RouteSession.ExpiresAt
		if update != nil && len(response.PublisherConnections) != 0 {
			if err := update(response.PublisherConnections); err != nil {
				return err
			}
		}
	}
}

func heartbeatResponseOnce(
	ctx context.Context,
	server RouteControlClient,
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
	expiresAt time.Time,
) (controlv1.RouteSessionHeartbeat, error) {
	callCtx, cancel := context.WithTimeout(ctx, heartbeatCallTimeout)
	response, err := server.Heartbeat(callCtx, routeID, version, sessionToken)
	cancel()
	if err == nil {
		return response, nil
	}
	if ctx.Err() != nil {
		return heartbeatFallback(expiresAt), nil
	}
	// A missed heartbeat is safe only while the last confirmed session remains valid.
	if errors.Is(err, controlclient.ErrUnavailable) && time.Now().Before(expiresAt) {
		return heartbeatFallback(expiresAt), nil
	}
	if errors.Is(err, controlclient.ErrUnavailable) {
		return heartbeatFallback(expiresAt), controlclient.ErrStatusConflict
	}
	return heartbeatFallback(expiresAt), err
}

func heartbeatFallback(expiresAt time.Time) controlv1.RouteSessionHeartbeat {
	return controlv1.RouteSessionHeartbeat{RouteSession: controlv1.RouteSession{ExpiresAt: expiresAt}}
}
