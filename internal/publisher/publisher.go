package publisher

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/serverclient"
	"github.com/tnldotdev/tnl/internal/tlschallenge"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
	"github.com/tnldotdev/tnl/pkg/protocol/transportv1"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const heartbeatCallTimeout = 10 * time.Second

var (
	errCertificateExpired = errors.New("publisher: application certificate expired")
	heartbeatInterval     = 15 * time.Second
	activationRetry       = 2 * time.Second
	renewalRetry          = time.Minute
	relayCheckInterval    = 15 * time.Second
)

type RouteControlClient interface {
	CreateRoute(context.Context, serverv1.CreateRouteRequest) (serverv1.SessionSetup, error)
	ListRoutes(context.Context) ([]serverv1.Route, error)
	CreateRouteSession(context.Context, string, credentials.RouteToken, []string) (serverv1.SessionSetup, error)
	DeleteRoute(context.Context, string) error
	AttachRouteTransport(context.Context, string, uint64, credentials.SessionToken, transportv1.TailcatDescriptor) error
	Ready(context.Context, string, uint64, credentials.SessionToken) error
	Heartbeat(context.Context, string, uint64, credentials.SessionToken) (serverv1.HeartbeatResponse, error)
	CreateCertificateIssuance(context.Context, string, uint64, credentials.SessionToken, string, []byte) (serverv1.CertificateIssuance, error)
	CertificateChallengeReady(context.Context, string, credentials.SessionToken) (serverv1.CertificateIssuance, error)
	CertificateChallengeRemoved(context.Context, string, credentials.SessionToken) error
	CertificateInstalled(context.Context, string, uint64, string, credentials.SessionToken) error
}

type Config struct {
	Server            RouteControlClient
	Hostname          string
	Target            string
	AllowedIPPrefixes []string
	Certificate       tls.Certificate
	State             *clientstate.Store
	ACMEProfile       string
	RelayRegion       string
	Regions           map[string]*tailcfg.DERPRegion
	LoadRegions       func(context.Context) (map[string]*tailcfg.DERPRegion, error)
	DrainTime         time.Duration
	Logf              logger.Logf
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
	if config.Server == nil {
		return errors.New("publisher: server client is required")
	}
	if config.DrainTime <= 0 {
		config.DrainTime = 30 * time.Second
	}
	hostname, err := naming.CanonicalizeHostname(config.Hostname)
	if err != nil {
		return err
	}
	automaticCertificates := config.ACMEProfile != ""
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
	if err := refreshRelayRegions(ctx, &config); err != nil {
		return err
	}
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		return err
	}
	setup, err := createOrRecover(ctx, config.Server, hostname, config.Target, routeToken, config.AllowedIPPrefixes)
	if err != nil {
		return err
	}
	routeID := setup.Route.Id
	defer func() {
		if routeID == "" {
			return
		}
		deleteCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := config.Server.DeleteRoute(deleteCtx, routeID); err != nil &&
			!errors.Is(err, serverclient.ErrNotFound) && !errors.Is(err, serverclient.ErrUnauthenticated) {
			result = errors.Join(result, fmt.Errorf("publisher: delete route: %w", err))
		}
	}()
	if err := observe(config, Event{Type: EventRouteAssigned, RouteID: routeID, Hostname: setup.Route.Hostname}); err != nil {
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
		if setup.Route.Id != routeID {
			return errors.New("publisher: server changed route ID during session acquisition")
		}
		if err := observe(config, Event{
			Type: EventProvisioning, RouteID: routeID, Hostname: setup.Route.Hostname,
			RouteVersion: uint64(setup.Session.RouteVersion),
		}); err != nil {
			return err
		}
		err := runSession(ctx, config, setup, routeState, func() error {
			return observe(config, Event{
				Type: EventReady, RouteID: routeID, Hostname: setup.Route.Hostname,
				PublicURL: "https://" + setup.Route.Hostname, RouteVersion: uint64(setup.Session.RouteVersion),
			})
		})
		if ctx.Err() != nil {
			return nil
		}
		if !errors.Is(err, serverclient.ErrStatusConflict) {
			return err
		}
		for {
			setup, err = config.Server.CreateRouteSession(ctx, routeID, routeToken, config.AllowedIPPrefixes)
			if err == nil {
				err = refreshRelayRegions(ctx, &config)
				if err == nil {
					break
				}
			}
			if !errors.Is(err, serverclient.ErrUnavailable) {
				return err
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(activationRetry):
			}
		}
	}
}

func refreshRelayRegions(ctx context.Context, config *Config) error {
	if config.LoadRegions != nil {
		regions, err := config.LoadRegions(ctx)
		if err != nil {
			return fmt.Errorf("publisher: load relay regions: %w", err)
		}
		config.Regions = regions
	}
	if config.Regions[config.RelayRegion] == nil {
		return fmt.Errorf("publisher: relay region %q is absent from the relay map", config.RelayRegion)
	}
	return nil
}

func createOrRecover(
	ctx context.Context,
	server RouteControlClient,
	hostname, target string,
	routeToken credentials.RouteToken,
	allowedIPPrefixes []string,
) (serverv1.SessionSetup, error) {
	for {
		request := serverv1.CreateRouteRequest{
			Hostname: hostname, LocalTarget: target, RouteToken: routeToken.String(),
		}
		if allowedIPPrefixes != nil {
			allowed := serverv1.AllowedIPPrefixes(slices.Clone(allowedIPPrefixes))
			request.AllowedIpPrefixes = &allowed
		}
		setup, err := server.CreateRoute(ctx, request)
		if err == nil {
			return setup, nil
		}
		if errors.Is(err, serverclient.ErrStatusConflict) || errors.Is(err, serverclient.ErrUnavailable) {
			// Creation may commit before its response is lost; recover with the same token.
			routes, listErr := server.ListRoutes(ctx)
			if listErr == nil {
				for _, route := range routes {
					if route.Hostname == hostname && route.LocalTarget == target {
						setup, sessionErr := server.CreateRouteSession(ctx, route.Id, routeToken, allowedIPPrefixes)
						if sessionErr == nil {
							return setup, nil
						}
						if !errors.Is(sessionErr, serverclient.ErrUnavailable) &&
							!errors.Is(sessionErr, serverclient.ErrUnauthenticated) {
							return serverv1.SessionSetup{}, sessionErr
						}
					}
				}
			}
			if !errors.Is(err, serverclient.ErrUnavailable) && listErr == nil {
				return serverv1.SessionSetup{}, err
			}
			if listErr != nil && !errors.Is(listErr, serverclient.ErrUnavailable) {
				return serverv1.SessionSetup{}, listErr
			}
			select {
			case <-ctx.Done():
				return serverv1.SessionSetup{}, ctx.Err()
			case <-time.After(activationRetry):
			}
			continue
		}
		return serverv1.SessionSetup{}, err
	}
}

func runSession(
	ctx context.Context,
	config Config,
	setup serverv1.SessionSetup,
	state *clientstate.RouteCertificateHandle,
	ready func() error,
) (result error) {
	if setup.Route.Id == "" || setup.Session.RouteVersion <= 0 || setup.SessionToken == "" || setup.WorkerPublicKey == "" {
		return errors.New("publisher: server returned incomplete session setup")
	}
	sessionToken := credentials.SessionToken(setup.SessionToken)
	if _, _, err := credentials.ParseSessionToken(sessionToken); err != nil {
		return errors.New("publisher: server returned invalid session token")
	}
	var tailcatDialerKey key.NodePublic
	if err := tailcatDialerKey.UnmarshalText([]byte(setup.WorkerPublicKey)); err != nil || tailcatDialerKey.IsZero() {
		return errors.New("publisher: server returned invalid tailcat dialer key")
	}
	version := uint64(setup.Session.RouteVersion)
	parentCtx := ctx
	sessionCtx, cancelSession := context.WithCancelCause(ctx)
	// Refresh before setup consumes the session, then continue heartbeats in the background.
	expiresAt, err := heartbeatOnce(
		sessionCtx, config.Server, setup.Route.Id, version, sessionToken, setup.Session.ExpiresAt,
	)
	if err != nil {
		cancelSession(nil)
		return fmt.Errorf("publisher: heartbeat: %w", err)
	}
	if sessionCtx.Err() != nil {
		cancelSession(nil)
		return nil
	}
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		if err := heartbeatSessionAfter(
			sessionCtx, config.Server, setup.Route.Id, version, sessionToken, expiresAt,
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
	ctx = sessionCtx
	certificate := config.Certificate
	var material clientstate.Material
	var hasMaterial bool
	if state != nil {
		material, hasMaterial, err = state.Current(ctx, setup.Route.Hostname)
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
		Hostname: setup.Route.Hostname, Target: config.Target, Certificate: certificate,
		StrictCertificate: true,
		AllowedClient:     tailcatDialerKey, RelayRegion: config.RelayRegion, Regions: config.Regions, Logf: config.Logf,
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
	endpoint, err := route.Start(ctx)
	if err != nil {
		return err
	}

	for {
		err = config.Server.AttachRouteTransport(ctx, setup.Route.Id, version, sessionToken, endpoint)
		if err == nil {
			break
		}
		if !errors.Is(err, serverclient.ErrUnavailable) {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(activationRetry):
		}
	}
	if state != nil {
		if !hasMaterial {
			material, err = issueInitialCertificate(
				ctx, config.Server, route, state, setup.Route.Id, version, sessionToken,
				setup.Route.Hostname, config.ACMEProfile,
			)
			if err != nil {
				return err
			}
			hasMaterial = true
		}
	}
	for {
		serverReady := false
		err = route.withValidCertificate(func() error {
			if err := config.Server.Ready(ctx, setup.Route.Id, version, sessionToken); err != nil {
				return err
			}
			serverReady = true
			return ready()
		})
		if err == nil {
			break
		}
		if serverReady || !errors.Is(err, serverclient.ErrUnavailable) {
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
	var relayTimer *time.Timer
	var relayCheck <-chan time.Time
	if config.LoadRegions != nil {
		relayTimer = time.NewTimer(relayCheckInterval)
		relayCheck = relayTimer.C
		defer relayTimer.Stop()
	}
	for {
		select {
		case <-ctx.Done():
			if parentCtx.Err() == nil {
				return context.Cause(ctx)
			}
			return errors.Join(
				observe(config, Event{Type: EventDraining, RouteID: setup.Route.Id, Hostname: setup.Route.Hostname, RouteVersion: version}),
				drainRoute(route, config.DrainTime),
			)
		case <-relayCheck:
			regions, relayErr := config.LoadRegions(ctx)
			if relayErr != nil {
				if config.Logf != nil {
					config.Logf("relay map refresh failed: %v", relayErr)
				}
				relayTimer.Reset(relayCheckInterval)
				continue
			}
			if !reflect.DeepEqual(config.Regions[config.RelayRegion], regions[config.RelayRegion]) {
				return serverclient.ErrStatusConflict
			}
			relayTimer.Reset(relayCheckInterval)
		case <-renewal:
			replacement, renewalErr := attemptCertificateTransaction(
				ctx, config.Server, route, state, setup.Route.Id, version, sessionToken,
				setup.Route.Hostname, config.ACMEProfile,
			)
			if replacement.Certificate.Leaf != nil {
				material = replacement
			}
			if renewalErr != nil {
				if errors.Is(renewalErr, serverclient.ErrStatusConflict) {
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

func logRenewalFailure(logf logger.Logf, err error) {
	if logf != nil {
		logf("certificate renewal failed; retrying while the current certificate remains valid: %v", err)
	}
}

func issueInitialCertificate(
	ctx context.Context,
	server RouteControlClient,
	route *Route,
	state *clientstate.RouteCertificateHandle,
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
	hostname, profile string,
) (clientstate.Material, error) {
	var material clientstate.Material
	retriedTerminal := false
	for {
		attempted, err := attemptCertificateTransaction(
			ctx, server, route, state, routeID, version, sessionToken, hostname, profile,
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
		} else if !errors.Is(err, serverclient.ErrUnavailable) && !errors.Is(err, serverclient.ErrRateLimited) {
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
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
	hostname, profile string,
) (clientstate.Material, error) {
	pending, err := state.CertificateAttempt(ctx, hostname)
	if err != nil {
		return clientstate.Material{}, err
	}
	issuance, err := server.CreateCertificateIssuance(
		ctx, routeID, version, sessionToken, profile, pending.CSRDER,
	)
	if err != nil {
		return clientstate.Material{}, err
	}
	if err := validateCertificateAttempt(
		ctx, server, route, state, issuance, routeID, version, sessionToken, hostname, profile, "", "",
	); err != nil {
		return clientstate.Material{}, err
	}
	challenge := issuance.Challenge
	if issuance.CertificatePem == nil && challenge == nil {
		return clientstate.Material{}, &pendingCertificateIssuanceError{retryAt: issuance.RetryAt}
	}
	if issuance.CertificatePem == nil {
		if issuance.Status != serverv1.CertificateIssuanceStatusWaitingForChallenge {
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
			ctx, server, route, state, issuance, routeID, version, sessionToken,
			hostname, profile, issuanceID, challenge.Id,
		); err != nil {
			return clientstate.Material{}, err
		}
		if issuance.CertificatePem == nil {
			return clientstate.Material{}, &pendingCertificateIssuanceError{retryAt: issuance.RetryAt}
		}
	}
	if challenge != nil {
		route.RemoveChallenge(challenge.Id)
		if err := server.CertificateChallengeRemoved(ctx, issuance.Id, sessionToken); err != nil {
			return clientstate.Material{}, err
		}
	}
	material, err := state.Commit(
		ctx, hostname, pending, []byte(*issuance.CertificatePem), *issuance.RenewAt, issuance.Id, version,
	)
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
	if err := server.CertificateInstalled(ctx, routeID, version, issuance.Id, sessionToken); err != nil {
		return material, err
	}
	installed, err := state.MarkInstalled(ctx, hostname, issuance.Id, version)
	if err != nil {
		return material, err
	}
	return installed, nil
}

func certificateChallenge(challenge *serverv1.CertificateChallenge, hostname string) (tlschallenge.TLSALPNChallenge, error) {
	digest, err := base64.RawURLEncoding.DecodeString(challenge.Digest)
	if err != nil || len(digest) != 32 || base64.RawURLEncoding.EncodeToString(digest) != challenge.Digest ||
		challenge.Id == "" || challenge.Hostname != hostname || !challenge.ExpiresAt.After(time.Now()) {
		return tlschallenge.TLSALPNChallenge{}, errors.New("publisher: server returned an invalid TLS-ALPN challenge digest")
	}
	result := tlschallenge.TLSALPNChallenge{
		ID: challenge.Id, Hostname: challenge.Hostname, ExpiresAt: challenge.ExpiresAt,
	}
	copy(result.Digest[:], digest)
	return result, nil
}

func validateCertificateAttempt(
	ctx context.Context,
	server RouteControlClient,
	route *Route,
	state *clientstate.RouteCertificateHandle,
	issuance serverv1.CertificateIssuance,
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
	hostname, profile, expectedID, installedChallengeID string,
) error {
	err := validateCertificateIssuance(issuance, routeID, version, hostname, profile, expectedID)
	var terminal *terminalCertificateIssuanceError
	if !errors.As(err, &terminal) {
		return err
	}
	if installedChallengeID == "" && issuance.Challenge != nil {
		installedChallengeID = issuance.Challenge.Id
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
	issuance serverv1.CertificateIssuance,
	routeID string,
	version uint64,
	hostname, profile string,
	expectedID string,
) error {
	if issuance.Id == "" || issuance.RouteId != routeID || issuance.RouteVersion != int(version) ||
		issuance.Hostname != hostname || issuance.AcmeProfile != profile || expectedID != "" && issuance.Id != expectedID {
		return errors.New("publisher: server returned a certificate issuance for a different route session")
	}
	if !issuance.Status.Valid() {
		return errors.New("publisher: server returned an unknown certificate issuance state")
	}
	if err := certificateIssuanceStatusError(issuance.Status); err != nil {
		return err
	}
	if issuance.CertificatePem != nil {
		if issuance.Status != serverv1.CertificateIssuanceStatusWaitingForInstall && issuance.Status != serverv1.CertificateIssuanceStatusInstalled ||
			issuance.NotBefore == nil || issuance.NotAfter == nil || issuance.RenewAt == nil {
			return errors.New("publisher: server returned certificate material in an inconsistent issuance state")
		}
	} else if issuance.Status == serverv1.CertificateIssuanceStatusWaitingForInstall || issuance.Status == serverv1.CertificateIssuanceStatusInstalled {
		return errors.New("publisher: server returned an installed issuance without certificate material")
	}
	if issuance.Challenge != nil && issuance.CertificatePem == nil {
		if !certificateIssuanceStatusAllowsChallenge(issuance.Status) {
			return errors.New("publisher: server returned a challenge in an inconsistent issuance state")
		}
	}
	if issuance.Challenge != nil {
		digest, err := base64.RawURLEncoding.DecodeString(issuance.Challenge.Digest)
		if err != nil || len(digest) != 32 || base64.RawURLEncoding.EncodeToString(digest) != issuance.Challenge.Digest ||
			issuance.Challenge.Id == "" || issuance.Challenge.Hostname != hostname || issuance.Challenge.ExpiresAt.IsZero() {
			return errors.New("publisher: server returned invalid TLS-ALPN challenge material")
		}
	}
	return nil
}

func certificateIssuanceStatusError(status serverv1.CertificateIssuanceStatus) error {
	if status == serverv1.CertificateIssuanceStatusFailed {
		return &terminalCertificateIssuanceError{state: status}
	}
	return nil
}

func certificateIssuanceStatusAllowsChallenge(status serverv1.CertificateIssuanceStatus) bool {
	switch status {
	case serverv1.CertificateIssuanceStatusWaitingForChallenge,
		serverv1.CertificateIssuanceStatusReadyToFinalize,
		serverv1.CertificateIssuanceStatusFinalizing:
		return true
	default:
		return false
	}
}

type terminalCertificateIssuanceError struct {
	state serverv1.CertificateIssuanceStatus
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

func (*pendingCertificateIssuanceError) Unwrap() error { return serverclient.ErrUnavailable }

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
	var limited *serverclient.RateLimitError
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
		var limited *serverclient.RateLimitError
		if errors.As(err, &limited) && limited.RetryAfter > 0 {
			delay = limited.RetryAfter
		}
	}
	return max(min(delay, time.Until(notAfter)), 0)
}

func heartbeatSession(
	ctx context.Context,
	server RouteControlClient,
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
	expiresAt time.Time,
) error {
	expiresAt, err := heartbeatOnce(ctx, server, routeID, version, sessionToken, expiresAt)
	if err != nil || ctx.Err() != nil {
		return err
	}
	return heartbeatSessionAfter(ctx, server, routeID, version, sessionToken, expiresAt)
}

func heartbeatSessionAfter(
	ctx context.Context,
	server RouteControlClient,
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
	expiresAt time.Time,
) error {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		var err error
		expiresAt, err = heartbeatOnce(ctx, server, routeID, version, sessionToken, expiresAt)
		if err != nil || ctx.Err() != nil {
			return err
		}
	}
}

func heartbeatOnce(
	ctx context.Context,
	server RouteControlClient,
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
	expiresAt time.Time,
) (time.Time, error) {
	callCtx, cancel := context.WithTimeout(ctx, heartbeatCallTimeout)
	response, err := server.Heartbeat(callCtx, routeID, version, sessionToken)
	cancel()
	if err == nil {
		return response.ExpiresAt, nil
	}
	if ctx.Err() != nil {
		return expiresAt, nil
	}
	// A missed heartbeat is safe only while the last confirmed session remains valid.
	if errors.Is(err, serverclient.ErrUnavailable) && time.Now().Before(expiresAt) {
		return expiresAt, nil
	}
	if errors.Is(err, serverclient.ErrUnavailable) {
		return expiresAt, serverclient.ErrStatusConflict
	}
	return expiresAt, err
}
