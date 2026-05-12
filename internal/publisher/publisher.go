package publisher

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
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
	heartbeatInterval  = 15 * time.Second
	activationRetry    = 2 * time.Second
	renewalRetry       = time.Minute
	relayCheckInterval = 15 * time.Second
)

type Server interface {
	CreateRoute(context.Context, serverv1.CreateRouteRequest) (serverv1.SessionSetup, error)
	ListRoutes(context.Context) ([]serverv1.Route, error)
	CreateRouteSession(context.Context, string, credentials.RouteToken, []string) (serverv1.SessionSetup, error)
	DeleteRoute(context.Context, string) error
	RegisterTransport(context.Context, string, uint64, credentials.SessionToken, transportv1.TailcatDescriptor) error
	Ready(context.Context, string, uint64, credentials.SessionToken) error
	Heartbeat(context.Context, string, uint64, credentials.SessionToken) (serverv1.HeartbeatResponse, error)
	CreateCertificateIssuance(context.Context, string, uint64, credentials.SessionToken, string, []byte) (serverv1.CertificateIssuance, error)
	CertificateChallengeReady(context.Context, string, credentials.SessionToken) (serverv1.CertificateIssuance, error)
	CertificateChallengeRemoved(context.Context, string, credentials.SessionToken) error
	CertificateInstalled(context.Context, string, uint64, string, credentials.SessionToken) error
}

type Config struct {
	Server            Server
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
	EventRoute        EventType = "route"
	EventProvisioning EventType = "provisioning"
	EventReady        EventType = "ready"
	EventDraining     EventType = "draining"
)

type Event struct {
	Type      EventType
	RouteID   string
	Hostname  string
	PublicURL string
	Version   uint64
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
	if err := observe(config, Event{Type: EventRoute, RouteID: routeID, Hostname: setup.Route.Hostname}); err != nil {
		return err
	}
	var routeState *clientstate.Route
	if automaticCertificates {
		routeState, err = clientstate.LockContext(ctx, config.State, routeID)
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
			Version: uint64(setup.Session.Version),
		}); err != nil {
			return err
		}
		err := runSession(ctx, config, setup, routeState, func() error {
			return observe(config, Event{
				Type: EventReady, RouteID: routeID, Hostname: setup.Route.Hostname,
				PublicURL: "https://" + setup.Route.Hostname, Version: uint64(setup.Session.Version),
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
	server Server,
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
	state *clientstate.Route,
	ready func() error,
) error {
	if setup.Route.Id == "" || setup.Session.Version <= 0 || setup.SessionToken == "" || setup.WorkerPublicKey == "" {
		return errors.New("publisher: server returned incomplete session setup")
	}
	sessionToken := credentials.SessionToken(setup.SessionToken)
	if _, _, err := credentials.ParseSessionToken(sessionToken); err != nil {
		return errors.New("publisher: server returned invalid session token")
	}
	var ingressKey key.NodePublic
	if err := ingressKey.UnmarshalText([]byte(setup.WorkerPublicKey)); err != nil || ingressKey.IsZero() {
		return errors.New("publisher: server returned invalid ingress key")
	}
	version := uint64(setup.Session.Version)
	sessionCtx, cancelSession := context.WithCancel(ctx)
	defer cancelSession()
	// Refresh before setup consumes the session, then continue heartbeats in the background.
	expiresAt, err := heartbeatOnce(
		sessionCtx, config.Server, setup.Route.Id, version, sessionToken, setup.Session.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("publisher: heartbeat: %w", err)
	}
	if sessionCtx.Err() != nil {
		return nil
	}
	heartbeatErrors := make(chan error, 1)
	go func() {
		if err := heartbeatSessionAfter(
			sessionCtx, config.Server, setup.Route.Id, version, sessionToken, expiresAt,
		); err != nil {
			heartbeatErrors <- err
		}
	}()
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
		AllowedClient:     ingressKey, RelayRegion: config.RelayRegion, Regions: config.Regions, Logf: config.Logf,
	})
	if err != nil {
		return err
	}
	defer route.Close()
	endpoint, err := route.Start(ctx)
	if err != nil {
		return err
	}

	for {
		err = config.Server.RegisterTransport(ctx, setup.Route.Id, version, sessionToken, endpoint)
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
		case err := <-heartbeatErrors:
			return err
		}
	}
	var nextRenewal time.Time
	if state != nil {
		if !hasMaterial {
			material, err = issueCertificate(
				ctx, config.Server, route, state, setup.Route.Id, version, sessionToken,
				setup.Route.Hostname, config.ACMEProfile, heartbeatErrors,
			)
			if err != nil {
				return err
			}
			hasMaterial = true
		} else if !material.Installed || !material.RenewAt.After(time.Now()) {
			replacement, refreshErr := refreshCertificate(
				ctx, config.Server, route, state, setup.Route.Id, version, sessionToken,
				setup.Route.Hostname, config.ACMEProfile, material, heartbeatErrors,
			)
			if !replacement.NotAfter.IsZero() {
				material = replacement
			}
			if refreshErr != nil {
				if errors.Is(refreshErr, serverclient.ErrStatusConflict) {
					return refreshErr
				}
				if !material.NotAfter.After(time.Now()) {
					return fmt.Errorf("publisher: renew expired certificate: %w", refreshErr)
				}
				logRenewalFailure(config.Logf, refreshErr)
				nextRenewal = time.Now().Add(min(renewalRetry, time.Until(material.NotAfter)))
			} else {
				material = replacement
			}
		}
		if nextRenewal.IsZero() {
			nextRenewal = material.RenewAt
		}
	}
	for {
		err = config.Server.Ready(ctx, setup.Route.Id, version, sessionToken)
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
		case err := <-heartbeatErrors:
			return err
		}
	}
	if err := ready(); err != nil {
		return err
	}
	var renewalTimer *time.Timer
	var renewal <-chan time.Time
	if state != nil {
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
			return errors.Join(
				observe(config, Event{Type: EventDraining, RouteID: setup.Route.Id, Hostname: setup.Route.Hostname, Version: version}),
				drainRoute(route, config.DrainTime),
			)
		case err := <-heartbeatErrors:
			return fmt.Errorf("publisher: heartbeat: %w", err)
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
			replacement, renewalErr := refreshCertificate(
				ctx, config.Server, route, state, setup.Route.Id, version, sessionToken,
				setup.Route.Hostname, config.ACMEProfile, material, heartbeatErrors,
			)
			if renewalErr != nil {
				if errors.Is(renewalErr, serverclient.ErrStatusConflict) {
					return renewalErr
				}
				if !replacement.NotAfter.IsZero() {
					material = replacement
				}
				if ctx.Err() != nil {
					return drainRoute(route, config.DrainTime)
				}
				if !material.NotAfter.After(time.Now()) {
					return fmt.Errorf("publisher: renew expired certificate: %w", renewalErr)
				}
				logRenewalFailure(config.Logf, renewalErr)
				renewalTimer.Reset(min(renewalRetry, time.Until(material.NotAfter)))
				continue
			}
			material = replacement
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

func refreshCertificate(
	ctx context.Context,
	server Server,
	route *Route,
	state *clientstate.Route,
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
	hostname, profile string,
	material clientstate.Material,
	heartbeatErrors <-chan error,
) (clientstate.Material, error) {
	if !material.Installed && material.RenewAt.After(time.Now()) && material.NotAfter.After(time.Now().Add(24*time.Hour)) {
		// Reconcile a committed certificate before issuing another issuance.
		reconciled, err := reconcileCertificateInstallation(
			ctx, server, route, state, routeID, version, sessionToken, hostname, profile, material, heartbeatErrors,
		)
		var terminal *terminalCertificateIssuanceError
		if !errors.As(err, &terminal) {
			return reconciled, err
		}
	}
	return issueCertificate(
		ctx, server, route, state, routeID, version, sessionToken, hostname, profile, heartbeatErrors,
	)
}

func logRenewalFailure(logf logger.Logf, err error) {
	if logf != nil {
		logf("certificate renewal failed; retrying while the current certificate remains valid: %v", err)
	}
}

func issueCertificate(
	ctx context.Context,
	server Server,
	route *Route,
	state *clientstate.Route,
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
	hostname, profile string,
	heartbeatErrors <-chan error,
) (clientstate.Material, error) {
	pending, err := state.Pending(ctx, hostname)
	if err != nil {
		return clientstate.Material{}, err
	}
	rotatedTerminalIssuance := false
	createAndRecord := func() (serverv1.CertificateIssuance, error) {
		for {
			issuance, createErr := createCertificateIssuance(
				ctx, server, routeID, version, sessionToken, hostname, profile, pending.CSRDER, heartbeatErrors,
			)
			var terminal *terminalCertificateIssuanceError
			if errors.As(createErr, &terminal) && !rotatedTerminalIssuance {
				// Retry one terminal issuance with fresh key material.
				pending, createErr = state.NewPending(ctx, hostname)
				if createErr != nil {
					return serverv1.CertificateIssuance{}, createErr
				}
				rotatedTerminalIssuance = true
				continue
			}
			if createErr != nil {
				return serverv1.CertificateIssuance{}, createErr
			}
			pending, createErr = state.RecordIssuance(ctx, hostname, pending, issuance.Id, version)
			return issuance, createErr
		}
	}
	issuance, err := createAndRecord()
	if err != nil {
		return clientstate.Material{}, err
	}
issuanceLoop:
	for {
		if issuance.CertificatePem != nil {
			if issuance.Challenge != nil {
				route.RemoveChallenge(issuance.Challenge.Id)
				if err := acknowledgeChallengeRemoval(ctx, server, issuance.Id, sessionToken, heartbeatErrors); err != nil {
					return clientstate.Material{}, err
				}
			}
			break
		}
		if issuance.Challenge == nil {
			if err := waitCertificateRetry(ctx, heartbeatErrors, certificateIssuanceRetry(issuance)); err != nil {
				return clientstate.Material{}, err
			}
			issuance, err = createAndRecord()
			if err != nil {
				return clientstate.Material{}, err
			}
			continue
		}
		digest, err := base64.RawURLEncoding.DecodeString(issuance.Challenge.Digest)
		if err != nil || len(digest) != 32 || base64.RawURLEncoding.EncodeToString(digest) != issuance.Challenge.Digest ||
			issuance.Challenge.Id == "" || issuance.Challenge.Hostname != hostname || !issuance.Challenge.ExpiresAt.After(time.Now()) {
			return clientstate.Material{}, errors.New("publisher: server returned an invalid TLS-ALPN challenge digest")
		}
		challenge := tlschallenge.TLSALPNChallenge{
			ID: issuance.Challenge.Id, Hostname: issuance.Challenge.Hostname, ExpiresAt: issuance.Challenge.ExpiresAt,
		}
		copy(challenge.Digest[:], digest)
		if err := route.InstallChallenge(challenge); err != nil {
			return clientstate.Material{}, err
		}
		defer route.RemoveChallenge(challenge.ID)
		for {
			expectedIssuanceID := issuance.Id
			advanced, readyErr := server.CertificateChallengeReady(ctx, expectedIssuanceID, sessionToken)
			err = readyErr
			if err == nil {
				if err := validateCertificateIssuance(advanced, routeID, version, hostname, profile, expectedIssuanceID); err != nil {
					var terminal *terminalCertificateIssuanceError
					if errors.As(err, &terminal) && !rotatedTerminalIssuance {
						route.RemoveChallenge(challenge.ID)
						pending, err = state.NewPending(ctx, hostname)
						if err != nil {
							return clientstate.Material{}, err
						}
						rotatedTerminalIssuance = true
						issuance, err = createAndRecord()
						if err != nil {
							return clientstate.Material{}, err
						}
						continue issuanceLoop
					}
					return clientstate.Material{}, err
				}
				issuance = advanced
				if issuance.CertificatePem != nil {
					break
				}
				if err := waitCertificateRetry(ctx, heartbeatErrors, certificateIssuanceRetry(issuance)); err != nil {
					return clientstate.Material{}, err
				}
				continue
			}
			if !errors.Is(err, serverclient.ErrUnavailable) {
				return clientstate.Material{}, err
			}
			if err := waitCertificateRetry(ctx, heartbeatErrors, activationRetry); err != nil {
				return clientstate.Material{}, err
			}
		}
		route.RemoveChallenge(challenge.ID)
		if err := acknowledgeChallengeRemoval(ctx, server, issuance.Id, sessionToken, heartbeatErrors); err != nil {
			return clientstate.Material{}, err
		}
	}
	if issuance.CertificatePem == nil || issuance.RenewAt == nil || issuance.Id == "" {
		return clientstate.Material{}, errors.New("publisher: server returned incomplete certificate material")
	}
	return installCertificateIssuance(
		ctx, server, route, state, routeID, version, sessionToken, hostname, pending, issuance, heartbeatErrors,
	)
}

func installCertificateIssuance(
	ctx context.Context,
	server Server,
	route *Route,
	state *clientstate.Route,
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
	hostname string,
	pending clientstate.Pending,
	issuance serverv1.CertificateIssuance,
	heartbeatErrors <-chan error,
) (clientstate.Material, error) {
	// Persist and verify before acknowledging the server; MarkInstalled closes the recovery window.
	material, err := state.Commit(
		ctx,
		hostname, pending, []byte(*issuance.CertificatePem), *issuance.RenewAt, issuance.Id, version,
	)
	if err != nil {
		return material, err
	}
	if err := route.InstallCertificate(material.Certificate); err != nil {
		return material, err
	}
	if err := route.VerifyCertificate(material.Certificate); err != nil {
		return material, err
	}
	if err := acknowledgeCertificate(
		ctx, server, routeID, version, issuance.Id, sessionToken, heartbeatErrors,
	); err != nil {
		return material, err
	}
	installed, err := state.MarkInstalled(ctx, hostname, issuance.Id, version)
	if err != nil {
		return material, err
	}
	return installed, nil
}

func createCertificateIssuance(
	ctx context.Context,
	server Server,
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
	hostname, profile string,
	csrDER []byte,
	heartbeatErrors <-chan error,
) (serverv1.CertificateIssuance, error) {
	for {
		issuance, err := server.CreateCertificateIssuance(ctx, routeID, version, sessionToken, profile, csrDER)
		if err == nil {
			if err := validateCertificateIssuance(issuance, routeID, version, hostname, profile, ""); err != nil {
				return serverv1.CertificateIssuance{}, err
			}
			return issuance, nil
		}
		if !errors.Is(err, serverclient.ErrUnavailable) && !errors.Is(err, serverclient.ErrRateLimited) {
			return serverv1.CertificateIssuance{}, err
		}
		if err := waitCertificateRetry(ctx, heartbeatErrors, certificateRetryDelay(err)); err != nil {
			return serverv1.CertificateIssuance{}, err
		}
	}
}

func reconcileCertificateInstallation(
	ctx context.Context,
	server Server,
	route *Route,
	state *clientstate.Route,
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
	hostname, profile string,
	material clientstate.Material,
	heartbeatErrors <-chan error,
) (clientstate.Material, error) {
	issuance, err := createCertificateIssuance(
		ctx, server, routeID, version, sessionToken, hostname, profile, material.CSRDER, heartbeatErrors,
	)
	if err != nil {
		return material, err
	}
	for issuance.CertificatePem == nil && issuance.Challenge == nil {
		if err := waitCertificateRetry(ctx, heartbeatErrors, certificateIssuanceRetry(issuance)); err != nil {
			return material, err
		}
		issuance, err = createCertificateIssuance(
			ctx, server, routeID, version, sessionToken, hostname, profile, material.CSRDER, heartbeatErrors,
		)
		if err != nil {
			return material, err
		}
	}
	if issuance.CertificatePem == nil {
		return completeReboundCertificateIssuance(
			ctx, server, route, state, routeID, version, sessionToken, hostname, profile, material, issuance, heartbeatErrors,
		)
	}
	chain, err := decodeCertificateChain([]byte(*issuance.CertificatePem))
	if err != nil || !equalCertificateChain(chain, material.Certificate.Certificate) || !issuance.RenewAt.Equal(material.RenewAt) {
		return material, errors.New("publisher: reused certificate does not match persisted material")
	}
	updated, err := state.RecordCurrentIssuance(ctx, hostname, issuance.Id, version)
	if err != nil {
		return material, err
	}
	material = updated
	if err := route.VerifyCertificate(material.Certificate); err != nil {
		return material, err
	}
	if err := acknowledgeCertificate(
		ctx, server, routeID, version, issuance.Id, sessionToken, heartbeatErrors,
	); err != nil {
		return material, err
	}
	installed, err := state.MarkInstalled(ctx, hostname, issuance.Id, version)
	if err != nil {
		return material, err
	}
	return installed, nil
}

func completeReboundCertificateIssuance(
	ctx context.Context,
	server Server,
	route *Route,
	state *clientstate.Route,
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
	hostname, profile string,
	current clientstate.Material,
	issuance serverv1.CertificateIssuance,
	heartbeatErrors <-chan error,
) (clientstate.Material, error) {
	pending, err := state.CurrentKey(ctx, hostname)
	if err != nil {
		return current, err
	}
	digest, err := base64.RawURLEncoding.DecodeString(issuance.Challenge.Digest)
	if err != nil || len(digest) != 32 || base64.RawURLEncoding.EncodeToString(digest) != issuance.Challenge.Digest ||
		issuance.Challenge.Id == "" || issuance.Challenge.Hostname != hostname || !issuance.Challenge.ExpiresAt.After(time.Now()) {
		return current, errors.New("publisher: server returned an invalid TLS-ALPN challenge digest")
	}
	challenge := tlschallenge.TLSALPNChallenge{
		ID: issuance.Challenge.Id, Hostname: issuance.Challenge.Hostname, ExpiresAt: issuance.Challenge.ExpiresAt,
	}
	copy(challenge.Digest[:], digest)
	if err := route.InstallChallenge(challenge); err != nil {
		return current, err
	}
	defer route.RemoveChallenge(challenge.ID)
	for issuance.CertificatePem == nil {
		expectedIssuanceID := issuance.Id
		advanced, readyErr := server.CertificateChallengeReady(ctx, expectedIssuanceID, sessionToken)
		if readyErr != nil {
			if !errors.Is(readyErr, serverclient.ErrUnavailable) {
				return current, readyErr
			}
			if err := waitCertificateRetry(ctx, heartbeatErrors, activationRetry); err != nil {
				return current, err
			}
			continue
		}
		if err := validateCertificateIssuance(advanced, routeID, version, hostname, profile, expectedIssuanceID); err != nil {
			return current, err
		}
		issuance = advanced
		if issuance.CertificatePem == nil {
			if err := waitCertificateRetry(ctx, heartbeatErrors, certificateIssuanceRetry(issuance)); err != nil {
				return current, err
			}
		}
	}
	route.RemoveChallenge(challenge.ID)
	if err := acknowledgeChallengeRemoval(ctx, server, issuance.Id, sessionToken, heartbeatErrors); err != nil {
		return current, err
	}
	replacement, err := installCertificateIssuance(
		ctx, server, route, state, routeID, version, sessionToken, hostname, pending, issuance, heartbeatErrors,
	)
	if replacement.NotAfter.IsZero() {
		return current, err
	}
	return replacement, err
}

func acknowledgeCertificate(
	ctx context.Context,
	server Server,
	routeID string,
	version uint64,
	issuanceID string,
	sessionToken credentials.SessionToken,
	heartbeatErrors <-chan error,
) error {
	for {
		err := server.CertificateInstalled(ctx, routeID, version, issuanceID, sessionToken)
		if err == nil {
			return nil
		}
		if !errors.Is(err, serverclient.ErrUnavailable) {
			return err
		}
		if err := waitCertificateRetry(ctx, heartbeatErrors, activationRetry); err != nil {
			return err
		}
	}
}

func acknowledgeChallengeRemoval(
	ctx context.Context,
	server Server,
	issuanceID string,
	sessionToken credentials.SessionToken,
	heartbeatErrors <-chan error,
) error {
	for {
		err := server.CertificateChallengeRemoved(ctx, issuanceID, sessionToken)
		if err == nil {
			return nil
		}
		if !errors.Is(err, serverclient.ErrUnavailable) {
			return err
		}
		if err := waitCertificateRetry(ctx, heartbeatErrors, activationRetry); err != nil {
			return err
		}
	}
}

func validateCertificateIssuance(
	issuance serverv1.CertificateIssuance,
	routeID string,
	version uint64,
	hostname, profile string,
	expectedID string,
) error {
	if issuance.Id == "" || issuance.RouteId != routeID || issuance.Version != int(version) ||
		issuance.Hostname != hostname || issuance.AcmeProfile != profile || expectedID != "" && issuance.Id != expectedID {
		return errors.New("publisher: server returned a certificate issuance for a different route session")
	}
	if !issuance.Status.Valid() {
		return errors.New("publisher: server returned an unknown certificate issuance state")
	}
	switch issuance.Status {
	case serverv1.CertificateIssuanceStatusFailed, serverv1.CertificateIssuanceStatusBlocked, serverv1.CertificateIssuanceStatusCanceled:
		return &terminalCertificateIssuanceError{state: issuance.Status}
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
		switch issuance.Status {
		case serverv1.CertificateIssuanceStatusWaitingForChallenge, serverv1.CertificateIssuanceStatusValidating, serverv1.CertificateIssuanceStatusReadyToFinalize, serverv1.CertificateIssuanceStatusFinalizing, serverv1.CertificateIssuanceStatusDownloading:
		default:
			return errors.New("publisher: server returned a challenge in an inconsistent issuance state")
		}
	}
	if issuance.Challenge == nil && issuance.Status == serverv1.CertificateIssuanceStatusWaitingForChallenge {
		return errors.New("publisher: server returned a challenge issuance without challenge material")
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

type terminalCertificateIssuanceError struct {
	state serverv1.CertificateIssuanceStatus
}

func (e *terminalCertificateIssuanceError) Error() string {
	return fmt.Sprintf("publisher: certificate issuance became %s", e.state)
}

func decodeCertificateChain(certificatePEM []byte) ([][]byte, error) {
	var chain [][]byte
	remaining := bytes.TrimSpace(certificatePEM)
	for len(remaining) != 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Bytes) == 0 {
			return nil, errors.New("publisher: invalid certificate chain")
		}
		chain = append(chain, block.Bytes)
		remaining = bytes.TrimSpace(rest)
	}
	if len(chain) == 0 {
		return nil, errors.New("publisher: empty certificate chain")
	}
	return chain, nil
}

func equalCertificateChain(left, right [][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !bytes.Equal(left[index], right[index]) {
			return false
		}
	}
	return true
}

func certificateIssuanceRetry(issuance serverv1.CertificateIssuance) time.Duration {
	if issuance.RetryAt != nil && issuance.RetryAt.After(time.Now()) {
		return min(time.Until(*issuance.RetryAt), time.Minute)
	}
	return activationRetry
}

func drainRoute(route *Route, timeout time.Duration) error {
	drainCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return route.Drain(drainCtx)
}

func waitCertificateRetry(ctx context.Context, heartbeatErrors <-chan error, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-heartbeatErrors:
		return fmt.Errorf("publisher: heartbeat: %w", err)
	case <-timer.C:
		return nil
	}
}

func certificateRetryDelay(err error) time.Duration {
	var limited *serverclient.RateLimitError
	if errors.As(err, &limited) && limited.RetryAfter > 0 {
		return min(limited.RetryAfter, 24*time.Hour)
	}
	return activationRetry
}

func heartbeatSession(
	ctx context.Context,
	server Server,
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
	server Server,
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
	server Server,
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
