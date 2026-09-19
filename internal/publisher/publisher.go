package publisher

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const defaultProvisioningStalledDelay = 2 * time.Minute

type RouteControlClient interface {
	CreateRoute(context.Context, controlv1.CreateRouteRequest, string) (controlv1.Route, error)
	GetRouteByHostname(context.Context, string, string) (controlv1.Route, error)
	UpdateRoute(context.Context, string, controlv1.UpdateRouteRequest) (controlv1.Route, error)
	DeleteRoute(context.Context, string) error
	CreateRouteSession(context.Context, string, string) (controlv1.RouteSessionSetup, error)
	CloseRouteSession(context.Context, string, credentials.RouteSessionToken) error
	MarkRouteSessionReady(context.Context, string, uint64, credentials.RouteSessionToken) error
	HeartbeatRouteSession(context.Context, string, uint64, credentials.RouteSessionToken) (controlv1.RouteSessionHeartbeat, error)
	CreateCertificateIssuance(context.Context, string, uint64, credentials.RouteSessionToken, []byte, string) (controlv1.CertificateIssuance, error)
	GetCertificateIssuance(context.Context, string, credentials.RouteSessionToken) (controlv1.CertificateIssuance, error)
	MarkCertificateChallengeReady(context.Context, string, credentials.RouteSessionToken) (controlv1.CertificateIssuance, error)
	MarkCertificateChallengeRemoved(context.Context, string, credentials.RouteSessionToken) error
	MarkRouteSessionCertificateInstalled(context.Context, string, uint64, string, time.Time, credentials.RouteSessionToken) error
}

type Config struct {
	Control                  RouteControlClient
	TeamID                   string
	DomainID                 string
	MembershipID             string
	PolicyRevision           uint64
	RouteScope               controlv1.RouteScope
	Hostname                 string
	Target                   string
	RequestLimit             int // Zero selects localproxy.DefaultRequestLimit.
	AllowedIPPrefixes        []string
	Ephemeral                bool
	State                    *clientstate.Store
	QUICConnector            muxsession.Connector
	TCPConnector             muxsession.Connector
	FallbackDelay            time.Duration
	DrainTime                time.Duration
	ProvisioningStalledDelay time.Duration
	Logf                     func(string, ...any)
	Observe                  func(Event) error
	heartbeatInterval        time.Duration
}

type EventType string

const (
	EventRouteAssigned       EventType = "route"
	EventProvisioning        EventType = "provisioning"
	EventProvisioningStalled EventType = "provisioning_stalled"
	EventReady               EventType = "ready"
	EventDraining            EventType = "draining"
	EventTransportFallback   EventType = "transport_fallback"
	EventIPPolicyDenials     EventType = "ip_policy_denials"
)

type Event struct {
	Type          EventType
	RouteID       string
	Hostname      string
	PublicURL     string
	RouteVersion  uint64
	Transport     tunnel.Transport
	PolicyDenials uint64
}

func Run(ctx context.Context, config Config) (result error) {
	if config.Control == nil {
		return errors.New("publisher: control client is required")
	}
	if config.RequestLimit < 0 {
		return errors.New("publisher: request limit cannot be negative")
	}
	if config.DrainTime < 0 || config.FallbackDelay < 0 {
		return errors.New("publisher: drain time and fallback delay cannot be negative")
	}
	if config.ProvisioningStalledDelay < 0 {
		return errors.New("publisher: provisioning stalled delay cannot be negative")
	}
	if config.DrainTime == 0 {
		config.DrainTime = 30 * time.Second
	}
	if config.FallbackDelay == 0 {
		config.FallbackDelay = 250 * time.Millisecond
	}
	if config.ProvisioningStalledDelay == 0 {
		config.ProvisioningStalledDelay = defaultProvisioningStalledDelay
	}
	if config.QUICConnector == nil || config.TCPConnector == nil {
		return errors.New("publisher: QUIC and TLS/yamux connectors are required")
	}
	hostname, err := naming.CanonicalizeHostname(config.Hostname)
	if err != nil {
		return err
	}
	config.Hostname = hostname
	if config.State == nil {
		return errors.New("publisher: client state is required")
	}
	config.Target, err = localproxy.NormalizeTarget(config.Target)
	if err != nil {
		return err
	}
	if err := localproxy.Preflight(ctx, config.Target); err != nil {
		return err
	}
	hostLock, err := clientstate.LockHostnameContext(ctx, config.State, hostname)
	if err != nil {
		return err
	}
	defer hostLock.Close()
	route, createdRoute, err := createOrLoadRoute(ctx, config)
	if err != nil {
		return err
	}
	routeID := route.Id
	if config.Ephemeral && createdRoute {
		defer func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			deleteErr := config.Control.DeleteRoute(cleanupCtx, route.Id)
			cancel()
			if deleteErr != nil && !errors.Is(deleteErr, controlclient.ErrNotFound) {
				result = errors.Join(result, fmt.Errorf("publisher: delete ephemeral route: %w", deleteErr))
			}
		}()
	}
	if err := observe(config, Event{Type: EventRouteAssigned, RouteID: routeID, Hostname: route.CanonicalHostname}); err != nil {
		return err
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
		err = runSession(ctx, config, setup, func() error {
			return observe(config, Event{
				Type: EventReady, RouteID: routeID, Hostname: setup.Route.CanonicalHostname,
				PublicURL: "https://" + setup.Route.CanonicalHostname, RouteVersion: uint64(setup.RouteSession.RouteVersion),
			})
		})
		closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		closeErr := config.Control.CloseRouteSession(closeCtx, setup.RouteSession.Id, credentials.RouteSessionToken(setup.RouteSessionToken))
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

func createOrLoadRoute(ctx context.Context, config Config) (controlv1.Route, bool, error) {
	allowedIPPrefixes, err := authorization.CanonicalizeIPPrefixes(config.AllowedIPPrefixes)
	if err != nil {
		return controlv1.Route{}, false, fmt.Errorf("publisher: invalid allowed IP prefixes: %w", err)
	}
	config.AllowedIPPrefixes = allowedIPPrefixes
	if !config.Ephemeral {
		route, err := config.Control.GetRouteByHostname(ctx, config.TeamID, config.Hostname)
		if err != nil && !errors.Is(err, controlclient.ErrNotFound) {
			return controlv1.Route{}, false, err
		}
		if err == nil {
			if err := validateRouteIdentity(route, config); err != nil {
				return controlv1.Route{}, false, err
			}
			reconciled, err := reconcileRoute(ctx, config, route)
			return reconciled, false, err
		}
	}
	idempotencyKey, err := opaqueID("route_")
	if err != nil {
		return controlv1.Route{}, false, err
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
	if config.Ephemeral {
		body.Ephemeral = &config.Ephemeral
	}
	route, err := config.Control.CreateRoute(ctx, body, idempotencyKey)
	return route, err == nil, classifyRouteConflict(err)
}

func validateRouteIdentity(route controlv1.Route, config Config) error {
	if route.CanonicalHostname != config.Hostname || route.TeamId != config.TeamID || route.DomainId != config.DomainID || route.RouteScope != config.RouteScope ||
		route.Ephemeral != config.Ephemeral {
		return diagnostic.Wrap(diagnostic.RouteConflict, errors.New("publisher: existing route identity does not match the requested route"))
	}
	if config.RouteScope == controlv1.Member {
		if route.MembershipId == nil || *route.MembershipId != config.MembershipID {
			return diagnostic.Wrap(diagnostic.RouteConflict, errors.New("publisher: existing route identity does not match the requested route"))
		}
	} else if route.MembershipId != nil {
		return diagnostic.Wrap(diagnostic.RouteConflict, errors.New("publisher: existing route identity does not match the requested route"))
	}
	return nil
}

func reconcileRoute(ctx context.Context, config Config, route controlv1.Route) (controlv1.Route, error) {
	if route.LifecycleState != controlv1.Enabled {
		return controlv1.Route{}, diagnostic.Wrap(
			diagnostic.RouteConflict,
			fmt.Errorf("publisher: route %s is not enabled", route.Id),
		)
	}
	currentPolicy := []string{}
	if route.AllowedIpPrefixes != nil {
		currentPolicy = *route.AllowedIpPrefixes
	}
	desiredPolicy := config.AllowedIPPrefixes
	if desiredPolicy == nil {
		desiredPolicy = []string{}
	}
	if !slices.Equal(currentPolicy, desiredPolicy) {
		updated, err := config.Control.UpdateRoute(ctx, route.Id, controlv1.UpdateRouteRequest{
			Target: config.Target, AllowedIpPrefixes: slices.Clone(desiredPolicy),
		})
		return updated, classifyRouteConflict(err)
	}
	if route.Target == config.Target {
		return route, nil
	}
	updated, err := config.Control.UpdateRoute(ctx, route.Id, controlv1.UpdateRouteRequest{
		Target: config.Target, AllowedIpPrefixes: slices.Clone(desiredPolicy),
	})
	return updated, classifyRouteConflict(err)
}

func classifyRouteConflict(err error) error {
	if errors.Is(err, controlclient.ErrNameUnavailable) || errors.Is(err, controlclient.ErrStatusConflict) {
		return diagnostic.Wrap(diagnostic.RouteConflict, err)
	}
	return err
}

func observe(config Config, event Event) error {
	if config.Observe == nil {
		return nil
	}
	return config.Observe(event)
}

func opaqueID(prefix string) (string, error) {
	id, err := opaqueid.New(prefix)
	if err != nil {
		return "", fmt.Errorf("publisher: generate idempotency key: %w", err)
	}
	return id, nil
}
