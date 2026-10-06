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

type PublicURLControlClient interface {
	CreatePublicURL(context.Context, controlv1.CreatePublicURLRequest, string) (controlv1.PublicURL, error)
	GetPublicURLByHostname(context.Context, string, string) (controlv1.PublicURL, error)
	UpdatePublicURL(context.Context, string, controlv1.UpdatePublicURLRequest) (controlv1.PublicURL, error)
	DeletePublicURL(context.Context, string) error
	CreatePublishRun(context.Context, string, string) (controlv1.PublishRunSetup, error)
	ClosePublishRun(context.Context, string, credentials.PublishRunToken) error
	MarkPublishRunReady(context.Context, string, uint64, credentials.PublishRunToken) error
	HeartbeatPublishRun(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.PublishRunHeartbeat, error)
	CreateCertificateIssuance(context.Context, string, uint64, credentials.PublishRunToken, []byte, string) (controlv1.CertificateIssuance, error)
	GetCertificateIssuance(context.Context, string, credentials.PublishRunToken) (controlv1.CertificateIssuance, error)
	MarkCertificateChallengeReady(context.Context, string, credentials.PublishRunToken) (controlv1.CertificateIssuance, error)
	MarkCertificateChallengeRemoved(context.Context, string, credentials.PublishRunToken) error
	MarkPublishRunCertificateInstalled(context.Context, string, uint64, string, time.Time, credentials.PublishRunToken) error
}

type Config struct {
	Control                  PublicURLControlClient
	ControlURL               string
	BrowserLoginAvailable    bool
	TeamID                   string
	DomainID                 string
	MembershipID             string
	PolicyRevision           uint64
	PublicURLScope           controlv1.PublicURLScope
	Hostname                 string
	PreviewID                string
	Feedback                 bool
	Demo                     bool
	ProjectRoot              string
	Service                  string
	Target                   string
	Mounts                   []localproxy.Mount
	RequestLimit             int // zero selects localproxy.DefaultRequestLimit.
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
	EventPublicURLAssigned   EventType = "route" // preserve the existing internal event value.
	EventProvisioning        EventType = "provisioning"
	EventProvisioningStalled EventType = "provisioning_stalled"
	EventReady               EventType = "ready"
	EventDraining            EventType = "draining"
	EventTransportFallback   EventType = "transport_fallback"
	EventIPPolicyDenials     EventType = "ip_policy_denials"
	EventTargetUnavailable   EventType = "target_unavailable"
)

type Event struct {
	Type             EventType
	PublicURLID      string
	Hostname         string
	PublicURL        string
	PublishRunNumber uint64
	Transport        tunnel.Transport
	PolicyDenials    uint64
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
	route, createdPublicURL, err := createOrLoadPublicURL(ctx, config)
	if err != nil {
		return err
	}
	publicURLID := route.Id
	if config.Ephemeral && createdPublicURL {
		defer func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			deleteErr := config.Control.DeletePublicURL(cleanupCtx, route.Id)
			cancel()
			if deleteErr != nil && !errors.Is(deleteErr, controlclient.ErrNotFound) {
				result = errors.Join(result, fmt.Errorf("publisher: delete ephemeral public_url: %w", deleteErr))
			}
		}()
	}
	if err := observe(config, Event{Type: EventPublicURLAssigned, PublicURLID: publicURLID, Hostname: route.CanonicalHostname}); err != nil {
		return err
	}
	for {
		setup, err := createPublishRun(ctx, config, route)
		if err != nil {
			return err
		}
		err = runPublishRun(ctx, config, setup, func() error {
			return observe(config, Event{
				Type: EventReady, PublicURLID: publicURLID, Hostname: setup.PublicUrl.CanonicalHostname,
				PublicURL: "https://" + setup.PublicUrl.CanonicalHostname, PublishRunNumber: uint64(setup.PublishRun.PublishRunNumber),
			})
		})
		if ctx.Err() != nil {
			return err
		}
		if !errors.Is(err, controlclient.ErrStatusConflict) {
			return err
		}
		route.NextPublishRunNumber = setup.PublishRun.PublishRunNumber + 1
	}
}

func runPublishRun(ctx context.Context, config Config, setup controlv1.PublishRunSetup, ready func() error) (result error) {
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		closeErr := config.Control.ClosePublishRun(closeCtx, setup.PublishRun.Id, credentials.PublishRunToken(setup.PublishRunToken))
		if closeErr != nil && !errors.Is(closeErr, controlclient.ErrNotFound) && !errors.Is(closeErr, controlclient.ErrUnauthenticated) {
			result = errors.Join(result, fmt.Errorf("publisher: close publish run: %w", closeErr))
		}
	}()
	if err := observe(config, Event{
		Type: EventProvisioning, PublicURLID: setup.PublicUrl.Id, Hostname: setup.PublicUrl.CanonicalHostname,
		PublishRunNumber: uint64(setup.PublishRun.PublishRunNumber),
	}); err != nil {
		return err
	}
	return runSession(ctx, config, setup, ready)
}

func createOrLoadPublicURL(ctx context.Context, config Config) (controlv1.PublicURL, bool, error) {
	allowedIPPrefixes, err := authorization.CanonicalizeIPPrefixes(config.AllowedIPPrefixes)
	if err != nil {
		return controlv1.PublicURL{}, false, fmt.Errorf("publisher: invalid allowed IP prefixes: %w", err)
	}
	config.AllowedIPPrefixes = allowedIPPrefixes
	if !config.Ephemeral {
		route, err := config.Control.GetPublicURLByHostname(ctx, config.TeamID, config.Hostname)
		if err != nil && !errors.Is(err, controlclient.ErrNotFound) {
			return controlv1.PublicURL{}, false, err
		}
		if err == nil {
			if err := validateRouteIdentity(route, config); err != nil {
				return controlv1.PublicURL{}, false, err
			}
			reconciled, err := reconcilePublicURL(ctx, config, route)
			return reconciled, false, err
		}
	}
	idempotencyKey, err := opaqueID(opaqueid.IdempotencyPrefix)
	if err != nil {
		return controlv1.PublicURL{}, false, err
	}
	body := controlv1.CreatePublicURLRequest{
		TeamId: config.TeamID, DomainId: config.DomainID, CanonicalHostname: config.Hostname,
		Target: config.Target, PublicUrlScope: config.PublicURLScope,
	}
	if config.PublicURLScope == controlv1.Member && config.MembershipID != "" {
		body.MembershipId = &config.MembershipID
	}
	if config.AllowedIPPrefixes != nil {
		allowed := slices.Clone(config.AllowedIPPrefixes)
		body.AllowedIpPrefixes = &allowed
	}
	if config.Ephemeral {
		body.Ephemeral = &config.Ephemeral
	}
	route, err := config.Control.CreatePublicURL(ctx, body, idempotencyKey)
	return route, err == nil, classifyPublicURLConflict(err)
}

func validateRouteIdentity(route controlv1.PublicURL, config Config) error {
	if route.CanonicalHostname != config.Hostname || route.TeamId != config.TeamID || route.DomainId != config.DomainID || route.PublicUrlScope != config.PublicURLScope ||
		route.Ephemeral != config.Ephemeral {
		return diagnostic.Wrap(diagnostic.PublicURLConflict, errors.New("publisher: existing public URL identity does not match the requested public URL"))
	}
	if config.PublicURLScope == controlv1.Member {
		if route.MembershipId == nil || *route.MembershipId != config.MembershipID {
			return diagnostic.Wrap(diagnostic.PublicURLConflict, errors.New("publisher: existing public URL identity does not match the requested public URL"))
		}
	} else if route.MembershipId != nil {
		return diagnostic.Wrap(diagnostic.PublicURLConflict, errors.New("publisher: existing public URL identity does not match the requested public URL"))
	}
	return nil
}

func reconcilePublicURL(ctx context.Context, config Config, route controlv1.PublicURL) (controlv1.PublicURL, error) {
	if route.LifecycleState != controlv1.Enabled {
		return controlv1.PublicURL{}, diagnostic.Wrap(
			diagnostic.PublicURLConflict,
			fmt.Errorf("publisher: public URL %s is not enabled", route.Id),
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
		updated, err := config.Control.UpdatePublicURL(ctx, route.Id, controlv1.UpdatePublicURLRequest{
			Target: config.Target, AllowedIpPrefixes: slices.Clone(desiredPolicy),
		})
		return updated, classifyPublicURLConflict(err)
	}
	if route.Target == config.Target {
		return route, nil
	}
	updated, err := config.Control.UpdatePublicURL(ctx, route.Id, controlv1.UpdatePublicURLRequest{
		Target: config.Target, AllowedIpPrefixes: slices.Clone(desiredPolicy),
	})
	return updated, classifyPublicURLConflict(err)
}

func classifyPublicURLConflict(err error) error {
	if errors.Is(err, controlclient.ErrNameUnavailable) || errors.Is(err, controlclient.ErrStatusConflict) {
		return diagnostic.Wrap(diagnostic.PublicURLConflict, err)
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
