package publisher

import (
	"context"
	"errors"
	"fmt"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/observability"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func Run(ctx context.Context, config Config) (result error) {
	if config.Control == nil {
		return errors.New("publisher: control client is required")
	}
	if err := config.Limits.Validate(); err != nil {
		return err
	}
	if !config.InspectionMode.Valid() {
		return errors.New("publisher: inspection mode must be none or summary")
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
	if config.ServiceProtocol == "" {
		config.ServiceProtocol = controlv1.Http
	}
	if config.ServiceProtocol != controlv1.Http {
		return errors.New("publisher: only HTTP uses public URL runs; use a service for TCP")
	}
	ctx = observability.WithPublisherProtocol(ctx, "http")
	if config.ServiceProtocol == controlv1.Http {
		if config.TargetTLSName != "" {
			config.TargetOptions.ServerName = config.TargetTLSName
		}
		config.Target, err = targetsyntax.NormalizeTarget(config.Target)
		if err != nil {
			return err
		}
		if config.Handler == nil {
			err = publisherproxy.PreflightWithOptions(ctx, config.Target, config.TargetOptions)
		}
	}
	if err != nil {
		return err
	}
	config.PublisherIdentityID, err = configuredPublisherIdentityID(config)
	if err != nil {
		return err
	}
	hostLock, err := clientstate.LockPublisherHostnameContext(ctx, config.State, hostname, config.PublisherIdentityID)
	if err != nil {
		return err
	}
	defer hostLock.Close()
	publicURL, createdPublicURL, err := createOrLoadPublicURL(ctx, config)
	if err != nil {
		return err
	}
	publicURLID := publicURL.Id
	ctx = observability.NarrowIdentity(ctx, observability.Identity{TeamID: publicURL.TeamId, PublisherIdentityID: config.PublisherIdentityID, PublicURLID: publicURL.Id})
	ctx = observability.WithFields(ctx, observability.Fields{Component: "publisher", ServiceProtocol: observability.ProtocolHTTP, AccessPath: "public_endpoint", Exposure: "public"})
	if config.Ephemeral && createdPublicURL {
		defer func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			deleteErr := config.Control.DeletePublicURL(cleanupCtx, publicURL.Id)
			cancel()
			if deleteErr != nil && !errors.Is(deleteErr, clientcontrol.ErrNotFound) {
				result = errors.Join(result, fmt.Errorf("publisher: delete ephemeral public_url: %w", deleteErr))
			}
		}()
	}
	if err := observe(config, Event{Type: EventPublicURLAssigned, PublicURLID: publicURLID, Hostname: publicURL.CanonicalHostname}); err != nil {
		return err
	}
	for {
		setup, err := createPublishRun(ctx, config, publicURL)
		if err != nil {
			return err
		}
		err = runPublishRun(ctx, config, setup, func() error {
			publicAddress := "https://" + setup.PublicUrl.CanonicalHostname
			return observe(config, Event{
				Type: EventReady, PublicURLID: publicURLID, Hostname: setup.PublicUrl.CanonicalHostname,
				PublicURL: publicAddress, PublishRunNumber: uint64(setup.PublishRun.PublishRunNumber),
			})
		})
		if ctx.Err() != nil {
			return err
		}
		if !errors.Is(err, clientcontrol.ErrStatusConflict) {
			return err
		}
		publicURL.NextPublishRunNumber = setup.PublishRun.PublishRunNumber + 1
	}
}
