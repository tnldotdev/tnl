package publisher

import (
	"context"
	"errors"
	"fmt"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/publisher/placement"
	"github.com/tnldotdev/tnl/internal/region"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const activationRetry = 2 * time.Second

func createPublishRun(ctx context.Context, config Config, publicURL controlv1.PublicURL) (controlv1.PublishRunSetup, error) {
	if _, err := region.Preferences(config.PreferredRegions); err != nil {
		return controlv1.PublishRunSetup{}, err
	}
	idempotencyKey, err := opaqueID(opaqueid.IdempotencyPrefix)
	if err != nil {
		return controlv1.PublishRunSetup{}, err
	}
	preferred := config.PreferredRegions
	if len(preferred) == 0 {
		if reader, ok := config.Control.(placement.CandidateReader); ok {
			preferred = placement.PreferredRegions(ctx, reader, "")
		}
	}
	for {
		var setup controlv1.PublishRunSetup
		if len(preferred) > 0 {
			control, ok := config.Control.(interface {
				CreatePublishRunInRegions(context.Context, string, string, []string) (controlv1.PublishRunSetup, error)
			})
			if !ok {
				return setup, region.ErrPreference
			}
			setup, err = control.CreatePublishRunInRegions(ctx, publicURL.Id, idempotencyKey, preferred)
		} else {
			setup, err = config.Control.CreatePublishRun(ctx, publicURL.Id, idempotencyKey)
		}
		if err == nil {
			return setup, nil
		}
		if !errors.Is(err, clientcontrol.ErrUnavailable) {
			return setup, classifyPublicURLConflict(err)
		}
		select {
		case <-ctx.Done():
			return controlv1.PublishRunSetup{}, context.Cause(ctx)
		case <-time.After(activationRetry):
		}
	}
}

func runPublishRun(ctx context.Context, config Config, setup controlv1.PublishRunSetup, ready func() error) (result error) {
	_, startup := observability.PublisherOperation(ctx, "startup")
	defer func() { startup(result) }()
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		closeErr := config.Control.ClosePublishRun(closeCtx, setup.PublishRun.Id, credentials.PublishRunToken(setup.PublishRunToken))
		if closeErr != nil && !errors.Is(closeErr, clientcontrol.ErrNotFound) && !errors.Is(closeErr, clientcontrol.ErrUnauthenticated) {
			result = errors.Join(result, fmt.Errorf("publisher: close publish run: %w", closeErr))
		}
	}()
	if err := observe(config, Event{
		Type: EventProvisioning, PublicURLID: setup.PublicUrl.Id, Hostname: setup.PublicUrl.CanonicalHostname,
		PublishRunNumber: uint64(setup.PublishRun.PublishRunNumber),
	}); err != nil {
		return err
	}
	return runSession(ctx, config, setup, func() error {
		err := ready()
		startup(err)
		observability.PublisherReadiness(ctx, err == nil)
		return err
	})
}

func confirmPublishRunReady(
	ctx context.Context,
	authority publicRunAuthority,
	route *PublicURLServer,
	ready func() error,
) error {
	for {
		confirmed := false
		err := route.withValidCertificate(func() error {
			if err := authority.markReady(ctx); err != nil {
				return err
			}
			confirmed = true
			return ready()
		})
		if err == nil || confirmed {
			return err
		}
		if !errors.Is(err, clientcontrol.ErrUnavailable) && !errors.Is(err, clientcontrol.ErrStatusConflict) {
			return err
		}
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-time.After(activationRetry):
		}
	}
}
