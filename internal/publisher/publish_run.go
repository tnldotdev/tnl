package publisher

import (
	"context"
	"errors"
	"fmt"
	"time"

	controlclient "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/security/credentials"
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

func runPublishRun(ctx context.Context, config Config, setup controlv1.PublishRunSetup, ready func() error) (result error) {
	_, startup := observability.PublisherOperation(ctx, "startup")
	defer func() { startup(result) }()
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
