package grouppublisher

import (
	"context"

	"github.com/tnldotdev/tnl/internal/privatepublisher"
	"github.com/tnldotdev/tnl/internal/targetdiscovery"
)

// PrepareCloudAssignment is the publisher-side assignment adapter. the caller
// projects only the assigned descriptor into Request; it never evaluates local
// config, performs discovery during apply, or supplies backend credentials.
func PrepareCloudAssignment(ctx context.Context, resolver *targetdiscovery.Resolver, request targetdiscovery.Request, run privatepublisher.RunConfig) (privatepublisher.RunConfig, error) {
	if resolver == nil || string(run.Metadata.Protocol) != request.Protocol || run.Metadata.TargetTls != nil {
		return privatepublisher.RunConfig{}, ErrAssignment
	}
	prepared, err := resolver.Prepare(ctx, request)
	if err != nil {
		return privatepublisher.RunConfig{}, err
	}
	address, _, err := prepared.ResolveTarget(ctx)
	if err != nil {
		return privatepublisher.RunConfig{}, err
	}
	run.Target, run.TargetResolver = address, prepared
	// the normal private publisher health path checks both discovery freshness
	// and protocol-aware verified target TLS for this preparation.
	run.Healthy = nil
	return run, nil
}

func PublishCloudAssignment(ctx context.Context, resolver *targetdiscovery.Resolver, request targetdiscovery.Request, run privatepublisher.RunConfig) error {
	prepared, err := PrepareCloudAssignment(ctx, resolver, request, run)
	if err != nil {
		return err
	}
	return privatepublisher.Publish(ctx, prepared)
}
