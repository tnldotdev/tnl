package grouppublisher

import (
	"context"

	"github.com/tnldotdev/tnl/internal/privatepublisher"
	"github.com/tnldotdev/tnl/internal/targetdiscovery"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// AssignmentDiscovery projects only the control-owned descriptor. there is no
// local configuration lookup or fallback to an address/static trust setting.
func AssignmentDiscovery(configuration controlv1.ProjectServiceConfiguration) (targetdiscovery.Request, error) {
	descriptor := configuration.TargetDiscovery
	if descriptor == nil || configuration.Protocol == nil || !configuration.Protocol.Valid() || !descriptor.Type.Valid() || configuration.Target != "" || configuration.TargetTls != nil || configuration.Publisher == nil || *configuration.Publisher == "" || *configuration.Publisher == "local" || configuration.PublicUrl != nil || configuration.Http != nil {
		return targetdiscovery.Request{}, ErrAssignment
	}
	if descriptor.Cluster != nil && *descriptor.Cluster == "" || descriptor.Instance != nil && *descriptor.Instance == "" {
		return targetdiscovery.Request{}, ErrAssignment
	}
	request := targetdiscovery.Request{Type: string(descriptor.Type), Region: descriptor.Region, Protocol: string(*configuration.Protocol)}
	if descriptor.Cluster != nil {
		request.Cluster = *descriptor.Cluster
	}
	if descriptor.Instance != nil {
		request.Instance = *descriptor.Instance
	}
	if descriptor.Endpoint != nil {
		if !descriptor.Endpoint.Valid() {
			return targetdiscovery.Request{}, ErrAssignment
		}
		request.Endpoint = string(*descriptor.Endpoint)
	}
	return request.Normalize()
}

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
