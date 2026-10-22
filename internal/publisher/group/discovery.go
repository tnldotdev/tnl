package group

import (
	"context"

	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	publisherdiscovery "github.com/tnldotdev/tnl/internal/publisher/target/discovery"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// AssignmentDiscovery projects only the control-owned descriptor. there is no
// local configuration lookup or fallback to an address/static trust setting.
func AssignmentDiscovery(configuration controlv1.ProjectServiceConfiguration) (publisherdiscovery.Request, error) {
	descriptor := configuration.TargetDiscovery
	if descriptor == nil || configuration.Protocol == nil || !configuration.Protocol.Valid() || !descriptor.Type.Valid() || configuration.Target != "" || configuration.TargetTls != nil || configuration.PublisherGroup == nil || *configuration.PublisherGroup == "" || *configuration.PublisherGroup == "local" || configuration.PublicUrl != nil || configuration.Http != nil {
		return publisherdiscovery.Request{}, ErrAssignment
	}
	if descriptor.Cluster != nil && *descriptor.Cluster == "" || descriptor.Instance != nil && *descriptor.Instance == "" {
		return publisherdiscovery.Request{}, ErrAssignment
	}
	request := publisherdiscovery.Request{Type: string(descriptor.Type), Region: descriptor.Region, Protocol: string(*configuration.Protocol)}
	if descriptor.Cluster != nil {
		request.Cluster = *descriptor.Cluster
	}
	if descriptor.Instance != nil {
		request.Instance = *descriptor.Instance
	}
	if descriptor.Endpoint != nil {
		if !descriptor.Endpoint.Valid() {
			return publisherdiscovery.Request{}, ErrAssignment
		}
		request.Endpoint = string(*descriptor.Endpoint)
	}
	return request.Normalize()
}

// PrepareCloudAssignment is the publisher-side assignment adapter. the caller
// projects only the assigned descriptor into Request; it never evaluates local
// config, performs discovery during apply, or supplies backend credentials.
func PrepareCloudAssignment(ctx context.Context, resolver *publisherdiscovery.Resolver, request publisherdiscovery.Request, run publisherservice.RunConfig) (publisherservice.RunConfig, error) {
	if resolver == nil || string(run.Metadata.Protocol) != request.Protocol || run.Metadata.TargetTls != nil {
		return publisherservice.RunConfig{}, ErrAssignment
	}
	prepared, err := resolver.Prepare(ctx, request)
	if err != nil {
		return publisherservice.RunConfig{}, err
	}
	address, _, err := prepared.ResolveTarget(ctx)
	if err != nil {
		return publisherservice.RunConfig{}, err
	}
	run.Target, run.TargetResolver = address, prepared
	// the normal private publisher health path checks both discovery freshness
	// and protocol-aware verified target TLS for this preparation.
	run.Healthy = nil
	return run, nil
}

func PublishCloudAssignment(ctx context.Context, resolver *publisherdiscovery.Resolver, request publisherdiscovery.Request, run publisherservice.RunConfig) error {
	prepared, err := PrepareCloudAssignment(ctx, resolver, request, run)
	if err != nil {
		return err
	}
	return publisherservice.Publish(ctx, prepared)
}
