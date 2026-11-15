package invocation

import (
	"context"
	"slices"

	"github.com/tnldotdev/tnl/internal/observability/inspection"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func nativeIntegrationConfig(ctx context.Context, services publisherServices, hostname string, allowed []string) (publisherservice.RunConfig, controlv1.Service, error) {
	services.hostname = hostname
	access := &controlv1.ProjectHTTPAccess{Mode: new(controlv1.Anonymous)}
	if len(allowed) != 0 {
		prefixes := slices.Clone(allowed)
		access.Ip = &prefixes
	}
	declaration := controlv1.ProjectServiceConfiguration{Target: "app",
		Http: &controlv1.ProjectServiceHTTP{Access: access,
			Limits: &controlv1.ProjectHTTPApplicationLimits{Concurrency: new(32)}}}
	native, saved, err := selectNativeProjectPublisher(ctx, services, declaration)
	if err != nil {
		return publisherservice.RunConfig{}, controlv1.Service{}, err
	}
	return publisherservice.RunConfig{Control: native, State: services.state, Access: native.Access,
		PublisherIdentityID: native.PublisherIdentityID(), PublisherGrantID: native.PublisherGrantID(), PublisherKeyID: native.PublisherKeyID(),
		ServiceID: saved.Id, Metadata: publisheridentity.ServiceMetadata(saved), InspectionMode: inspection.None}, saved, nil
}
