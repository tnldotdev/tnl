package invocation

import (
	"context"
	"errors"
	"slices"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var errIntegrationIntent = errors.New("saved service requires explicit integration handler and anonymous access configuration")

func nativeIntegrationConfig(ctx context.Context, services publisherServices, hostname string, intent targetsyntax.IntegrationTarget, allowed []string) (publisherservice.RunConfig, controlv1.Service, error) {
	if !intent.Valid() {
		return publisherservice.RunConfig{}, controlv1.Service{}, publisheridentity.ErrScope
	}
	services.hostname = hostname
	access := &controlv1.ProjectHTTPAccess{Mode: new(controlv1.Anonymous)}
	if len(allowed) != 0 {
		prefixes := slices.Clone(allowed)
		access.Ip = &prefixes
	}
	declaration := controlv1.ProjectServiceConfiguration{Target: string(intent),
		Http: &controlv1.ProjectServiceHTTP{Access: access,
			Limits: &controlv1.ProjectHTTPApplicationLimits{Concurrency: new(32)}}}
	native, saved, err := selectNativeProjectPublisher(ctx, services, declaration, func(_ controlv1.Service, current *controlv1.ProjectServiceConfiguration) (*controlv1.ProjectServiceConfiguration, error) {
		if current == nil || current.Target != string(intent) || current.TargetTls != nil || current.TargetDiscovery != nil || current.Http == nil ||
			current.Http.Access == nil || current.Http.Access.Mode == nil || *current.Http.Access.Mode != controlv1.Anonymous {
			return nil, failure.Wrap("prepare integration service", failure.ServerResponseInvalid, errIntegrationIntent)
		}
		return &declaration, nil
	})
	if err != nil {
		return publisherservice.RunConfig{}, controlv1.Service{}, err
	}
	return publisherservice.RunConfig{Control: native, State: services.state, Access: native.Access,
		PublisherIdentityID: native.PublisherIdentityID(), PublisherGrantID: native.PublisherGrantID(), PublisherKeyID: native.PublisherKeyID(),
		ServiceID: saved.Id, Metadata: publisheridentity.ServiceMetadata(saved), InspectionMode: inspection.None}, saved, nil
}
