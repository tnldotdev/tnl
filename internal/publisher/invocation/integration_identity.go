package invocation

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var errIntegrationIntent = errors.New("saved service requires explicit integration handler and anonymous access configuration")

// integration shutdown carries the enclosing owner's bound, independently of
// an individual run attempt. routine retries must not start that terminal fence.
type integrationShutdown struct {
	deadline func() time.Time
	fence    context.Context
}

func (s integrationShutdown) bind(ctx context.Context, cfg *publisherservice.RunConfig) {
	cfg.ShutdownContext = s.fence
	_, bounded := ctx.Deadline()
	if s.deadline == nil && !bounded {
		return
	}
	cfg.ShutdownDeadline = func() time.Time {
		var until time.Time
		if ctx.Err() != nil && s.deadline != nil {
			until = s.deadline()
		}
		if parent, ok := ctx.Deadline(); ok && (until.IsZero() || parent.Before(until)) {
			until = parent
		}
		return until
	}
}

func nativeIntegrationConfig(ctx context.Context, services publisherServices, hostname string, intent targetsyntax.IntegrationTarget, allowed []string, shutdown integrationShutdown) (publisherservice.RunConfig, controlv1.Service, error) {
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
	cfg := publisherservice.RunConfig{Control: native, State: services.state, Access: native.Access,
		PublisherIdentityID: native.PublisherIdentityID(), PublisherGrantID: native.PublisherGrantID(), PublisherKeyID: native.PublisherKeyID(),
		ServiceID: saved.Id, Metadata: publisheridentity.ServiceMetadata(saved), InspectionMode: inspection.None}
	shutdown.bind(ctx, &cfg)
	return cfg, saved, nil
}
