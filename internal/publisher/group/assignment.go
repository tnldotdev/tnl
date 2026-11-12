package group

import (
	"context"
	"crypto/ed25519"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	targetplan "github.com/tnldotdev/tnl/internal/publisher/target"
	publisherdiscovery "github.com/tnldotdev/tnl/internal/publisher/target/discovery"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// AssignmentPublisher publishes an authenticated group service assignment using
// its exact grant, target, and trust revision. the surrounding group runtime owns
// cancellation and joins; its shared discovery resolver outlives every worker.
// installed jobs and foreground callers compose this operation without giving it
// a registry or transferring their process lifetime to it.
type AssignmentPublisher struct {
	Member    controlv1.PublisherGroupMember
	Private   ed25519.PrivateKey
	State     *clientstate.Store
	Control   publisheridentity.NativeControl
	Authority publisheridentity.AssertionExchanger
	Discovery *publisherdiscovery.Resolver
}

func (AssignmentPublisher) String() string   { return "publisher group publications" }
func (AssignmentPublisher) GoString() string { return "publisher group publications" }

func (p AssignmentPublisher) Publish(ctx context.Context, assignment controlv1.PublisherGroupServiceAssignment, health func(bool)) error {
	if assignment.ServiceKind != "service" || assignment.Configuration.Protocol == nil || assignment.TrustRevision < 1 || assignment.Configuration.PublisherGroup == nil || *assignment.Configuration.PublisherGroup == "" || *assignment.Configuration.PublisherGroup == "local" {
		return ErrAssignment
	}
	identity := authorityv1.PublisherEnrollmentResult{ClientId: p.Member.PublisherIdentityId, KeyId: p.Member.KeyId, TeamId: p.Member.TeamId, GrantId: assignment.GrantId, Kind: authorityv1.Service, ServiceId: &assignment.ServiceId}
	native, err := publisheridentity.NewNative(p.Control, p.Authority, identity, p.Private)
	if err != nil {
		return err
	}
	service, err := native.SavedService(ctx)
	if err != nil {
		return err
	}
	if service.Id != assignment.ServiceId || service.TrustRevision != assignment.TrustRevision || service.Protocol != *assignment.Configuration.Protocol {
		return ErrAssignment
	}
	run := publisherservice.RunConfig{Control: native, State: p.State, Access: native.Access, Identity: identity, ServiceID: service.Id, Metadata: publisheridentity.ServiceMetadata(service), ObserveReadiness: func(status publisherservice.RunStatus) {
		if health != nil {
			health(status.Ready)
		}
	}}
	if assignment.Configuration.TargetDiscovery != nil {
		// service carries approved protocol/trust revision, not a second
		// selector. the exact authenticated assignment owns the cloud descriptor.
		if service.TargetTls != nil {
			return ErrAssignment
		}
		request, err := AssignmentDiscovery(assignment.Configuration)
		if err != nil {
			return err
		}
		return PublishCloudAssignment(ctx, p.Discovery, request, run)
	}
	plan := targetplan.TargetPlan{Protocol: config.ProtocolName(service.Protocol), Target: assignment.Configuration.Target}
	if trust := assignment.Configuration.TargetTls; trust != nil {
		snapshot := targettrust.Declaration{Hostname: trust.Hostname, Digest: trust.Digest}
		if trust.CaPem != nil {
			snapshot.CAPEM = []byte(*trust.CaPem)
		}
		plan.Trust, err = snapshot.Snapshot()
		if err != nil {
			return err
		}
	}
	if err := publisheridentity.MatchServiceDeclaration(service, string(plan.Protocol), plan.Trust); err != nil {
		return err
	}
	run.Target = plan.Target
	return targetplan.PublishPrivate(ctx, plan, run)
}
