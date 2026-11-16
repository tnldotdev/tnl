package deployment

import (
	"context"
	"crypto/ed25519"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	targetplan "github.com/tnldotdev/tnl/internal/publisher/target"
	publisherdiscovery "github.com/tnldotdev/tnl/internal/publisher/target/discovery"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// AssignmentPublisher publishes an authenticated deployment service assignment using
// its exact grant, target, and trust revision. the surrounding deployment runtime owns
// cancellation and joins; its shared discovery resolver outlives every worker.
// installed jobs and foreground callers compose this operation without giving it
// a registry or transferring their process lifetime to it.
type AssignmentPublisher struct {
	Telemetry       *clienttelemetry.Collector
	Member          controlv1.DeploymentPublisherIdentity
	Private         ed25519.PrivateKey
	State           *clientstate.Store
	Control         publisheridentity.NativeControl
	Authority       publisheridentity.AssertionExchanger
	Discovery       *publisherdiscovery.Resolver
	ServerDiscovery ServerDiscovery
}

type ServerDiscovery interface {
	Discovery(context.Context) (controlv1.ControlDiscovery, error)
}

func (AssignmentPublisher) String() string   { return "deployment publications" }
func (AssignmentPublisher) GoString() string { return "deployment publications" }

func (p AssignmentPublisher) Publish(ctx context.Context, assignment controlv1.DeploymentPublisherServiceAssignment, health func(bool), deadline func() time.Time) error {
	if assignment.Configuration.Protocol == nil || !assignment.Configuration.Protocol.Valid() || assignment.Configuration.Target == "app" || assignment.TrustRevision < 1 || p.Member.DeploymentId == "" || p.Member.DeploymentName == "" || p.Member.DeploymentName == "local" {
		return ErrAssignment
	}
	var browserLogin *bool
	if *assignment.Configuration.Protocol == controlv1.ServiceProtocolHTTP && assignment.Configuration.Public != nil && *assignment.Configuration.Public {
		if p.ServerDiscovery == nil {
			return ErrAssignment
		}
		server, err := p.ServerDiscovery.Discovery(ctx)
		if err != nil {
			return err
		}
		browserLogin = new(server.BrowserLoginAvailable != nil && *server.BrowserLoginAvailable)
	}
	identity := authorityv1.PublisherEnrollmentResult{ClientId: p.Member.PublisherIdentityId, KeyId: p.Member.KeyId, TeamId: p.Member.TeamId, GrantId: assignment.GrantId, Kind: authorityv1.Service, ServiceId: &assignment.ServiceId}
	native, err := publisheridentity.NewNative(p.Control, p.Authority, identity, p.Private)
	if err != nil {
		return err
	}
	var traffic *trafficlimits.Selection
	if selected := assignment.Configuration.Traffic; selected != nil {
		traffic = &trafficlimits.Selection{
			Connections: selected.Connections, Rate: selected.Rate, RatePer: selected.RatePer, Burst: selected.Burst,
			UploadBytes: selected.UploadBytes, DownloadBytes: selected.DownloadBytes,
			TotalConnections: selected.TotalConnections, TotalUploadBytes: selected.TotalUploadBytes, TotalDownloadBytes: selected.TotalDownloadBytes,
		}
	}
	native, err = native.WithTraffic(traffic)
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
	if health != nil {
		defer health(false)
	}
	run := publisherservice.RunConfig{Telemetry: p.Telemetry, Control: native, State: p.State, Access: native.Access, PublisherIdentityID: identity.ClientId, PublisherGrantID: identity.GrantId, PublisherKeyID: identity.KeyId, ServiceID: service.Id, ShutdownDeadline: deadline, Metadata: publisheridentity.ServiceMetadata(service), BrowserLoginAvailable: browserLogin, ObserveReadiness: func(status publisherservice.RunStatus) {
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
