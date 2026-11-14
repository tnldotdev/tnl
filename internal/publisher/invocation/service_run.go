package invocation

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	targetplan "github.com/tnldotdev/tnl/internal/publisher/target"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (a *ProjectRuntime) ServiceConfiguration(ctx context.Context, service publisherapp.Service) (publisherapp.Configuration, error) {
	project := a.project
	effective, err := project.EffectiveService(service.Name)
	if err != nil {
		return publisherapp.Configuration{}, err
	}
	resolver := resolve.NewMetadataResolver(a.state, project.Project, authenticateRuntime)
	auth, selectedTeam, err := resolver.Context(ctx, effective)
	if err != nil {
		return publisherapp.Configuration{}, err
	}
	current := FromTeamContext(selectedTeam)
	profile, err := a.state.Server(ctx, auth.ServerEndpoint)
	if err != nil {
		return publisherapp.Configuration{}, err
	}
	definition := project.Config.Services[service.Name]
	binding := targetplan.RuntimeTargetBinding(project.Project, service.Name, service.Target, nil, a.TargetResolver)
	target, err := binding.Capture(ctx)
	if err != nil {
		return publisherapp.Configuration{}, err
	}
	trust, err := project.CaptureServiceTrust(ctx, service.Name, target.Address)
	if err != nil {
		return publisherapp.Configuration{}, err
	}
	plan := targetplan.TargetPlan{Protocol: config.ProtocolName(config.Protocol(definition)), Target: target.Address, Trust: trust}
	if err := targetplan.PreflightPrivate(ctx, plan); err != nil {
		return publisherapp.Configuration{}, err
	}
	realized, err := RealizeLocalService(ctx, auth.Control, LocalService{Project: project.Project, Team: current, Name: service.Name, TargetResolver: a.TargetResolver})
	if err != nil {
		return publisherapp.Configuration{}, err
	}
	saved, err := auth.Control.GetService(ctx, realized.ServiceId)
	if err != nil {
		return publisherapp.Configuration{}, err
	}
	if saved.Id != realized.ServiceId || saved.TeamId != current.team.Id || !saved.Enabled {
		return publisherapp.Configuration{}, publisheridentity.ErrScope
	}
	if err := publisheridentity.MatchServiceDeclaration(saved, config.Protocol(definition), trust); err != nil {
		return publisherapp.Configuration{}, err
	}
	native, identity, err := publisheridentity.EnsureServiceOwner(ctx, profile, auth.Control, auth.Authority, saved)
	if err != nil {
		return publisherapp.Configuration{}, err
	}
	traffic, err := config.ResolveTrafficSelection(effectiveTunnelLimits(effective))
	if err != nil {
		return publisherapp.Configuration{}, err
	}
	native, err = native.WithTraffic(traffic)
	if err != nil {
		return publisherapp.Configuration{}, err
	}
	if config.TargetType(definition) != "app" {
		plan.Project, plan.ProjectService = &project.Project, service.Name
	}
	transport, err := targetplan.PrivateTransport(plan)
	if err != nil {
		return publisherapp.Configuration{}, err
	}
	readiness := &serviceRunReadiness{binding: binding, transport: transport, path: service.Readiness.Path}
	if saved.Protocol == controlv1.ServiceProtocolHTTP && saved.Endpoint != nil && saved.Endpoint.Public {
		readiness.publicURL = "https://" + saved.Endpoint.Hostname
	}
	var readinessProof func(httpaccess.ReadinessRun) *httpaccess.ReadinessProof
	if saved.Protocol == controlv1.ServiceProtocolHTTP {
		readinessProof = readiness.proof
	}
	policy, err := config.ResolveInspection(effective.Inspection, config.Protocol(definition))
	if err != nil {
		return publisherapp.Configuration{}, err
	}
	primary, shared, err := InspectionRoots(ctx, project.Root)
	if err != nil {
		return publisherapp.Configuration{}, err
	}
	publication := &publisherapp.ServicePublication{Options: clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish,
		Server: auth.ServerEndpoint, Project: project.Root, Target: service.Target, Service: service.Name, ServiceProtocol: saved.Protocol}, Check: readiness.check, URL: readiness.publicURL}
	publication.Run = func(ctx context.Context, observe func(uint64, bool) error, summary inspection.Observer) error {
		var pending targetplan.TargetSnapshot
		capture := func(target targetplan.TargetSnapshot) error {
			actual, err := binding.Capture(ctx)
			if err != nil {
				return err
			}
			if target.Address != actual.Address || target.Identity != actual.Identity {
				return publisherapp.ErrRegistrationStale
			}
			pending = actual
			return nil
		}
		publish := func() error {
			return targetplan.PublishPrivate(ctx, plan, publisherservice.RunConfig{Telemetry: a.Telemetry, Control: native, State: profile, Access: native.Access, Identity: identity, ServiceID: saved.Id, Target: plan.Target, Metadata: publisheridentity.ServiceMetadata(saved),
				InspectionMode: policy.Mode, ObserveSummary: summary,
				Prepared: func(preparation controlv1.ServiceRunPreparation) error {
					readiness.prepare(pending, preparation)
					return observe(uint64(preparation.RunNumber), false)
				},
				AdmitRequest: func(r *http.Request) error {
					current := readiness.load()
					if ctx.Err() != nil || !a.manager.CurrentRun(service.Name, service.RegistrationID, service.Target, current.run.Number) {
						return publisherapp.ErrRegistrationStale
					}
					if readiness.load() != current || !binding.Current(r.Context(), current.target) {
						return publisherapp.ErrRegistrationStale
					}
					return nil
				},
				ReadinessProof: readinessProof,
				Healthy: func(probe context.Context) bool {
					current := service
					current.RunNumber = readiness.load().run.Number
					observation := readiness.localCheck(probe, current)
					if readiness.publicURL == "" {
						a.manager.Observe(observation)
					}
					return observation.Ready
				}, Ready: func() error {
					run := readiness.load().run.Number
					if err := observe(run, true); err != nil {
						return err
					}
					current := service
					current.RunNumber = run
					a.manager.Observe(readiness.check(ctx, current))
					return nil
				}}, targetplan.TargetHooks{Resolver: a.TargetResolver, Capture: capture})
		}
		for attempt := 0; ctx.Err() == nil; attempt++ {
			err := publish()
			if ctx.Err() != nil {
				if err == nil || failure.Only(err, context.Canceled) {
					return nil
				}
				return err
			}
			if err == nil || !privateAppRetry(err) {
				return err
			}
			if run := readiness.load().run.Number; run != 0 {
				if err := observe(run, false); err != nil {
					return err
				}
			}
			if reason, _, ok := failure.Describe(err); ok {
				a.manager.RecordWarning(service.Name, service.RegistrationID, string(reason))
			}
			timer := time.NewTimer(publisherapp.RetryDelay(attempt))
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
		}
		return nil
	}
	return publisherapp.Configuration{Service: publication, Inspection: policy, PrimaryRoot: primary, SharedRoot: shared}, nil
}

type serviceRunBinding struct {
	target targetplan.TargetSnapshot
	run    httpaccess.ReadinessRun
	proof  *httpaccess.ReadinessProof
}

// preparation replaces the entire binding, including its proof. public probes
// serialize renewal through consumption without holding the binding mutex.
type serviceRunReadiness struct {
	binding   *targetplan.TargetBinding
	transport targettransport.Transport
	path      string
	publicURL string
	mu        sync.Mutex
	probeMu   sync.Mutex
	current   serviceRunBinding
}

func (r *serviceRunReadiness) load() serviceRunBinding {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.current
}

func (r *serviceRunReadiness) prepare(target targetplan.TargetSnapshot, preparation controlv1.ServiceRunPreparation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.current = serviceRunBinding{target: target, run: httpaccess.ReadinessRun{
		Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: preparation.ServiceId},
		ID:      preparation.ServiceRunId, Number: uint64(preparation.RunNumber), Hostname: preparation.Hostname,
	}}
}

func (r *serviceRunReadiness) proof(run httpaccess.ReadinessRun) *httpaccess.ReadinessProof {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current.run != run {
		return nil
	}
	path := r.path
	if path == "" {
		path = "/"
	}
	proof, err := httpaccess.NewReadinessProof(run, path)
	if err != nil {
		return nil
	}
	r.current.proof = proof
	return proof
}

func (r *serviceRunReadiness) localCheck(ctx context.Context, service publisherapp.Service) publisherapp.Observation {
	current := r.load()
	observation := publisherapp.Observation{Target: service.Target, RegistrationID: service.RegistrationID, RunNumber: service.RunNumber, Readiness: service.Readiness, CheckedAt: time.Now().UTC(), Reason: "runtime.target_changed"}
	if current.run.Number != service.RunNumber || current.target.Address == "" || !r.binding.Current(ctx, current.target) {
		return observation
	}
	local := service
	local.Target = current.target.Address
	observation = publisherapp.ProbeServiceTarget(ctx, local, r.transport)
	observation.Target = service.Target
	latest := r.load()
	if latest.run != current.run || latest.target != current.target || !r.binding.Current(ctx, current.target) {
		observation.Ready, observation.Reason = false, "runtime.target_changed"
	}
	return observation
}

func (r *serviceRunReadiness) check(ctx context.Context, service publisherapp.Service) publisherapp.Observation {
	if r.publicURL == "" {
		return r.localCheck(ctx, service)
	}
	r.probeMu.Lock()
	defer r.probeMu.Unlock()
	current := r.load()
	observation := publisherapp.Observation{Target: service.Target, RegistrationID: service.RegistrationID, RunNumber: service.RunNumber, Readiness: service.Readiness, CheckedAt: time.Now().UTC(), Reason: "runtime.target_changed"}
	if current.run.Number != service.RunNumber || current.proof == nil || current.target.Address == "" || !r.binding.Current(ctx, current.target) {
		return observation
	}
	secret, err := current.proof.Renew()
	if err != nil {
		return observation
	}
	service.PublicURL = r.publicURL
	observation = publisherapp.ProbeWithProof(ctx, service, nil, secret)
	// a successful unrelated responder is not proof that this run served it.
	if r.load() != current || !r.binding.Current(ctx, current.target) || current.proof.HeaderValue() != "" {
		observation.Ready, observation.Reason = false, "runtime.target_changed"
	}
	return observation
}

func privateAppRetry(err error) bool {
	if errors.Is(err, publisheridentity.ErrScope) || errors.Is(err, clientcontrol.ErrUnauthenticated) || errors.Is(err, clientcontrol.ErrNotFound) {
		return false
	}
	if reason, _, ok := failure.Describe(err); ok {
		definition, _ := failure.DefinitionFor(reason)
		return definition.Retry == failure.RetryLater
	}
	var network net.Error
	return errors.Is(err, publisherservice.ErrPrivateStream) || errors.As(err, &network)
}
