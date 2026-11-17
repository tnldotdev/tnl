package invocation

import (
	"context"
	"errors"
	"net"
	"net/http"
	"slices"
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
	telemetryv1 "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
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
	traffic, err := config.ResolveTrafficSelection(effective.Traffic)
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
	if saved.Protocol == controlv1.ServiceProtocolHTTP {
		binding.Changed = func() { a.manager.TargetChanged(service.Name, service.RegistrationID, service.Target) }
	}
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
	publication := &publisherapp.ServicePublication{Options: clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, ServiceID: saved.Id,
		Server: auth.ServerEndpoint, Project: project.Root, Target: service.Target, Service: service.Name, ServiceProtocol: saved.Protocol}, Check: readiness.check, URL: readiness.publicURL}
	framework := telemetryv1.PublicationReadyFramework(service.Framework)
	if !framework.Valid() {
		framework = ""
	}
	base := publisherservice.RunConfig{Telemetry: a.Telemetry, Framework: framework, Control: native, State: profile, Access: native.Access,
		PublisherIdentityID: identity.ClientId, PublisherGrantID: identity.GrantId, PublisherKeyID: identity.KeyId,
		ServiceID: saved.Id, Target: plan.Target, Metadata: publisheridentity.ServiceMetadata(saved), InspectionMode: policy.Mode,
		ProjectRoot: project.Root, ProjectService: service.Name}
	base.ShutdownDeadline = func() time.Time { return a.manager.PublicationShutdownDeadline(service.RegistrationID) }
	base.ShutdownContext = a.manager.PublicationShutdownContext(service.RegistrationID)
	if saved.Protocol == controlv1.ServiceProtocolHTTP {
		base.ResolveHTTPTarget = func(request *http.Request) (string, string, error) {
			selected, err := readiness.captureHTTP(request.Context())
			return selected.Address, selected.Identity, err
		}
		base.Mounts, err = ProjectMounts(ctx, project.Project, service.Name, func(name string) string {
			for _, candidate := range a.manager.Snapshot().Services {
				if candidate.Name == name && a.manager.CurrentRegistration(name, candidate.RegistrationID, candidate.Target) {
					return candidate.Target
				}
			}
			return ""
		}, a.TargetResolver)
		if err != nil {
			return publisherapp.Configuration{}, err
		}
		preview, err := ensurePreview(ctx, a.state, profile, auth.Control, auth.ServerEndpoint, saved.TeamId, project.Root)
		if err != nil {
			return publisherapp.Configuration{}, err
		}
		included, err := auth.Control.AddPreviewService(ctx, preview, saved.Id)
		if err != nil {
			return publisherapp.Configuration{}, err
		}
		if included.Id != preview || included.TeamId != saved.TeamId || !slices.Contains(included.ServiceIds, saved.Id) {
			return publisherapp.Configuration{}, failure.Wrap("associate preview", failure.ServerResponseInvalid, errors.New("preview omitted the selected service"))
		}
		base.PreviewID, base.Feedback = preview, effective.Feedback != nil && *effective.Feedback
	}
	publication.Run = func(ctx context.Context, tunnel *clientstate.Tunnel, observe func(uint64, bool) error, summary inspection.Observer) error {
		base.ObserveSummary = summary
		address, closeTarget, err := targetplan.ServiceTarget(ctx, plan)
		if err != nil {
			return err
		}
		defer closeTarget()
		base.Target = address
		base.AdmitRequest = func(r *http.Request) error {
			current := readiness.load()
			if ctx.Err() != nil || !a.manager.CurrentRun(service.Name, service.RegistrationID, service.Target, current.run.Number) {
				return publisherapp.ErrRegistrationStale
			}
			if saved.Protocol != controlv1.ServiceProtocolHTTP && (readiness.load() != current || !binding.Current(r.Context(), current.target)) {
				return publisherapp.ErrRegistrationStale
			}
			return nil
		}
		if saved.Protocol == controlv1.ServiceProtocolHTTP {
			stop, err := attachRuntimeIntegrations(ctx, a.state, project.Project, service, tunnel, &base)
			if err != nil {
				return err
			}
			if stop != nil {
				defer stop()
			}
		}
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
			runCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			var prepared *serviceRunBinding
			var notified bool
			var observationError error
			cfg := base
			cfg.Prepared = func(preparation controlv1.ServiceRunPreparation) error {
				prepared = readiness.prepare(pending, preparation)
				notified = false
				return observe(uint64(preparation.RunNumber), false)
			}
			cfg.ReadinessProof = readinessProof
			cfg.Healthy = func(probe context.Context) bool {
				current := service
				current.RunNumber = readiness.load().run.Number
				observation := readiness.localCheck(probe, current)
				if readiness.publicURL == "" {
					a.manager.Observe(observation)
				}
				return observation.Ready
			}
			cfg.Ready = func() error {
				if prepared == nil {
					return publisherapp.ErrRegistrationStale
				}
				if err := observe(prepared.run.Number, true); err != nil {
					return err
				}
				notified = true
				return nil
			}
			cfg.ObserveReadiness = func(status publisherservice.RunStatus) {
				// the runtime reports status before its first Ready callback.
				// only that callback announces initial publication; later status
				// changes use the manager's current availability, not a copy.
				if !notified || runCtx.Err() != nil || observationError != nil {
					return
				}
				if err := a.observeServiceReadiness(service, prepared.run, status, observe); err != nil {
					observationError = err
					cancel()
				}
			}
			if a.AttachPublication != nil {
				if err := a.AttachPublication(runCtx, service, &cfg); err != nil {
					return err
				}
			}
			err := targetplan.PublishPrivate(runCtx, plan, cfg, targetplan.TargetHooks{Resolver: a.TargetResolver, Capture: capture})
			return errors.Join(err, observationError)
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

func (a *ProjectRuntime) observeServiceReadiness(service publisherapp.Service, run httpaccess.ReadinessRun, status publisherservice.RunStatus, observe func(uint64, bool) error) error {
	current, ok := a.manager.ServiceForRun(service.Name, service.RegistrationID, service.Target, run.Number)
	if !ok {
		return publisherapp.ErrRegistrationStale
	}
	if current.Routable == status.Ready {
		return nil
	}
	return observe(run.Number, status.Ready)
}

type serviceRunBinding struct {
	target targetplan.TargetSnapshot
	run    httpaccess.ReadinessRun
	proof  *httpaccess.ReadinessProof
}

// preparation replaces the entire binding, including its proof. public probes
// serialize renewal through consumption without holding the binding mutex.
// runtime callbacks borrow that same binding's immutable run facts rather than
// following a later preparation or keeping another run counter.
type serviceRunReadiness struct {
	binding   *targetplan.TargetBinding
	transport targettransport.Transport
	path      string
	publicURL string
	mu        sync.Mutex
	probeMu   sync.Mutex
	current   *serviceRunBinding
}

func (r *serviceRunReadiness) load() serviceRunBinding {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current == nil {
		return serviceRunBinding{}
	}
	return *r.current
}

// HTTP target replacement invalidates observations, not the current run or
// requests already using an earlier target. the exact run proof remains shared.
func (r *serviceRunReadiness) captureHTTP(ctx context.Context) (targetplan.TargetSnapshot, error) {
	selected, err := r.binding.Capture(ctx)
	if err != nil {
		return targetplan.TargetSnapshot{}, err
	}
	r.mu.Lock()
	if r.current != nil {
		r.current.target = selected
	}
	r.mu.Unlock()
	return selected, nil
}

func (r *serviceRunReadiness) prepare(target targetplan.TargetSnapshot, preparation controlv1.ServiceRunPreparation) *serviceRunBinding {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.current = &serviceRunBinding{target: target, run: httpaccess.ReadinessRun{
		Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: preparation.ServiceId},
		ID:      preparation.ServiceRunId, Number: uint64(preparation.RunNumber), Hostname: preparation.Hostname,
	}}
	return r.current
}

func (r *serviceRunReadiness) proof(run httpaccess.ReadinessRun) *httpaccess.ReadinessProof {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current == nil || r.current.run != run {
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
	if r.transport.Protocol == config.ProtocolHTTP {
		if _, err := r.captureHTTP(ctx); err != nil {
			return publisherapp.Observation{Target: service.Target, RegistrationID: service.RegistrationID, RunNumber: service.RunNumber,
				Readiness: service.Readiness, CheckedAt: time.Now().UTC(), Reason: "runtime.target_changed"}
		}
	}
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
	if _, err := r.captureHTTP(ctx); err != nil {
		return publisherapp.Observation{Target: service.Target, RegistrationID: service.RegistrationID, RunNumber: service.RunNumber,
			Readiness: service.Readiness, CheckedAt: time.Now().UTC(), Reason: "runtime.target_changed"}
	}
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
