package invocation

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	controlclient "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	clientruntime "github.com/tnldotdev/tnl/internal/publisher/app"
	nativeauth "github.com/tnldotdev/tnl/internal/publisher/identity"
	privatepublisher "github.com/tnldotdev/tnl/internal/publisher/managed"
	targetplan "github.com/tnldotdev/tnl/internal/publisher/target"
	privatetrust "github.com/tnldotdev/tnl/internal/security/targettrust"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type privateProjectControl struct {
	privatepublisher.RunControl
	number   atomic.Uint64
	prepared func(uint64) error
}

func (c *privateProjectControl) PreparePrivateServiceRun(ctx context.Context, id, key, access string, declaration ...controlv1.PrivateServiceRunDeclaration) (controlv1.PrivateServiceRunPreparation, error) {
	preparation, err := c.RunControl.PreparePrivateServiceRun(ctx, id, key, access, declaration...)
	if err != nil && privateAppRetry(err) && ctx.Err() == nil {
		// a lost response must retry the same idempotency key before another
		// run is considered. this does not issue a second task key or grant.
		preparation, err = c.RunControl.PreparePrivateServiceRun(ctx, id, key, access, declaration...)
	}
	if err == nil && preparation.RunNumber > 0 {
		c.number.Store(uint64(preparation.RunNumber))
		if c.prepared != nil {
			err = c.prepared(uint64(preparation.RunNumber))
		}
	}
	return preparation, err
}

func (a *ProjectRuntime) PrivateConfiguration(ctx context.Context, service clientruntime.Service) (clientruntime.Configuration, error) {
	project := a.project
	effective, err := project.EffectiveService(service.Name)
	if err != nil {
		return clientruntime.Configuration{}, err
	}
	resolver := resolve.NewMetadataResolver(a.state, project.Project, authenticateRuntime)
	auth, selectedTeam, err := resolver.Context(ctx, effective)
	if err != nil {
		return clientruntime.Configuration{}, err
	}
	current := FromTeamContext(selectedTeam)
	profile, err := a.state.Server(ctx, auth.ServerEndpoint)
	if err != nil {
		return clientruntime.Configuration{}, err
	}
	definition := project.Config.Services[service.Name]
	binding := targetplan.RuntimeTargetBinding(project.Project, service.Name, service.Target, nil, a.TargetResolver)
	target, err := binding.Capture(ctx)
	if err != nil {
		return clientruntime.Configuration{}, err
	}
	trust, err := project.CaptureServiceTrust(ctx, privatetrust.NewCache(nil), service.Name, target.Address)
	if err != nil {
		return clientruntime.Configuration{}, err
	}
	plan := targetplan.PrivateTargetPlan{Protocol: config.ProtocolName(config.Protocol(definition)), Target: target.Address, Trust: trust}
	if err := targetplan.PreflightPrivate(ctx, plan); err != nil {
		return clientruntime.Configuration{}, err
	}
	realized, err := RealizeLocalService(ctx, auth.Control, LocalService{Project: project.Project, Team: current, Name: service.Name, TargetResolver: a.TargetResolver})
	if err != nil {
		return clientruntime.Configuration{}, err
	}
	saved, err := auth.Control.GetPrivateService(ctx, realized.ServiceId)
	if err != nil {
		return clientruntime.Configuration{}, err
	}
	if saved.Id != realized.ServiceId || saved.TeamId != current.team.Id || !saved.Enabled {
		return clientruntime.Configuration{}, nativeauth.ErrScope
	}
	if err := nativeauth.MatchPrivateServiceDeclaration(saved, config.Protocol(definition), trust); err != nil {
		return clientruntime.Configuration{}, err
	}
	native, identity, err := nativeauth.EnsurePrivateServiceOwner(ctx, profile, auth.Control, auth.Authority, saved)
	if err != nil {
		return clientruntime.Configuration{}, err
	}
	if config.TargetType(definition) != "app" {
		plan.Project, plan.ProjectService = &project.Project, service.Name
	}
	transport, err := targetplan.PrivateTransport(plan)
	if err != nil {
		return clientruntime.Configuration{}, err
	}
	var pinMu sync.Mutex
	var pending, pin targetplan.TargetSnapshot
	var pinRun uint64
	check := func(ctx context.Context, current clientruntime.Service) clientruntime.Observation {
		pinMu.Lock()
		captured, run := pin, pinRun
		pinMu.Unlock()
		observation := clientruntime.Observation{Target: current.Target, RegistrationID: current.RegistrationID, PublishRunNumber: current.PublishRunNumber, Readiness: current.Readiness, CheckedAt: time.Now().UTC(), Reason: "runtime.target_changed"}
		if run != current.PublishRunNumber || captured.Address == "" || !binding.Current(ctx, captured) {
			return observation
		}
		local := current
		local.Target = captured.Address
		observation = clientruntime.ProbePrivateTarget(ctx, local, transport)
		observation.Target = current.Target
		if !binding.Current(ctx, captured) {
			observation.Ready, observation.Reason = false, "runtime.target_changed"
		}
		return observation
	}
	return clientruntime.Configuration{CheckPrivate: check, RunPrivate: func(ctx context.Context, observe func(uint64, bool) error) error {
		control := &privateProjectControl{RunControl: native.ManagedRunControl()}
		control.prepared = func(run uint64) error {
			pinMu.Lock()
			pin, pinRun = pending, run
			pinMu.Unlock()
			return observe(run, false)
		}
		capture := func(target targetplan.TargetSnapshot) error {
			actual, err := binding.Capture(ctx)
			if err != nil {
				return err
			}
			if target.Address != actual.Address || target.Identity != actual.Identity {
				return clientruntime.ErrRegistrationStale
			}
			pinMu.Lock()
			pending = actual
			pinMu.Unlock()
			return nil
		}
		publish := func() error {
			return targetplan.PublishPrivate(ctx, plan, privatepublisher.RunConfig{Control: control, State: profile, Access: native.Access, Identity: identity, PrivateServiceID: saved.Id, Target: plan.Target, Metadata: nativeauth.PrivateServiceMetadata(saved),
				Healthy: func(probe context.Context) bool {
					current := service
					current.PublishRunNumber = control.number.Load()
					observation := check(probe, current)
					a.manager.Observe(observation)
					return observation.Ready
				}, Ready: func() error {
					run := control.number.Load()
					if err := observe(run, true); err != nil {
						return err
					}
					current := service
					current.PublishRunNumber = run
					a.manager.Observe(check(ctx, current))
					return nil
				}}, targetplan.PrivateTargetHooks{Resolver: a.TargetResolver, Capture: capture})
		}
		for attempt := 0; ctx.Err() == nil; attempt++ {
			err := publish()
			if ctx.Err() != nil {
				return nil
			}
			if err == nil || !privateAppRetry(err) {
				return err
			}
			if run := control.number.Load(); run != 0 {
				if err := observe(run, false); err != nil {
					return err
				}
			}
			if reason, _, ok := failure.Describe(err); ok {
				a.manager.RecordWarning(service.Name, service.RegistrationID, string(reason))
			}
			timer := time.NewTimer(clientruntime.RetryDelay(attempt))
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
		}
		return nil
	}}, nil
}

func privateAppRetry(err error) bool {
	if errors.Is(err, nativeauth.ErrScope) || errors.Is(err, controlclient.ErrUnauthenticated) || errors.Is(err, controlclient.ErrNotFound) {
		return false
	}
	if reason, _, ok := failure.Describe(err); ok {
		definition, _ := failure.DefinitionFor(reason)
		return definition.Retry == failure.RetryLater
	}
	var network net.Error
	return errors.Is(err, privatepublisher.ErrPrivateStream) || errors.As(err, &network)
}
