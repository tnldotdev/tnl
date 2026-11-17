package target

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"time"

	serviceconfig "github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
)

// PublishPrivate resolves captured project discovery settings before each run.
// native target replacement closes that run before accepting another stream.
// HTTP captures targets per request; in-flight requests retain their selection.
type TargetHooks struct {
	Resolver TargetResolver
	Capture  func(TargetSnapshot) error
}

func PublishPrivate(ctx context.Context, plan TargetPlan, config publisherservice.RunConfig, hooks ...TargetHooks) error {
	if len(hooks) > 1 || !plan.Protocol.Valid() || string(config.Metadata.Protocol) != string(plan.Protocol) {
		return ErrScope
	}
	if err := plan.Normalize(); err != nil {
		return err
	}
	if !reflect.DeepEqual(config.Metadata.TargetTls, publisheridentity.ServiceTargetTLS(plan.Trust)) {
		return ErrScope
	}
	var hook TargetHooks
	if len(hooks) == 1 {
		hook = hooks[0]
	}
	if hook.Resolver == nil {
		hook.Resolver = Resolver{}
	}
	if config.Healthy == nil {
		config.Healthy = func(ctx context.Context) bool {
			current := plan
			if plan.Project != nil && plan.Protocol == serviceconfig.ProtocolHTTP {
				selected, err := ResolveTargetSnapshot(ctx, *plan.Project, plan.ProjectService, hook.Resolver)
				if err != nil {
					return false
				}
				current.Target = selected.Address
			}
			return PreflightPrivate(ctx, current) == nil
		}
	}
	publish := func(ctx context.Context, plan TargetPlan, deadline func() time.Time) error {
		target, close, err := ServiceTarget(ctx, plan)
		if err != nil {
			return err
		}
		defer close()
		run := config
		run.Target, run.ShutdownDeadline = target, deadline
		if err := PreflightPrivate(ctx, plan); err != nil {
			return err
		}
		return publisherservice.Publish(ctx, run)
	}
	if plan.Project == nil {
		if hook.Capture != nil {
			if err := hook.Capture(TargetSnapshot{Address: plan.Target, Identity: plan.Target}); err != nil {
				return err
			}
		}
		return publish(ctx, plan, config.ShutdownDeadline)
	}
	if plan.Protocol == serviceconfig.ProtocolHTTP {
		initial, err := ResolveTargetSnapshot(ctx, *plan.Project, plan.ProjectService, hook.Resolver)
		if err != nil {
			return err
		}
		if hook.Capture != nil {
			if err := hook.Capture(initial); err != nil {
				return err
			}
		}
		if config.ResolveHTTPTarget == nil {
			config.ResolveHTTPTarget = func(request *http.Request) (string, string, error) {
				selected, err := ResolveTargetSnapshot(request.Context(), *plan.Project, plan.ProjectService, hook.Resolver)
				return selected.Address, selected.Identity, err
			}
		}
		plan.Target = initial.Address
		return publish(ctx, plan, config.ShutdownDeadline)
	}
	for ctx.Err() == nil {
		initial, err := ResolveTargetSnapshot(ctx, *plan.Project, plan.ProjectService, hook.Resolver)
		if err != nil {
			return err
		}
		if hook.Capture != nil {
			if err := hook.Capture(initial); err != nil {
				return err
			}
		}
		worker, cancel := context.WithCancel(ctx)
		changed := make(chan struct{})
		done := make(chan struct{})
		go func() {
			defer close(done)
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-worker.Done():
					return
				case <-ticker.C:
					next, err := ResolveTargetSnapshot(worker, *plan.Project, plan.ProjectService, hook.Resolver)
					if err != nil || next.Address != initial.Address || next.Identity != initial.Identity {
						close(changed)
						cancel()
						return
					}
				}
			}
		}()
		plan.Target = initial.Address
		err = publish(worker, plan, targetRunShutdownDeadline(ctx, changed, config.ShutdownDeadline))
		cancel()
		<-done
		if ctx.Err() != nil {
			if context.Cause(ctx) == context.Canceled && (err == nil || failure.Only(err, context.Canceled)) {
				return nil
			}
			return errors.Join(err, context.Cause(ctx))
		}
		select {
		case <-changed:
			if err != nil && !failure.Only(err, context.Canceled) {
				return err
			}
			continue
		default:
			return err
		}
	}
	return nil
}

// target replacement retires one run, not its still-serving process. only a
// final stop consumes the composing operation's shared cleanup budget.
func targetRunShutdownDeadline(parent context.Context, changed <-chan struct{}, deadline func() time.Time) func() time.Time {
	if deadline == nil {
		return nil
	}
	return func() time.Time {
		if parent.Err() == nil {
			select {
			case <-changed:
				return time.Time{}
			default:
			}
		}
		return deadline()
	}
}
