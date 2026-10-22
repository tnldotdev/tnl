package target

import (
	"context"
	"reflect"
	"time"

	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
)

// PublishPrivate resolves captured project discovery settings before each run.
// replacement or disappearance closes that run before a new target can receive
// streams; the next run gets a new TLS key and assignment identities.
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
			return PreflightPrivate(ctx, plan) == nil
		}
	}
	if plan.Project == nil {
		if hook.Capture != nil {
			if err := hook.Capture(TargetSnapshot{Address: plan.Target, Identity: plan.Target}); err != nil {
				return err
			}
		}
		target, close, err := ServiceTarget(ctx, plan)
		if err != nil {
			return err
		}
		defer close()
		config.Target = target
		if err := PreflightPrivate(ctx, plan); err != nil {
			return err
		}
		return publisherservice.Publish(ctx, config)
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
		target, close, err := ServiceTarget(worker, plan)
		if err != nil {
			cancel()
			<-done
			return err
		}
		config.Target = target
		err = PreflightPrivate(worker, plan)
		if err == nil {
			err = publisherservice.Publish(worker, config)
		}
		cancel()
		close()
		<-done
		if ctx.Err() != nil {
			return nil
		}
		select {
		case <-changed:
			continue
		default:
			return err
		}
	}
	return nil
}
