package publisherjob

import (
	"context"
	"reflect"
	"time"

	"github.com/tnldotdev/tnl/internal/privatepublisher"
	"github.com/tnldotdev/tnl/internal/projectpublisher"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/internal/publishertarget"
)

// PublishPrivate resolves captured project discovery settings before each run.
// replacement or disappearance closes that run before a new target can receive
// streams; the next run gets a new TLS key and assignment identities.
type PrivateTargetHooks struct {
	Resolver projectpublisher.TargetResolver
	Capture  func(projectpublisher.TargetSnapshot) error
}

func PublishPrivate(ctx context.Context, job Job, config privatepublisher.RunConfig, hooks ...PrivateTargetHooks) error {
	if len(hooks) > 1 || job.Kind != KindPrivateService || !job.Protocol.Valid() || string(config.Metadata.Protocol) != string(job.Protocol) {
		return ErrScope
	}
	if err := validateTarget(&job); err != nil {
		return err
	}
	if !reflect.DeepEqual(config.Metadata.TargetTls, nativeauth.PrivateServiceTLS(job.Trust)) {
		return ErrScope
	}
	var hook PrivateTargetHooks
	if len(hooks) == 1 {
		hook = hooks[0]
	}
	if hook.Resolver == nil {
		hook.Resolver = publishertarget.Resolver{}
	}
	if config.Healthy == nil {
		config.Healthy = func(ctx context.Context) bool {
			return PreflightPrivate(ctx, job) == nil
		}
	}
	if job.Project == nil {
		if hook.Capture != nil {
			if err := hook.Capture(projectpublisher.TargetSnapshot{Address: job.Target, Identity: job.Target}); err != nil {
				return err
			}
		}
		target, close, err := PrivateTarget(ctx, job)
		if err != nil {
			return err
		}
		defer close()
		config.Target = target
		if err := PreflightPrivate(ctx, job); err != nil {
			return err
		}
		return privatepublisher.Publish(ctx, config)
	}
	for ctx.Err() == nil {
		initial, err := projectpublisher.ResolveTargetSnapshot(ctx, *job.Project, job.ProjectService, hook.Resolver)
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
					next, err := projectpublisher.ResolveTargetSnapshot(worker, *job.Project, job.ProjectService, hook.Resolver)
					if err != nil || next.Address != initial.Address || next.Identity != initial.Identity {
						close(changed)
						cancel()
						return
					}
				}
			}
		}()
		job.Target = initial.Address
		target, close, err := PrivateTarget(worker, job)
		if err != nil {
			cancel()
			<-done
			return err
		}
		config.Target = target
		err = PreflightPrivate(worker, job)
		if err == nil {
			err = privatepublisher.Publish(worker, config)
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
