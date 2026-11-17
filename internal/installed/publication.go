package installed

import (
	"context"
	"errors"
	"slices"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/policy/serviceendpoint"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/processidentity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	targetplan "github.com/tnldotdev/tnl/internal/publisher/target"
)

// publishJob uses the job's original signing key and exact service grant. the
// supervisor keeps one runtime owner across retries, including open-run conflicts.
func (e Engine) publishJob(ctx context.Context, job Job, attempts uint64, runtime **processidentity.Owner) (bool, error) {
	identity, private, profile, err := e.Registry.signingIdentity(ctx, job)
	if err != nil {
		return false, err
	}
	control, authority, err := e.Clients(job)
	if err != nil {
		return false, err
	}
	native, err := publisheridentity.NewNative(control.NativeControl, authority, identity, private)
	if err != nil {
		return false, err
	}
	if *runtime == nil {
		*runtime, err = native.RemoteRuntime(job.Server)
		if err != nil {
			return false, err
		}
	}
	if _, err := (*runtime).Renew(ctx); err != nil {
		return false, err
	}
	native.WithRuntime(*runtime)
	native, err = native.WithTraffic(job.Traffic)
	if err != nil {
		return false, err
	}
	service, err := native.SavedService(ctx)
	if err != nil {
		return false, err
	}
	if err := publisheridentity.MatchServiceDeclaration(service, string(job.Protocol), job.Trust); err != nil {
		return false, err
	}
	if service.TrustRevision != job.TrustRevision || service.PublisherPool != job.PublisherPool || service.Endpoint == nil {
		return false, ErrScope
	}
	if !serviceendpoint.Valid(string(service.Protocol), service.Endpoint.Hostname, service.Endpoint.Port, service.Endpoint.Public) {
		return false, ErrScope
	}
	worker, cancel := context.WithCancelCause(ctx)
	readiness := newPublicationReadiness(worker, cancel, job, service, attempts, func(ctx context.Context, status Status) error {
		return e.status(ctx, job, status)
	})
	if e.ShutdownContext != nil {
		readiness.shutdownContext = e.ShutdownContext
	}
	if e.ShutdownDeadline != nil {
		readiness.shutdownDeadline = func() time.Time {
			if until := e.ShutdownDeadline(); !until.IsZero() {
				return until
			}
			return time.Now().Add(10 * time.Second)
		}
	}
	cfg := publisherservice.RunConfig{
		Telemetry: e.Telemetry, PreferredRegions: slices.Clone(job.PreferredRegions),
		Control: native, State: profile, Access: native.Access,
		PublisherIdentityID: identity.ClientId, PublisherGrantID: identity.GrantId, PublisherKeyID: identity.KeyId,
		ServiceID: job.ServiceID, Target: job.Target, Metadata: publisheridentity.ServiceMetadata(service),
		StreamCapacity: job.StreamCapacity, DrainTime: e.DrainTime, ShutdownDeadline: e.ShutdownDeadline, ShutdownContext: e.ShutdownContext,
		Prepared: readiness.Prepared, ObserveReadiness: readiness.Observe, Healthy: readiness.Healthy,
	}
	if job.Protocol == config.ProtocolHTTP {
		if service.Endpoint.Public {
			cfg.ReadinessProof = readiness.Proof
		}
	}
	err = targetplan.PublishPrivate(worker, job.TargetPlan(), cfg, targetplan.TargetHooks{Resolver: readiness.resolver, Capture: readiness.Capture})
	cancel(context.Canceled)
	ready, cleanup := readiness.Close()
	if cause := context.Cause(worker); cause != nil && !failure.Only(cause, context.Canceled) {
		err = errors.Join(err, cause)
	}
	err = errors.Join(err, cleanup)
	if ctx.Err() == nil && errors.Is(err, clientcontrol.ErrStatusConflict) {
		// only this existing owner may wait for an earlier run to expire. a
		// fenced owner must block, not inspect and claim a new runtime epoch.
		if _, currentErr := (*runtime).Renew(ctx); currentErr != nil {
			err = errors.Join(err, currentErr)
		} else {
			err = failure.Wrap("wait for previous service run", failure.InstalledPublishRunPending, err)
		}
	}
	return ready, err
}
