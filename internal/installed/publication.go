package installed

import (
	"context"
	"crypto/tls"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/processidentity"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	targetplan "github.com/tnldotdev/tnl/internal/publisher/target"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// publishJob composes an installed job's captured identity and settings with the
// real publication owners. the reconciler owns retries and joins; publication
// state, relay connections, and certificate work remain with those owners.
func (e Engine) publishJob(ctx context.Context, job Job, attempts uint64, runtime **processidentity.Owner) (bool, error) {
	identity, private, profile, err := e.Registry.signingIdentity(ctx, job)
	if err != nil {
		return false, err
	}
	control, authority, err := e.Clients(job)
	if err != nil {
		return false, err
	}
	if job.Kind == KindPublicURL && control.Discovery == nil {
		return false, ErrScope
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
	if job.Kind == KindService {
		service, err := native.SavedService(ctx)
		if err != nil {
			return false, err
		}
		if err := publisheridentity.MatchServiceDeclaration(service, string(job.Protocol), job.Trust); err != nil {
			return false, err
		}
		if service.TrustRevision != job.TrustRevision || service.PublisherPool != job.PublisherPool {
			return false, ErrScope
		}
		var ready atomic.Bool
		err = targetplan.PublishPrivate(ctx, job.TargetPlan(), publisherservice.RunConfig{
			Telemetry:        e.Telemetry,
			PreferredRegions: slices.Clone(job.PreferredRegions),
			Control:          native, State: profile, Access: native.Access, Identity: identity, Metadata: publisheridentity.ServiceMetadata(service), StreamCapacity: int32(job.Limits.Concurrency),
			ServiceID: job.ServiceID, Target: job.Target,
			Ready: func() error {
				ready.Store(true)
				return e.Registry.status(ctx, job.ID, job.Revision, Status{State: JobReady, Attempts: attempts})
			},
		})
		return ready.Load(), err
	}
	publicURL, err := native.SavedPublicURL(ctx)
	if err != nil {
		return false, err
	}
	cfg, err := publicationConfig(job, publicURL)
	if err != nil {
		return false, err
	}
	cfg.Control, cfg.State, cfg.DrainTime = native, profile, e.DrainTime
	cfg.Telemetry = e.Telemetry
	cfg.Identity, cfg.Audit, cfg.VisitorControl = native, native, control.PublicURLControl
	cfg.BrowserControl = control.PublicURLControl
	cfg.Shares, cfg.Previews, cfg.FeedbackControl = control.PublicURLControl, control.PublicURLControl, control.PublicURLControl
	server, err := control.Discovery.Discovery(ctx)
	if err != nil {
		return false, err
	}
	cfg.BrowserLoginAvailable = server.BrowserLoginAvailable != nil && *server.BrowserLoginAvailable
	cfg.PublisherIdentityID = native.PublisherIdentityID()
	transportTLS := &tls.Config{MinVersion: tls.VersionTLS13}
	cfg.TransportTLS = transportTLS
	var mu sync.Mutex
	ready := false
	cfg.Observe = func(event publisher.Event) error {
		status := Status{State: JobProvisioning, Attempts: attempts, RunNumber: event.PublishRunNumber, PublicURL: event.PublicURL}
		switch event.Type {
		case publisher.EventReady:
			mu.Lock()
			ready = true
			mu.Unlock()
			status.State = JobReady
		case publisher.EventDraining:
			status.State = JobDraining
		case publisher.EventTargetUnavailable:
			status.State = JobTargetUnavailable
		case publisher.EventProvisioning, publisher.EventPublicURLAssigned:
		default:
			return nil
		}
		observationCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return e.Registry.status(observationCtx, job.ID, job.Revision, status)
	}
	if job.VerifyReadiness {
		VerifyPublicationReadiness(ctx, &cfg, job.ReadinessPath)
	}
	// native runtime log messages can contain external error text. system jobs
	// expose only approved observations through the registry and CLI renderer.
	err = e.Publish(ctx, cfg)
	if ctx.Err() == nil && errors.Is(err, clientcontrol.ErrStatusConflict) {
		// an abrupt reboot can leave the previous run open until its lease
		// expires. retry only while this same runtime owner remains current;
		// a fenced epoch must block instead of inspecting and claiming again.
		if _, currentErr := (*runtime).Renew(ctx); currentErr != nil {
			err = currentErr
		} else {
			err = failure.Wrap("wait for previous publish run", failure.InstalledPublishRunPending, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	return ready, err
}

func publicationConfig(job Job, publicURL controlv1.PublicURL) (publisher.Config, error) {
	if err := validateJob(&job); err != nil {
		return publisher.Config{}, err
	}
	if job.Kind != KindPublicURL || job.Protocol != config.ProtocolHTTP || publicURL.Id != job.PublicURLID || publicURL.ServiceProtocol != controlv1.Http || publicURL.Ephemeral || publicURL.Purpose != controlv1.App || publicURL.LifecycleState != controlv1.Enabled {
		return publisher.Config{}, ErrScope
	}
	if publicURL.Target != "" && publicURL.Target != job.Target {
		return publisher.Config{}, ErrScope
	}
	roots, err := trustRoots(job.TargetCAPEM)
	if err != nil {
		return publisher.Config{}, err
	}
	cfg := publisher.Config{ControlURL: job.Server, TeamID: publicURL.TeamId, DomainID: publicURL.DomainId, PolicyRevision: uint64(publicURL.PolicyRevision), PublicURLScope: publicURL.PublicUrlScope, Purpose: publicURL.Purpose, Hostname: publicURL.CanonicalHostname, Target: job.Target, ServiceProtocol: controlv1.Http, TargetTLSName: job.TargetTLSName, TargetOptions: publisherproxy.TargetOptions{RootCAs: roots, ServerName: job.TargetTLSName}, PreserveSavedPublicURLTarget: publicURL.Target == "", InspectionMode: inspection.Mode("none")}
	cfg.Limits = job.Limits
	cfg.Protection = job.Protection
	cfg.PreferredRegions = slices.Clone(job.PreferredRegions)
	if publicURL.MembershipId != nil {
		cfg.MembershipID = *publicURL.MembershipId
	}
	if publicURL.AllowedIpPrefixes != nil {
		cfg.AllowedIPPrefixes = slices.Clone(*publicURL.AllowedIpPrefixes)
	}
	return cfg, nil
}
