package service

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	serviceconfig "github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/tcptarget"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisher/placement"
	"github.com/tnldotdev/tnl/internal/publisher/visitorpolicy"
	"github.com/tnldotdev/tnl/internal/region"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// RunControl is the exact service authority boundary. a person
// creates the saved service separately; only the scoped publisher assertion
// prepares and starts runs, and only the run token can renew or close one.
type RunControl interface {
	ManagedControl
	GetPublisherService(context.Context, string) (controlv1.Service, error)
	PrepareServiceRun(context.Context, string, string, string, controlv1.ServiceRunDeclaration) (controlv1.ServiceRunPreparation, error)
	HeartbeatServiceRunHealth(context.Context, string, string, credentials.ServiceRunToken, controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error)
	CloseServiceRun(context.Context, string, string, credentials.ServiceRunToken) error
}

type SlotSession = tunnel.SlotSession

type RunConfig struct {
	Control           RunControl
	State             *clientstate.Store
	Access            func(context.Context) (string, error)
	Identity          authorityv1.PublisherEnrollmentResult
	ServiceID         string
	PreferredRegions  []string
	Target            string
	TargetResolver    TargetResolver
	resolvedTargetTLS *tls.Config
	HeartbeatInterval time.Duration
	Connect           func(context.Context, *Bound, uint8) (SlotSession, error)
	Ready             func() error
	TransportTLS      *tls.Config
	Metadata          controlv1.ServiceMetadata
	StreamCapacity    int32
	Healthy           func(context.Context) bool
	ObserveReadiness  func(RunStatus)
}

// RunStatus separates current readiness from the one-time Ready notification.
// a failed heartbeat cannot extend LeaseExpiresAt or LastSuccess. target health
// is the local probe result, independent of control configuration and freshness.
type RunStatus struct {
	Ready, TargetHealthy, ConfigurationCurrent bool
	LastCheck, LastSuccess, LeaseExpiresAt     time.Time
	Connected                                  [2]bool
}

func (RunConfig) String() string   { return "private publisher configuration" }
func (RunConfig) GoString() string { return "private publisher configuration" }

// Publish keeps the managed certificate lifecycle, two independently claimed
// relay slots and current control heartbeat together. live bytes are never replayed.
func Publish(ctx context.Context, config RunConfig) (result error) {
	if _, err := region.Preferences(config.PreferredRegions); err != nil {
		return errors.Join(ErrPrivateStream, err)
	}
	if config.Control == nil || config.Access == nil || config.Identity.ServiceId == nil ||
		config.Identity.Kind != authorityv1.Service || *config.Identity.ServiceId != config.ServiceID {
		return ErrPrivateStream
	}
	var discoveredTLS *tls.Config
	if config.TargetResolver != nil {
		var err error
		config.Target, discoveredTLS, err = config.TargetResolver.ResolveTarget(ctx)
		if err != nil {
			return err
		}
		if discoveredTLS == nil {
			return ErrPrivateStream
		}
		config.resolvedTargetTLS = discoveredTLS
	}
	if _, err := tcptarget.Normalize(config.Target); err != nil {
		return err
	}
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = 10 * time.Second
	}
	if config.HeartbeatInterval < time.Millisecond || config.HeartbeatInterval > 15*time.Second {
		return ErrPrivateStream
	}
	key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
	if err != nil {
		return err
	}
	access, err := config.Access(ctx)
	if err != nil || access == "" {
		return errors.Join(ErrPrivateStream, err)
	}
	if config.Metadata.Protocol == "" {
		config.Metadata.Protocol = controlv1.ServiceProtocol("tcp")
	}
	approved, err := config.Control.GetPublisherService(ctx, access)
	if err != nil {
		return err
	}
	if approved.Endpoint == nil || approved.Id != config.ServiceID || !approved.Enabled || approved.TrustRevision < 1 ||
		approved.Protocol != config.Metadata.Protocol || !samePrivateTrust(approved.TargetTls, config.Metadata.TargetTls) ||
		config.Metadata.TrustRevision != 0 && config.Metadata.TrustRevision != approved.TrustRevision {
		return ErrPrivateStream
	}
	config.Metadata.TrustRevision = approved.TrustRevision
	ctx = observability.NarrowIdentity(ctx, observability.Identity{TeamID: approved.TeamId, PublisherIdentityID: config.Identity.ClientId, ServiceID: approved.Id})
	exposure := "private"
	if approved.Endpoint.Public {
		exposure = "public"
	}
	protocol, _ := observability.ParseProtocol(string(approved.Protocol))
	ctx = observability.WithFields(ctx, observability.Fields{Component: "publisher", ServiceProtocol: protocol, Exposure: exposure})
	ctx = observability.WithPublisherRecovery(ctx)
	_, startup := observability.PublisherOperation(ctx, "private_startup")
	defer func() { startup(result) }()
	trust, err := targetTrust(approved)
	if err != nil {
		return err
	}
	transport := targettransport.Transport{Protocol: serviceconfig.ProtocolName(approved.Protocol)}
	if config.TargetResolver != nil {
		// cloud trust comes from the exact assigned selector's publisher-side
		// discovery, never from a local apply or a saved static CA override.
		if trust != nil {
			return ErrPrivateStream
		}
		transport.TLS = discoveredTLS
	} else {
		transport, err = targettransport.FromTrust(serviceconfig.ProtocolName(approved.Protocol), trust)
		if err != nil {
			return err
		}
	}
	if err := transport.Validate(); err != nil {
		return err
	}
	declaration := controlv1.ServiceRunDeclaration{Protocol: config.Metadata.Protocol, TargetTls: config.Metadata.TargetTls, TrustRevision: approved.TrustRevision}
	if config.StreamCapacity == 0 {
		config.StreamCapacity = 64
	}
	if config.StreamCapacity < 1 || config.StreamCapacity > 4096 {
		return ErrPrivateStream
	}
	if config.Healthy == nil {
		config.Healthy = func(ctx context.Context) bool {
			probe, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			target, current := config.Target, transport
			if config.TargetResolver != nil {
				var err error
				target, current.TLS, err = config.TargetResolver.ResolveTarget(probe)
				if err != nil {
					return false
				}
			}
			return current.Preflight(probe, target) == nil
		}
	}
	var preparation controlv1.ServiceRunPreparation
	err = recoverControlResponse(ctx, time.Time{}, func(attempt context.Context) error {
		access, err := config.Access(attempt)
		if err != nil {
			return err
		}
		if access == "" {
			return ErrPrivateStream
		}
		preparation, err = config.Control.PrepareServiceRun(attempt, config.ServiceID, key, access, declaration)
		return err
	})
	if err != nil {
		return err
	}
	if preparation.IdempotencyKey != key {
		return ErrPrivateStream
	}
	var prepared *Prepared
	managedControl := config.Control
	prepared, err = newManagedPrepared(preparation, approved, config)
	if err != nil {
		return err
	}
	// uncertain starts retry the exact prepared run, never a new preparation.
	var setup controlv1.ServiceRunSetup
	preferred := config.PreferredRegions
	if len(preferred) == 0 {
		if reader, ok := config.Control.(placement.CandidateReader); ok {
			preferred = placement.PreferredRegions(ctx, reader, access)
		}
	}
	err = recoverControlResponse(ctx, preparation.ExpiresAt, func(attempt context.Context) error {
		access, err := config.Access(attempt)
		if err != nil {
			return err
		}
		if access == "" {
			return ErrPrivateStream
		}
		if len(preferred) > 0 {
			control, ok := managedControl.(interface {
				StartServiceRunInRegions(context.Context, string, string, string, int64, []string) (controlv1.ServiceRunSetup, error)
			})
			if !ok {
				return errors.Join(ErrPrivateStream, region.ErrPreference)
			}
			setup, err = control.StartServiceRunInRegions(attempt, config.ServiceID, preparation.ServiceRunId, access, preparation.RunNumber, preferred)
		} else {
			setup, err = managedControl.StartServiceRun(attempt, config.ServiceID, preparation.ServiceRunId, access, preparation.RunNumber)
		}
		return err
	})
	if err != nil {
		return err
	}
	runToken := credentials.ServiceRunToken(setup.RunToken)
	defer func() {
		finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		result = errors.Join(result, config.Control.CloseServiceRun(finish, config.ServiceID, setup.ServiceRunId, runToken))
	}()
	// control owns the opaque token's encoding and authorization. Activate
	// requires a nonempty value and binds the setup to this prepared run.
	bound, err := prepared.Activate(setup)
	if err != nil {
		return err
	}
	defer bound.Invalidate()
	bound.streamCapacity = int(config.StreamCapacity)
	policy, err := visitorpolicy.Prepare(ctx, managedControl, visitorscope.Scope{Kind: visitorscope.Service, ID: setup.ServiceId}, setup.ServiceRunId, setup.RunNumber, setup.RunToken, nil)
	if err != nil {
		return err
	}
	defer policy.Close()
	prepared.policy = policy.Lease
	if prepared.managedPublic && prepared.managedProtocol == serviceconfig.ProtocolHTTP {
		prepared.serviceHTTP, err = publisher.NewServiceHTTPRuntime(ctx, managedControl, policy)
		if err != nil {
			return err
		}
		defer prepared.serviceHTTP.Close()
	}
	var certificateDone <-chan error
	{
		maintain, cancel, err := configureServiceRun(ctx, config, prepared, setup, managedControl, config.State)
		if err != nil {
			return err
		}
		done := make(chan error, 1)
		certificateDone = done
		go func() { done <- maintain() }()
		defer func() {
			cancel()
			if certificateDone != nil {
				<-certificateDone
			}
		}()
	}
	status := RunStatus{ConfigurationCurrent: true}
	report := func() {
		observability.PublisherReadinessStatus(ctx, status.Ready, status.TargetHealthy, status.ConfigurationCurrent, status.LastCheck, status.LastSuccess)
		if config.ObserveReadiness != nil {
			config.ObserveReadiness(status)
		}
	}
	defer func() {
		status.Ready = false
		status.LastCheck = time.Now()
		report()
	}()
	heartbeat := func(ctx context.Context) (state controlv1.ServiceRunState, err error) {
		ctx, finish := observability.PublisherOperation(ctx, "private_heartbeat")
		defer func() {
			finish(err)
			if err == nil {
				observability.PublisherLease(ctx, state.PublisherExpiresAt)
			}
		}()
		bound.mu.Lock()
		active := len(bound.active)
		bound.mu.Unlock()
		status.TargetHealthy = config.Healthy(ctx)
		state, err = config.Control.HeartbeatServiceRunHealth(ctx, config.ServiceID, setup.ServiceRunId, runToken,
			controlv1.ServiceRunHeartbeat{Healthy: status.TargetHealthy, StreamCapacity: config.StreamCapacity, ActiveStreams: int32(active)})
		if err == nil {
			err = bound.ApplyHeartbeat(state)
			if err != nil {
				status.ConfigurationCurrent = false
			}
		}
		return state, err
	}
	state, err := heartbeat(ctx)
	if err != nil {
		return errors.Join(ErrPrivateStream, err)
	}
	paths, err := tunnel.NewSlots(context.WithoutCancel(ctx), tunnel.SlotsConfig{SingleUse: true, Connect: func(ctx context.Context, slot uint8, preferTCP bool) (tunnel.SlotSession, error) {
		if config.Connect != nil {
			return config.Connect(ctx, bound, slot)
		}
		return bound.ConnectSlotWithPreference(ctx, slot, preferTCP, config.TransportTLS)
	}})
	if err != nil {
		return err
	}
	defer func() {
		if result == nil && ctx.Err() != nil {
			finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()
			_ = paths.Drain(finish)
		} else {
			_ = paths.Close()
		}
	}()
	for slot := range uint8(2) {
		if err := paths.Set(slot, bound.assignmentKey(slot)); err != nil {
			return err
		}
	}
	ticker := time.NewTicker(config.HeartbeatInterval)
	defer ticker.Stop()
	ready := false
	heartbeatOK := true
	for {
		connected, changed := paths.Snapshot()
		status.LastCheck = time.Now()
		status.LeaseExpiresAt = state.PublisherExpiresAt
		status.Connected = [2]bool{connected[0] != nil, connected[1] != nil}
		// initial readiness needs both slots; an established run can serve on one
		// while replacing the other, without repeating its one-time notification.
		connectionsReady := status.Connected[0] && status.Connected[1] || ready && (status.Connected[0] || status.Connected[1])
		status.Ready = heartbeatOK && status.ConfigurationCurrent && status.TargetHealthy && state.PublisherExpiresAt.After(status.LastCheck) && state.State == controlv1.ServiceRunStateState("ready") && (state.Healthy == nil || *state.Healthy) && connectionsReady
		if status.Ready {
			status.LastSuccess = status.LastCheck
		}
		report()
		if status.Ready && !ready {
			if config.Ready != nil {
				if err := config.Ready(); err != nil {
					return err
				}
			}
			ready = true
			startup(nil)
		}
		expires := time.NewTimer(time.Until(state.PublisherExpiresAt))
		select {
		case err := <-certificateDone:
			expires.Stop()
			certificateDone = nil
			if ctx.Err() != nil {
				return nil
			}
			return err
		case <-ctx.Done():
			expires.Stop()
			return nil
		case <-expires.C:
			return ErrPrivateStream
		case <-changed:
			expires.Stop()
		case <-ticker.C:
			expires.Stop()
			if !state.PublisherExpiresAt.After(time.Now()) {
				return ErrPrivateStream
			}
			checkCtx, cancel := context.WithDeadline(ctx, state.PublisherExpiresAt)
			next, err := heartbeat(checkCtx)
			cancel()
			if err != nil {
				heartbeatOK = false
				status.Ready = false
				status.LastCheck = time.Now()
				report()
				if ctx.Err() != nil {
					return nil
				}
				reason, _ := failure.ReasonOf(err)
				if reason != failure.ServerUnavailable && reason != failure.ServerRateLimited {
					return err
				}
				// a surviving slot remains usable only until the last confirmed
				// publisher deadline; retry without reviving stale authority.
				continue
			}
			state = next
			heartbeatOK = true
			for slot := range uint8(2) {
				if err := paths.Set(slot, bound.assignmentKey(slot)); err != nil {
					return err
				}
			}
		}
	}
}

// recoverControlResponse keeps an uncertain mutation inside its owning
// invocation. preparation has no locally known deadline until control replies;
// only control can decide whether that exact idempotency key has expired.
// start retries retain the exact endpoint and plan until preparation expires.
func recoverControlResponse(ctx context.Context, expires time.Time, operation func(context.Context) error) error {
	if !expires.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, expires)
		defer cancel()
	}
	delay := 100 * time.Millisecond
	for {
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		err := operation(ctx)
		if err == nil || !transientControlError(err) {
			return err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return context.Cause(ctx)
		case <-timer.C:
		}
		delay = min(2*delay, 2*time.Second)
	}
}

func transientControlError(err error) bool {
	if reason, ok := failure.ReasonOf(err); ok {
		return reason == failure.ServerUnavailable || reason == failure.ServerRateLimited
	}
	var network net.Error
	return errors.As(err, &network) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func samePrivateTrust(left, right *controlv1.ServiceTargetTLS) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	snapshot := func(value *controlv1.ServiceTargetTLS) targettrust.Snapshot {
		var pem []byte
		if value.Pem != nil {
			pem = []byte(*value.Pem)
		}
		return targettrust.Snapshot{Hostname: value.Hostname, System: value.System, PEM: pem, Digest: value.Digest}
	}
	a, b := snapshot(left), snapshot(right)
	if _, err := a.Verifier(); err != nil {
		return false
	}
	if _, err := b.Verifier(); err != nil {
		return false
	}
	return a.Digest == b.Digest && a.Hostname == b.Hostname && a.System == b.System && string(a.PEM) == string(b.PEM)
}
