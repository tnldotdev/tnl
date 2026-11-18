package service

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	serviceconfig "github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/controloutage"
	"github.com/tnldotdev/tnl/internal/policy/tcptarget"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/proxy"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/region"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	telemetryv1 "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

// RunControl is the exact service authority boundary. a person
// creates the saved service separately; only the scoped publisher assertion
// prepares and starts runs, and only the run token can renew or close one.
type RunControl interface {
	ManagedControl
	connectorPolicyControl
	ConnectorPeerControl
	GetPublisherService(context.Context, string, string) (controlv1.Service, error)
	PrepareServiceRun(context.Context, string, string, string, controlv1.ServiceRunDeclaration) (controlv1.ServiceRunPreparation, error)
	HeartbeatServiceRun(context.Context, string, string, credentials.ServiceRunToken, controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error)
	CloseServiceRun(context.Context, string, string, credentials.ServiceRunToken) error
	ReportServiceRunObservations(context.Context, string, string, int64, credentials.ServiceRunToken, serviceaudit.Batch) error
}

type SlotSession = tunnel.SlotSession

// Telemetry starts the optional run-owned scope without requiring its native
// collector's database or preference watcher in portable publication.
type Telemetry interface {
	BeginScope(telemetryv1.TransportReportRole) *clienttelemetry.Scope
}

type RunConfig struct {
	Telemetry Telemetry
	// framework is optional; unknown generated enum values are omitted.
	Framework        telemetryv1.PublicationReadyFramework
	PreferredRegions []string
	Control          RunControl
	State            LocalState
	// certificate storage is explicit for host publishers. when supplied, no
	// certificate operation consults State or opens a native private directory.
	CertificateStore                                      CertificateStore
	Access                                                func(context.Context) (string, error)
	PublisherIdentityID, PublisherGrantID, PublisherKeyID string
	ServiceID                                             string
	Target                                                string
	Handler                                               http.Handler
	Mounts                                                []proxy.Mount
	// ResolveHTTPTarget captures one HTTP request's target and replacement identity.
	// target trust remains run-approved; discovery with its own TLS uses TargetResolver.
	ResolveHTTPTarget func(*http.Request) (address, identity string, err error)
	InspectionMode    inspection.Mode
	ObserveSummary    inspection.Observer
	AdmitRequest      func(*http.Request) error
	// http admission receives this serving run's validated facts, not mutable
	// preparation state shared with another publication.
	HTTPAdmitRequest func(*http.Request, HTTPRun) error
	// preparation is read-only; its per-request claim commits only after visitor
	// authorization and capacity admission, immediately before app forwarding.
	// owner readiness probes do not prepare or commit application claims.
	HTTPPrepareRequest                     func(*http.Request, HTTPRun) (func(context.Context) error, error)
	ReadinessProof                         func(httpaccess.ReadinessRun) *httpaccess.ReadinessProof
	Feedback                               bool
	PreviewID, ProjectService, ProjectRoot string
	Demo                                   bool
	// nil asks the public HTTP owner to observe discovery. a nonnil value
	// captures an earlier successful observation, including disabled or omitted.
	BrowserLoginAvailable *bool
	// http response hooks are built once from validated run facts, not per visitor.
	// inline applications do not use upstream response hooks.
	HTTPResponseHooks func(HTTPRun) httpstream.ResponseHooks
	TargetResolver    TargetResolver
	resolvedTargetTLS *tls.Config
	HeartbeatInterval time.Duration
	DrainTime         time.Duration
	// shutdown deadline is owned by the composing operation and includes drain
	// and exact-run cleanup. without an active fence the first value is fixed;
	// with a fence later values may only narrow the first local stop cap.
	ShutdownDeadline func() time.Time
	// shutdown context carries the owner's active expiry fence. cancellation of
	// ordinary publication work must not be used as this cleanup lifetime.
	ShutdownContext context.Context
	Connect         func(context.Context, *Bound, uint8, ConnectOptions) (SlotSession, error)
	// prepared observes validated control facts once, before starting that run.
	Prepared       func(controlv1.ServiceRunPreparation) error
	Ready          func() error
	TransportTLS   *tls.Config
	RelayQUIC      muxsession.Connector
	RelayWebSocket muxsession.Connector
	// WebSocketOnly avoids native UDP resources, including direct discovery.
	WebSocketOnly bool
	Connectivity  peer.ConnectivityOptions
	// PeerSocket is borrowed by qualification; the default service run owns one.
	PeerSocket       *peer.Socket
	Metadata         controlv1.ServiceMetadata
	StreamCapacity   int32
	Healthy          func(context.Context) bool
	ObserveReadiness func(RunStatus)
}

// RunStatus separates current readiness from the one-time Ready notification.
// a failed heartbeat cannot extend LeaseExpiresAt or LastSuccess. target health
// is the local probe result, independent of control configuration and freshness.
type RunStatus struct {
	Ready, TargetHealthy, ConfigurationCurrent bool
	LastCheck, LastSuccess, LeaseExpiresAt     time.Time
	Connected                                  [2]bool
	// transports belong to the connected sessions in this observation, not
	// attempted dials or a remembered transport preference.
	Transports [2]tunnel.Transport
	Draining   bool
}

func (RunConfig) String() string   { return "service publisher configuration" }
func (RunConfig) GoString() string { return "service publisher configuration" }

func (c RunConfig) hasFetchTarget() bool {
	return c.Handler != nil && c.Metadata.Protocol == controlv1.ServiceProtocolHTTP && c.Target == "" &&
		c.TargetResolver == nil && c.Metadata.TargetTls == nil && len(c.Mounts) == 0 && c.ResolveHTTPTarget == nil
}

// Publish keeps the managed certificate lifecycle, two independently claimed
// relay slots and current control heartbeat together. live bytes are never replayed.
func Publish(ctx context.Context, config RunConfig) (result error) {
	if err := validateFeedbackPlatform(config.Feedback, config.Demo); err != nil {
		return err
	}
	if servicestream.HandlerOnly && !config.hasFetchTarget() {
		return ErrPrivateStream
	}
	if !peer.HostUDP || config.WebSocketOnly {
		config.WebSocketOnly = true
		config.RelayQUIC = muxsession.DisabledConnector{}
		config.Connectivity.DisableDirect = true
	}
	config.PreferredRegions, result = region.Preferences(config.PreferredRegions)
	if result != nil {
		return result
	}
	var telemetry *clienttelemetry.Scope
	if config.Telemetry != nil {
		telemetry = config.Telemetry.BeginScope("publisher")
	}
	defer telemetry.Close()
	if config.Control == nil || config.Access == nil || !config.Metadata.Protocol.Valid() || !config.InspectionMode.Valid() || config.DrainTime < 0 ||
		!opaqueid.Valid(config.ServiceID, opaqueid.ServicePrefix) ||
		!opaqueid.Valid(config.PublisherIdentityID, opaqueid.PublisherIdentityPrefix) ||
		!opaqueid.Valid(config.PublisherGrantID, opaqueid.PublisherGrantPrefix) ||
		!opaqueid.Valid(config.PublisherKeyID, opaqueid.PublisherIdentityKeyPrefix) ||
		config.ReadinessProof != nil && config.Metadata.Protocol != controlv1.ServiceProtocolHTTP ||
		config.Feedback && config.Metadata.Protocol != controlv1.ServiceProtocolHTTP ||
		(len(config.Mounts) != 0 || config.ResolveHTTPTarget != nil) &&
			(config.Metadata.Protocol != controlv1.ServiceProtocolHTTP || config.Handler != nil || config.TargetResolver != nil) ||
		config.HTTPResponseHooks != nil && (config.Metadata.Protocol != controlv1.ServiceProtocolHTTP || config.Handler != nil) {
		return ErrPrivateStream
	}
	if config.DrainTime == 0 {
		config.DrainTime = 10 * time.Second
	}
	parentDeadline := config.ShutdownDeadline
	if parentDeadline != nil && config.ShutdownContext == nil {
		parentDeadline = sync.OnceValue(parentDeadline)
	}
	var deadlineMu sync.Mutex
	var shutdownUntil time.Time
	config.ShutdownDeadline = func() time.Time {
		var parent time.Time
		if parentDeadline != nil {
			parent = parentDeadline()
		}
		deadlineMu.Lock()
		defer deadlineMu.Unlock()
		if shutdownUntil.IsZero() {
			shutdownUntil = time.Now().Add(config.DrainTime)
		}
		if !parent.IsZero() && parent.Before(shutdownUntil) {
			shutdownUntil = parent
		}
		return shutdownUntil
	}
	canceled := make(chan struct{})
	stopShutdown := context.AfterFunc(ctx, func() { defer close(canceled); config.ShutdownDeadline() })
	defer func() {
		if !stopShutdown() {
			<-canceled
		}
	}()
	var dialer muxsession.QUICDialer
	var udpErr error
	if peer.HostUDP && config.RelayQUIC == nil {
		var transport *muxsession.QUICTransport
		transport, udpErr = muxsession.ListenQUICTransport("udp", ":0")
		if udpErr == nil {
			dialer = transport
			defer func() { result = errors.Join(result, transport.Close()) }()
		}
	}
	connectOptions, err := config.connectionOptions(dialer, udpErr)
	if err != nil {
		return err
	}
	var discoveredTLS *tls.Config
	if !servicestream.HandlerOnly && config.TargetResolver != nil {
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
	if config.Handler != nil {
		if !config.hasFetchTarget() {
			return ErrPrivateStream
		}
	} else if !servicestream.HandlerOnly {
		if _, err := tcptarget.Normalize(config.Target); err != nil {
			return err
		}
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
	if err != nil {
		return err
	}
	if access == "" {
		return ErrPrivateStream
	}
	approved, err := config.Control.GetPublisherService(ctx, config.ServiceID, access)
	if err != nil {
		return err
	}
	if approved.Endpoint == nil || approved.Id != config.ServiceID || !approved.Enabled || approved.TrustRevision < 1 || approved.EndpointRevision < 1 ||
		approved.Protocol != config.Metadata.Protocol || !samePrivateTrust(approved.TargetTls, config.Metadata.TargetTls) ||
		config.Metadata.TrustRevision != 0 && config.Metadata.TrustRevision != approved.TrustRevision {
		return ErrPrivateStream
	}
	config.Metadata.TrustRevision = approved.TrustRevision
	ctx = observability.NarrowIdentity(ctx, observability.Identity{TeamID: approved.TeamId, PublisherIdentityID: config.PublisherIdentityID, ServiceID: approved.Id})
	exposure := "private"
	if approved.Endpoint.Public {
		exposure = "public"
	}
	protocol, _ := observability.ParseProtocol(string(approved.Protocol))
	ctx = observability.WithFields(ctx, observability.Fields{Component: "publisher", ServiceProtocol: protocol, Exposure: exposure})
	ctx = observability.WithPublisherRecovery(ctx)
	_, startup := observability.PublisherOperation(ctx, "private_startup")
	defer func() { startup(result) }()
	transport := targettransport.Transport{Protocol: serviceconfig.ProtocolName(approved.Protocol)}
	if !servicestream.HandlerOnly {
		trust, err := targetTrust(approved)
		if err != nil {
			return err
		}
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
	}
	if err := transport.Validate(); err != nil {
		return err
	}
	declaration := controlv1.ServiceRunDeclaration{Protocol: config.Metadata.Protocol, TargetTls: config.Metadata.TargetTls, TrustRevision: approved.TrustRevision}
	if len(config.PreferredRegions) != 0 {
		declaration.PreferredRegions = &config.PreferredRegions
	}
	if config.StreamCapacity == 0 {
		config.StreamCapacity = 64
	}
	if config.StreamCapacity < 1 || config.StreamCapacity > 4096 {
		return ErrPrivateStream
	}
	if config.Healthy == nil {
		config.Healthy = func(ctx context.Context) bool {
			if servicestream.HandlerOnly || config.Handler != nil {
				return true
			}
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
	reservation := runPreparation{config: config, approved: approved, key: key, declaration: declaration}
	defer func() { result = errors.Join(result, reservation.close(ctx)) }()
	preparation, err := reservation.prepare(ctx)
	if err != nil {
		return err
	}
	var prepared *Prepared
	managedControl := config.Control
	prepared, err = newManagedPrepared(preparation, approved, config)
	if err != nil {
		return err
	}
	if config.Prepared != nil {
		if err := config.Prepared(preparation); err != nil {
			return err
		}
	}
	// uncertain starts retry the exact prepared run, never a new preparation.
	var setup controlv1.ServiceRunSetup
	err = recoverControlResponse(ctx, preparation.ExpiresAt, func(attempt context.Context) error {
		access, err := config.Access(attempt)
		if err != nil {
			return err
		}
		if access == "" {
			return ErrPrivateStream
		}
		setup, err = managedControl.StartServiceRun(attempt, config.ServiceID, preparation.ServiceRunId, access, preparation.RunNumber)
		return err
	})
	if err != nil {
		return err
	}
	if setup.RunToken != preparation.RunToken {
		return ErrPrivateStream
	}
	runToken := credentials.ServiceRunToken(preparation.RunToken)
	// control owns the opaque token's encoding and authorization. Activate
	// requires a nonempty value and binds the setup to this prepared run.
	bound, err := prepared.Activate(setup)
	if err != nil {
		return err
	}
	// caller cancellation requests bounded drain, not authority revocation.
	// the run owner cancels these workers only after visitors have joined.
	runCtx, stopRun := context.WithCancel(context.WithoutCancel(ctx))
	defer stopRun()
	bound.telemetry = telemetry
	bound.connectivityOptions = telemetry.Connectivity(config.Connectivity)
	if peer.HostUDP && !config.Connectivity.DisableDirect {
		bound.peerSocket = config.PeerSocket
		if bound.peerSocket == nil {
			// UDP is an optimization; a blocked socket leaves relay WSS usable.
			// relay slots retain admitted visitors through caller cancellation.
			// the deferred close follows their bounded drain and joined cleanup.
			bound.peerSocket, _ = peer.ListenSocket(context.WithoutCancel(ctx), "udp", ":0")
			if bound.peerSocket != nil {
				defer bound.peerSocket.Close()
			}
		}
		if bound.peerSocket != nil && config.RelayQUIC == nil {
			connector := connectOptions.QUIC.(muxsession.QUICConnector)
			connector.Dialer = bound.peerSocket
			connectOptions.QUIC = connector
		}
	}
	// close and join visitors before flushing their final observations. the
	// reporter outlives caller cancellation but retains a fixed shutdown budget.
	audit, err := serviceaudit.NewQueue(context.WithoutCancel(ctx), serviceaudit.QueueConfig{
		Metrics: observability.FromContext(ctx),
		Report: func(ctx context.Context, batch serviceaudit.Batch) error {
			return config.Control.ReportServiceRunObservations(ctx, config.ServiceID, setup.ServiceRunId, setup.RunNumber, runToken, batch)
		},
	})
	if err != nil {
		bound.Invalidate()
		return err
	}
	bound.audit = audit
	defer func() {
		bound.Invalidate()
		flush, finish := config.cleanupContext(ctx, config.ShutdownDeadline())
		defer func() { result = errors.Join(result, finish()) }()
		result = errors.Join(result, audit.Close(flush))
	}()
	bound.streamCapacity = int(config.StreamCapacity)
	var certificateDone <-chan error
	{
		// synchronous discovery and preview setup still belong to the caller.
		// detach that stop request once setup joins; serving workers then retain
		// the run lifetime through admitted visitors' bounded drain.
		startupCtx, stopStartup := context.WithCancel(runCtx)
		defer stopStartup()
		startupCanceled := make(chan struct{})
		detach := context.AfterFunc(ctx, func() { defer close(startupCanceled); stopStartup() })
		maintain, cancel, err := configureServiceRun(startupCtx, config, prepared, setup, managedControl, config.State, audit)
		if !detach() {
			<-startupCanceled
		}
		if err != nil {
			return err
		}
		done := make(chan error, 1)
		certificateDone = done
		go func() { done <- maintain() }()
		defer func() {
			result = errors.Join(result, cancel())
			if certificateDone != nil {
				result = errors.Join(result, serviceWorkerError(<-certificateDone, context.Canceled))
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
	var servingConfirmation controloutage.Confirmation
	heartbeat := func(ctx context.Context) (state controlv1.ServiceRunState, err error) {
		started := time.Now()
		ctx, finish := observability.PublisherOperation(ctx, "private_heartbeat")
		defer func() {
			finish(err)
			if err == nil {
				observability.PublisherLease(ctx, state.PublisherExpiresAt)
			}
		}()
		bound.mu.Lock()
		active := bound.reservedStreams
		bound.mu.Unlock()
		status.TargetHealthy = config.Healthy(ctx)
		state, err = config.Control.HeartbeatServiceRun(ctx, config.ServiceID, setup.ServiceRunId, runToken,
			controlv1.ServiceRunHeartbeat{Healthy: status.TargetHealthy, StreamCapacity: config.StreamCapacity, ActiveStreams: int32(active)})
		if err == nil {
			var next controloutage.Confirmation
			next, state, err = acceptServingConfirmation(servingConfirmation, started, state, time.Now())
			if err == nil {
				err = context.Cause(ctx)
			}
			if err == nil {
				err = bound.ApplyHeartbeat(state)
			}
			if err == nil {
				servingConfirmation = next
			}
			if err != nil {
				status.ConfigurationCurrent = false
			}
		}
		return state, err
	}
	state, err := heartbeat(ctx)
	if err != nil {
		return err
	}
	if err := bound.PrepareConnectorPolicy(runCtx, config.Control, runToken); err != nil {
		return err
	}
	peers, stopPeers := context.WithCancel(runCtx)
	peersDone := make(chan error, 1)
	go func() { peersDone <- bound.ServeConnectorPeers(peers, config.Control, runToken) }()
	defer func() {
		stopPeers()
		if peersDone != nil {
			result = errors.Join(result, serviceWorkerError(<-peersDone, context.Canceled))
		}
	}()
	paths, err := tunnel.NewSlots(context.WithoutCancel(ctx), tunnel.SlotsConfig{SingleUse: true, Connect: func(ctx context.Context, slot uint8, preferTCP bool) (tunnel.SlotSession, error) {
		options := connectOptions
		options.PreferWebSocket = config.WebSocketOnly || preferTCP
		if config.Connect != nil {
			return config.Connect(ctx, bound, slot, options)
		}
		return bound.ConnectSlot(ctx, slot, options)
	}})
	if err != nil {
		return err
	}
	completed := false
	publisherExpires := state.PublisherExpiresAt
	defer func() {
		until := config.ShutdownDeadline()
		if publisherExpires.Before(until) {
			until = publisherExpires
		}
		finish, join := config.cleanupContext(ctx, until)
		defer func() { result = errors.Join(result, join()) }()
		interrupt := bound.fenceDrain(until)
		status.Ready, status.Draining = false, true
		status.LastCheck = time.Now()
		report()
		drained := make(chan error, 1)
		visitorsJoined := make(chan struct{})
		peersJoined := make(chan struct{})
		if peersDone == nil {
			close(peersJoined)
		}
		var invalidationDone <-chan struct{}
		invalidationStarted := false
		invalidate := func() {
			if invalidationStarted {
				return
			}
			invalidationStarted = true
			// fence authority now; never enter a potentially blocking physical
			// close in the owner's failure/deadline selection loop.
			bound.mu.Lock()
			bound.closed = true
			bound.mu.Unlock()
			stopRun()
			done := make(chan struct{})
			invalidationDone = done
			go func() { bound.Invalidate(); close(done) }()
		}
		if result != nil || !completed && ctx.Err() == nil {
			invalidate()
		}
		go func() {
			interruptionErr := interrupt()
			visitorErr := bound.joinDrain()
			close(visitorsJoined)
			stopPeers()
			<-peersJoined
			drained <- errors.Join(interruptionErr, visitorErr, paths.StopAdmissions(finish))
		}()
		deadline := finish.Done()
	drain:
		for {
			select {
			case err := <-drained:
				drained = nil
				result = errors.Join(result, err)
				if invalidationDone == nil {
					break drain
				}
			case <-invalidationDone:
				invalidationDone = nil
				if drained == nil {
					break drain
				}
			case <-deadline:
				deadline = nil
				result = errors.Join(result, context.DeadlineExceeded)
				invalidate()
			case err := <-certificateDone:
				certificateDone = nil
				result = errors.Join(result, serviceWorkerError(err, context.Canceled))
				invalidate()
			case err := <-peersDone:
				peersDone = nil
				result = errors.Join(result, serviceWorkerError(err, context.Canceled))
				close(peersJoined)
				select {
				case <-visitorsJoined:
					// expected peer retirement after admitted visitors join.
				default:
					invalidate()
				}
			}
		}
		result = errors.Join(result, paths.Close())
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
	startupConfirmationAttempted := false
	refreshHeartbeat := func() (stop bool, err error) {
		if !state.PublisherExpiresAt.After(time.Now()) {
			return true, ErrPrivateStream
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
				return true, serviceWorkerError(err, ctx.Err())
			}
			reason, _ := failure.ReasonOf(err)
			if reason != failure.ServerUnavailable && reason != failure.ServerRateLimited {
				return true, err
			}
			// a surviving slot remains usable only until the last confirmed
			// publisher deadline; retry without reviving stale authority.
			return false, nil
		}
		state = next
		publisherExpires = state.PublisherExpiresAt
		heartbeatOK = true
		for slot := range uint8(2) {
			if err := paths.Set(slot, bound.assignmentKey(slot)); err != nil {
				return true, err
			}
		}
		return false, nil
	}
	localReadiness := func(connected [2]SlotSession, now time.Time) bool {
		// native policies use their own permission port (zero), not an HTTP
		// endpoint shape. every protocol still needs its exact current policy.
		connectionsReady := connected[0] != nil && connected[1] != nil || ready && (connected[0] != nil || connected[1] != nil)
		_, certificateErr := prepared.currentCertificate()
		bound.mu.Lock()
		current := !bound.closed
		bound.mu.Unlock()
		return ctx.Err() == nil && current && prepared.currentPolicy() && certificateErr == nil &&
			status.ConfigurationCurrent && status.TargetHealthy && state.PublisherExpiresAt.After(now) && connectionsReady
	}
	controlReadiness := func() bool {
		endpointReady := !approved.Endpoint.Public || state.PublicEndpointReady && state.EndpointRevision == approved.EndpointRevision
		return endpointReady && state.State == controlv1.ServiceRunStateState("ready") && (state.Healthy == nil || *state.Healthy)
	}
	currentReadiness := func(connected [2]SlotSession, now time.Time) bool {
		return localReadiness(connected, now) && heartbeatOK && controlReadiness()
	}
	for {
		connected, changed := paths.Snapshot()
		status.LastCheck = time.Now()
		status.LeaseExpiresAt = state.PublisherExpiresAt
		status.Connected = [2]bool{connected[0] != nil, connected[1] != nil}
		status.Transports = [2]tunnel.Transport{}
		for slot, session := range connected {
			if session != nil {
				status.Transports[slot] = session.Transport()
			}
		}
		// initial readiness needs both slots; an established run can serve on one
		// while replacing the other, without repeating its one-time notification.
		status.Ready = currentReadiness(connected, status.LastCheck)
		if status.Ready {
			status.LastSuccess = status.LastCheck
		}
		report()
		if status.Ready && !ready {
			// reporting calls user code. it can outlive a deadline or revoke
			// policy, so recheck authority and connected slots before notification.
			current, _ := paths.Snapshot()
			if !currentReadiness(current, time.Now()) {
				status.Ready, status.LastCheck = false, time.Now()
				report()
			} else {
				if config.Ready != nil {
					if err := config.Ready(); err != nil {
						return err
					}
				}
				ready = true
				payload := telemetryv1.PublicationReady{ServerKind: telemetryv1.SelfHosted, PublishMode: telemetryv1.App}
				if config.Control.ControlURL() == naming.DefaultControlURL {
					payload.ServerKind = telemetryv1.Hosted
				}
				if config.Demo {
					payload.PublishMode = telemetryv1.Demo
				}
				if framework := config.Framework; framework.Valid() {
					payload.Framework = &framework
				}
				telemetry.Ready(payload)
				startup(nil)
			}
		}
		if !ready && !startupConfirmationAttempted && !controlReadiness() {
			// reporting can run user code. confirm current local prerequisites
			// again before spending the one startup attempt, including on failure.
			current, _ := paths.Snapshot()
			if localReadiness(current, time.Now()) {
				startupConfirmationAttempted = true
				if stop, err := refreshHeartbeat(); stop {
					return err
				}
				continue
			}
		}
		expires := time.NewTimer(time.Until(state.PublisherExpiresAt))
		select {
		case <-prepared.serviceHTTPRequests.Completed():
			expires.Stop()
			completed = true
			return nil
		case err := <-peersDone:
			expires.Stop()
			peersDone = nil
			return errors.Join(ErrPrivateStream, err)
		case err := <-certificateDone:
			expires.Stop()
			certificateDone = nil
			return err
		case <-ctx.Done():
			expires.Stop()
			return nil
		case <-expires.C:
			return ErrPrivateStream
		case <-changed:
			expires.Stop()
		case <-prepared.certificateInstalled:
			expires.Stop()
		case <-ticker.C:
			expires.Stop()
			if stop, err := refreshHeartbeat(); stop {
				return err
			}
		}
	}
}

// an expected stop alone is not failure. inspect the actual causes rather than
// errors.Is, which also matches a join containing an independent failure.
func serviceWorkerError(err, stopped error) error {
	if err == nil || err == stopped {
		return nil
	}
	switch wrapped := err.(type) {
	case *muxsession.QUICTransportCloseError, *servicestream.VisitorTLSCallbackFailure:
		return err
	case *servicestream.VisitorProtocolRefusal, *servicestream.VisitorTLSIOFailure:
		// Abort already normalized identified TLS interruptions. a retained
		// producer wrapper still contains an independent or required failure.
		if stopped == errConnectorAdmissionAbort {
			return err
		}
		if serviceWorkerError(errors.Unwrap(err), stopped) == nil {
			return nil
		}
	case interface{ Unwrap() []error }:
		var failures []error
		for _, cause := range wrapped.Unwrap() {
			failures = append(failures, serviceWorkerError(cause, stopped))
		}
		return errors.Join(failures...)
	case interface{ Unwrap() error }:
		if serviceWorkerError(wrapped.Unwrap(), stopped) == nil {
			return nil
		}
	}
	return err
}

// compose relay trust once for the run, independently of target and visitor TLS.
// supplied connectors must preserve certificate verification for the assigned
// server name even when they redirect the dial address to a local fixture.
func (config RunConfig) connectionOptions(dialer muxsession.QUICDialer, udpErr error) (ConnectOptions, error) {
	roots := config.TransportTLS
	if roots == nil {
		roots = &tls.Config{MinVersion: tls.VersionTLS13}
	} else {
		if roots.InsecureSkipVerify {
			return ConnectOptions{}, ErrPrivateStream
		}
		roots = roots.Clone()
		roots.MinVersion = max(roots.MinVersion, tls.VersionTLS13)
	}
	options := ConnectOptions{QUIC: config.RelayQUIC, WebSocket: config.RelayWebSocket, PreferWebSocket: config.WebSocketOnly}
	if peer.HostUDP && options.QUIC == nil {
		if udpErr != nil {
			options.QUIC = muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) { return nil, udpErr })
		} else {
			options.QUIC = muxsession.QUICConnector{TLSConfig: roots, Config: muxsession.QUICConfig{Config: &quic.Config{EnableDatagrams: true}}, Dialer: dialer}
		}
	}
	if options.WebSocket == nil {
		options.WebSocket = muxsession.WebSocketConnector{TLSConfig: roots}
	}
	return options, nil
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
	var last error
	canceled := func() error {
		cause := context.Cause(ctx)
		if last == nil || failure.Only(last, ctx.Err()) || failure.Only(last, cause) {
			return cause
		}
		return errors.Join(cause, last)
	}
	for {
		if ctx.Err() != nil {
			return canceled()
		}
		err := operation(ctx)
		last = err
		if err == nil || !transientControlError(err) {
			return err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return canceled()
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
