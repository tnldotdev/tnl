package stream

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/serviceendpoint"
	"github.com/tnldotdev/tnl/internal/security/tlspolicy"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	telemetryv1 "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type preparedOpening struct {
	entry tunnelv1.ConnectorPeerVisitorEntry
	until time.Time
}

type connectorUse struct {
	entry       tunnelv1.ConnectorPeerVisitorEntry
	prepared    *PreparedConnector
	until       time.Time
	terminalKey tunnelv1.ConnectorVisitorTerminalKey
	admitted    bool
}

type connectorPath struct {
	leg                        *connectorRelayLeg
	carrier                    *peer.CarrierSlot
	inspected, needsInspection bool
	probeAfter                 time.Time
}

// connectorConnection owns one selected run and retained inner QUIC connection.
// background workers own authority renewal and proof generation;
// local arrivals consume immutable signed openings and never call control.
type connectorConnection struct {
	ctx             context.Context
	cancel          context.CancelCauseFunc
	packetCtx       context.Context
	packetCancel    context.CancelCauseFunc
	cleanup         *connectorCleanup
	retirement      *connectorRetirement
	parentStop      func() bool
	parentDone      chan struct{}
	packetStopOnce  sync.Once
	packetStop      func() bool
	packetStopDone  chan struct{}
	closing         bool
	closeErr        error
	config          Config
	signer          Signer
	owner           string
	endpoint        *peer.Endpoint
	socket          *peer.Socket
	ownedSocket     bool
	connectivity    *peer.Connectivity
	transport       *quic.Transport
	udpTransport    *muxsession.QUICTransport
	connection      *quic.Conn
	session         muxsession.Session
	permissions     *tunnel.ConnectorPermissionWriter
	mu              sync.Mutex
	run             Run
	pair            controlv1.ConnectorPeerPair
	until           time.Time
	preparedUntil   time.Time
	reportedUntil   time.Time
	source          string
	permission      controlv1.VisitorTokenResponse
	paths           [2]connectorPath
	key             [32]byte
	openings        []preparedOpening
	active          map[*connectorUse]struct{}
	warm            *connectorUse
	changed         chan struct{}
	refill          chan struct{}
	recover         chan struct{}
	recoveryState   connectorRecoveryState
	recoveryStarted time.Time
	rebind          *connectorRebindOperation
	inspection      *connectorRebindPhase
	highWater       int64
	bindingCtx      context.Context
	bindingCancel   context.CancelFunc
	legUses         sync.WaitGroup
	workers         sync.WaitGroup
	servingWorkers  sync.WaitGroup
	uses            sync.WaitGroup
	useErr          error
	once            sync.Once
}

func connectorTemporary(err error) bool {
	if classified, retry := connectorClassifiedTemporary(err); classified {
		return retry
	}
	if joined, retry := connectorJoinedTemporary(err); joined {
		return retry
	}
	var network net.Error
	return errors.As(err, &network) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// an explicit operation reason classifies its diagnostic causes. another typed
// denial or owned cleanup failure still vetoes retry, regardless of tree order.
func connectorClassifiedTemporary(err error) (classified, retry bool) {
	retry = true
	var visit func(error)
	visit = func(err error) {
		switch cause := err.(type) {
		case *CleanupError, *tunnel.SessionCleanupError, *muxsession.QUICTransportCloseError, *connectorLegAttemptError:
			classified, retry = true, false
			return
		case *tunnel.ProtocolError:
			classified = true
			retry = retry && cause.Code == tunnelv1.Unavailable
			return
		case *clientcontrol.ProblemError:
			if cause.Status == http.StatusUnauthorized || cause.Status == http.StatusForbidden {
				classified, retry = true, false
			}
		case *failure.Error:
			definition, _ := failure.DefinitionFor(cause.Reason())
			classified = true
			retry = retry && definition.Retry == failure.RetryLater
		case interface{ FailureReason() failure.Reason }:
			if definition, ok := failure.DefinitionFor(cause.FailureReason()); ok {
				classified = true
				retry = retry && definition.Retry == failure.RetryLater
			}
		}
		switch cause := err.(type) {
		case interface{ Unwrap() []error }:
			for _, child := range cause.Unwrap() {
				visit(child)
			}
		case interface{ Unwrap() error }:
			visit(cause.Unwrap())
		}
	}
	visit(err)
	return classified, retry
}

// a retryable network leaf cannot hide an independent joined failure.
func connectorJoinedTemporary(err error) (bool, bool) {
	switch cause := err.(type) {
	case interface{ Unwrap() []error }:
		children := cause.Unwrap()
		if len(children) == 0 {
			return true, false
		}
		for _, child := range children {
			if !connectorTemporary(child) {
				return true, false
			}
		}
		return true, true
	case interface{ Unwrap() error }:
		return connectorJoinedTemporary(cause.Unwrap())
	}
	return false, false
}

// inspect each node before its children: typed failures can be childless, and
// an EOF or cancellation inside failed cleanup never permits another attempt.
func connectorRetryVeto(err error) bool {
	switch cause := err.(type) {
	case *CleanupError, *tunnel.SessionCleanupError, *muxsession.QUICTransportCloseError:
		return true
	case *tunnel.ProtocolError:
		if connectorProtocolDisposition(cause.Code) == terminateConnection {
			return true
		}
	case *clientcontrol.ProblemError:
		if cause.Status == http.StatusUnauthorized || cause.Status == http.StatusForbidden {
			return true
		}
	case *failure.Error:
		definition, ok := failure.DefinitionFor(cause.Reason())
		if !ok || definition.Retry != failure.RetryLater {
			return true
		}
	case interface{ FailureReason() failure.Reason }:
		if definition, ok := failure.DefinitionFor(cause.FailureReason()); ok && definition.Retry != failure.RetryLater {
			return true
		}
	}
	switch cause := err.(type) {
	case interface{ Unwrap() []error }:
		for _, child := range cause.Unwrap() {
			if connectorRetryVeto(child) {
				return true
			}
		}
	case interface{ Unwrap() error }:
		return connectorRetryVeto(cause.Unwrap())
	}
	return false
}

// an owned operation may also receive capacity rejection. unlike the legacy
// reconnect scan, every independent child must permit retry.
func connectorAttemptTemporary(err error) bool {
	if err == nil || connectorRetryVeto(err) {
		return false
	}
	switch cause := err.(type) {
	case *tunnel.ProtocolError:
		return connectorProtocolDisposition(cause.Code) == retryAttempt
	}
	switch cause := err.(type) {
	case interface{ Unwrap() []error }:
		children := cause.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !connectorAttemptTemporary(child) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		if child := cause.Unwrap(); child != nil {
			return connectorAttemptTemporary(child)
		}
	}
	return connectorTemporary(err)
}

func connectorOwnedCancellationOnly(err, cause error) bool {
	if err == nil {
		return true
	}
	if connectorRetryVeto(err) {
		return false
	}
	if attempt, ok := err.(*connectorLegAttemptError); ok {
		if attempt.count == 0 || attempt.cleanup != nil || !connectorOwnedCancellationOnly(attempt.context, cause) {
			return false
		}
		stopped := false
		for _, candidate := range attempt.candidates[:attempt.count] {
			if candidate.stage != connectorAttemptConnect && candidate.stage != connectorAttemptHello && candidate.stage != connectorAttemptActivation ||
				candidate.cleanup != nil {
				return false
			}
			if candidate.stage == connectorAttemptConnect && candidate.cause == muxsession.ErrConnectorDisabled {
				continue
			}
			observed := candidate.stage == connectorAttemptHello && tunnel.ConnectorHelloStopped(candidate.cause, cause) ||
				candidate.stage == connectorAttemptActivation && tunnel.ConnectorActivationStopped(candidate.cause, cause)
			if !observed && !connectorOwnedCancellationOnly(candidate.cause, cause) {
				return false
			}
			stopped = true
		}
		return stopped
	}
	if failure.Only(err, cause) || failure.Only(err, context.Canceled) {
		return true
	}
	switch wrapped := err.(type) {
	case interface{ Unwrap() []error }:
		children := wrapped.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !connectorOwnedCancellationOnly(child, cause) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		if child := wrapped.Unwrap(); child != nil {
			return connectorOwnedCancellationOnly(child, cause)
		}
	}
	return false
}

// only an idle maintenance guard produces this observation of its exact owner.
// a received reply, entered call, or joined failure never acquires this marker.
type connectorIdleLegStop struct {
	owner    *connectorConnection
	lifetime context.Context
}

func (e *connectorIdleLegStop) Error() string { return e.Unwrap().Error() }
func (e *connectorIdleLegStop) Unwrap() error { return context.Cause(e.lifetime) }

func (p *connectorConnection) idleLegStop() error {
	return &connectorIdleLegStop{owner: p, lifetime: p.ctx}
}

func (p *connectorConnection) recordLegRecoveryFailure(err, canceled error) {
	if stopped, ok := err.(*connectorIdleLegStop); ok && stopped != nil &&
		stopped.owner == p && stopped.lifetime == p.ctx && p.ctx.Err() != nil {
		return
	}
	if connectorOwnedCancellationOnly(err, canceled) {
		return
	}
	// the owned disposition already distinguished cancellation from cleanup.
	// retain typed cleanup even when its underlying close returned Canceled.
	p.mu.Lock()
	p.useErr = errors.Join(p.useErr, err)
	p.mu.Unlock()
}

func prepareConnectorConnection(ctx, setup context.Context, config Config, signer Signer) (_ *connectorConnection, result error) {
	config.telemetry = config.Telemetry.BeginScope("connector")
	config.Connectivity = config.telemetry.Connectivity(config.Connectivity)
	life, cancelServing := context.WithCancelCause(context.WithoutCancel(ctx))
	packetLife, cancelPackets := context.WithCancelCause(context.WithoutCancel(ctx))
	if config.cleanup == nil {
		config.cleanup = newConnectorCleanup(ctx, config.CleanupContext)
	}
	p := &connectorConnection{ctx: life, packetCtx: packetLife, packetCancel: cancelPackets, cleanup: config.cleanup,
		config: config, signer: signer, changed: make(chan struct{}), refill: make(chan struct{}, 1), recover: make(chan struct{}, 1),
		active: make(map[*connectorUse]struct{}), parentDone: make(chan struct{}), packetStopDone: make(chan struct{})}
	cancel := func(cause error) {
		p.cleanup.begin()
		cancelServing(cause)
		cleanup := p.cleanup.context()
		p.packetStopOnce.Do(func() {
			p.packetStop = context.AfterFunc(cleanup, func() { defer close(p.packetStopDone); cancelPackets(context.Cause(cleanup)) })
		})
	}
	p.cancel = cancel
	p.parentStop = context.AfterFunc(ctx, func() { defer close(p.parentDone); cancel(context.Cause(ctx)) })
	// stopping serving fences new leg work, but an entered renewal must not
	// destroy its packet carrier merely because its reply is still in flight.
	p.bindingCtx, p.bindingCancel = context.WithCancel(packetLife)
	stage := "owner"
	defer func() {
		if result != nil {
			result = fmt.Errorf("prepare connector %s: %w", stage, errors.Join(result, p.Close(p.cleanup.context())))
		}
	}()
	if !config.Connectivity.DisableDirect {
		p.socket = config.PeerSocket
		if p.socket == nil {
			// inability to open UDP must not prevent TLS/TCP relay delivery.
			p.socket, _ = peer.ListenSocket(packetLife, "udp", ":0")
			p.ownedSocket = p.socket != nil
		}
		if p.socket != nil && config.RelayQUIC == nil {
			config.RelayQUIC = muxsession.QUICConnector{TLSConfig: config.TransportTLS, Dialer: p.socket, Config: muxsession.QUICConfig{Config: &quic.Config{EnableDatagrams: true}}}
		}
		p.config = config
	}
	p.owner, result = opaqueid.New(opaqueid.IdempotencyPrefix)
	if result != nil {
		return nil, result
	}
	stage = "service selection"
	p.run, result = config.Control.ResolveService(setup, config.ServiceID)
	if result != nil {
		return nil, result
	}
	if result = validateConnectorRun(config, p.run); result != nil {
		return nil, result
	}
	p.run.ServiceTLS = config.ServiceTLS
	var create controlv1.ConnectorPeerPairRequest
	var key [32]byte
	stage = "pair"
	p.pair, key, p.until, create, result = prepareConnectorPair(setup, config.Control, signer, p.run, p.owner)
	if p.pair.PairId != "" {
		captureErr := p.captureRetirement(p.pair)
		result = errors.Join(result, captureErr)
		if result == nil {
			p.cleanup.observe(earliestConnectorDeadline(p.until, p.run.ValidUntil))
		}
	}
	if result != nil {
		return nil, result
	}
	setup, stopAuthority := context.WithDeadline(setup, p.until)
	defer stopAuthority()
	var results [2]error
	var starts sync.WaitGroup
	stage = "relay legs"
	if config.RelayQUIC == nil {
		transport, udpErr := muxsession.ListenQUICTransport("udp", ":0")
		if udpErr == nil {
			p.udpTransport = transport
			config.RelayQUIC = muxsession.QUICConnector{TLSConfig: config.TransportTLS, Config: muxsession.QUICConfig{Config: &quic.Config{EnableDatagrams: true}}, Dialer: transport}
		} else {
			config.RelayQUIC = muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) { return nil, udpErr })
		}
	}
	p.config = config
	for slot := range 2 {
		starts.Go(func() {
			p.paths[slot].leg, results[slot] = connectConnectorLeg(setup, packetLife, config, signer, p.pair, key, slot)
		})
	}
	starts.Wait()
	if result = errors.Join(results[:]...); result != nil {
		return nil, result
	}
	if p.paths[0].leg.receipt.SourceIP != p.paths[1].leg.receipt.SourceIP {
		return nil, ErrServiceConnection
	}
	p.source = p.paths[0].leg.receipt.SourceIP
	stage = "publisher installation"
	if p.preparedUntil, p.reportedUntil, result = awaitConnectorPublisher(setup, config.Control, p.run.ServiceID, create, p.pair); result != nil {
		return nil, result
	}
	p.key = key
	p.highWater = p.pair.DeliveryGeneration
	stage = "packet carriers"
	for slot := range 2 {
		path := &p.paths[slot]
		path.carrier = peer.NewCarrierSlot()
		if result = path.carrier.Install(connectorLegCarrier{path.leg}); result != nil {
			return nil, result
		}
	}
	frameKey, result := connectorPairSecret(p.pair.SessionKey)
	if result != nil {
		return nil, result
	}
	initialBinding := connectorBindingRevision(p.pair)
	var direct *peer.CarrierSlot
	if p.socket != nil {
		direct = peer.NewCarrierSlot()
	}
	p.endpoint, result = peer.New(packetLife, peer.Config{Key: frameKey, Role: 0, Paths: [2]peer.Carrier{p.paths[0].carrier, p.paths[1].carrier}, Direct: direct, Binding: initialBinding})
	if result != nil {
		return nil, result
	}
	stage = "packet paths"
	if result = awaitConnectorPaths(setup, p.endpoint); result != nil {
		return nil, result
	}
	p.transport = &quic.Transport{Conn: p.endpoint}
	trust := tlspolicy.RequirePostQuantum(config.ServiceTLS)
	trust.ServerName, trust.NextProtos = p.run.Endpoint.Hostname, []string{muxsession.ALPN}
	innerConfig := tunnel.ConnectorQUICConfig()
	innerConfig.MaxIncomingStreams = -1
	stage = "inner TLS"
	p.connection, result = p.transport.Dial(setup, p.endpoint.RemoteAddr(), trust, innerConfig)
	if result != nil {
		return nil, failure.Wrap("prepare connector peer TLS", failure.ConnectionTLSRejected, result)
	}
	p.session, result = muxsession.AdoptQUIC(p.connection)
	if result != nil {
		return nil, result
	}
	stage = "permission control"
	scope := tunnelv1.ConnectorControlScope{ServiceID: p.pair.ServiceId, ServiceRunID: p.pair.ServiceRunId, RunNumber: uint64(p.pair.RunNumber), PublisherIdentityID: p.pair.PublisherIdentityId, PairID: p.pair.PairId}
	p.permissions, result = tunnel.OpenConnectorPermissionControl(packetLife, setup, p.session, scope)
	if result != nil {
		return nil, result
	}
	p.workers.Go(func() {
		<-p.permissions.Done()
		// match session retirement while preserving the transport cause. an
		// earlier authority failure remains the context's first cancellation cause.
		p.cancel(fmt.Errorf("connector permission owner ended: %w", errors.Join(ErrServiceConnection, p.permissions.Err())))
	})
	stage = "visitor permission"
	p.permission, result = config.Control.VisitorPermission(setup, config.ServiceID)
	if result != nil || setup.Err() != nil {
		return nil, errors.Join(ErrServiceConnection, result, context.Cause(setup))
	}
	if result = validateConnectorPermissionMetadata(config, p.permission); result != nil {
		return nil, result
	}
	if !validConnectorPermission(p.run, p.permission) {
		return nil, ErrServiceConnection
	}
	p.cleanup.observe(earliestConnectorDeadline(p.until, p.run.ValidUntil, p.permission.ExpiresAt))
	stage = "application openings"
	if result = p.fillOpenings(); result != nil {
		return nil, result
	}
	// the first TCP stream belongs to the actual ready pool, not a disposable
	// readiness probe. server-first protocols keep their negotiation app-owned.
	if config.Protocol == "tcp" {
		p.mu.Lock()
		opening := p.openings[0]
		p.openings = p.openings[1:]
		p.mu.Unlock()
		preparedRun := p.run
		preparedRun.ValidUntil = earliestConnectorDeadline(preparedRun.ValidUntil, p.until, opening.until)
		use := &connectorUse{entry: opening.entry, until: opening.until, terminalKey: connectorTerminalKey(opening.entry)}
		p.warm = use
		p.active[use] = struct{}{}
		prepared, err := prepareConnector(life, setup, p.session, preparedRun, opening.entry, func() { use.admitted = true })
		use.prepared = prepared
		if err != nil {
			return nil, err
		}
	}
	if setup.Err() != nil || !p.currentLocked() {
		return nil, errors.Join(ErrServiceConnection, context.Cause(setup))
	}
	if p.socket != nil {
		p.connectivity = peer.NewConnectivity(p.socket, p.connection, p.endpoint, true, config.Connectivity, p.admitDirectPacket)
		p.connectivity.SetBinding(connectorConnectivityBinding(p.pair))
	}
	p.servingWorkers.Go(p.watch)
	p.servingWorkers.Go(p.refresh)
	p.servingWorkers.Go(func() {
		for {
			select {
			case <-life.Done():
				return
			case <-p.refill:
				if err := p.fillOpenings(); err != nil {
					cancel(fmt.Errorf("refill connector openings: %w", err))
					return
				}
			}
		}
	})
	for slot := range 2 {
		p.servingWorkers.Go(func() { p.maintainLeg(slot) })
	}
	if p.socket != nil {
		p.workers.Go(func() {
			if err := p.connectivity.Serve(packetLife); err != nil && packetLife.Err() == nil {
				p.cancel(err)
			}
		})
	}
	return p, nil
}

func awaitConnectorPaths(ctx context.Context, endpoint *peer.Endpoint) error {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		if endpoint.PathHealthy(peer.RelayA) && endpoint.PathHealthy(peer.RelayB) {
			return nil
		}
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-ticker.C:
		}
	}
}

func validateConnectorRun(config Config, run Run) error {
	if run.ServiceID != config.ServiceID || !opaqueid.Valid(run.ServiceRunID, opaqueid.ServiceRunPrefix) || run.RunNumber == 0 || !run.ValidUntil.After(time.Now()) || run.PairReady != nil && len(run.PairReady.Relays) != 2 ||
		run.Endpoint == nil || !serviceendpoint.Valid(run.Protocol, run.Endpoint.Hostname, run.Endpoint.Port, run.Endpoint.Public) {
		return ErrServiceConnection
	}
	if run.Protocol != config.Protocol || run.TrustRevision != config.TrustRevision || !sameEndpoint(run.Endpoint, config.Endpoint) {
		return metadataReload(config.ServiceID, config.TrustRevision, run.TrustRevision)
	}
	return nil
}

func validConnectorPermission(run Run, permission controlv1.VisitorTokenResponse) bool {
	return permission.Resource.Kind == controlv1.VisitorResourceScopeKindService && permission.Resource.Id == run.ServiceID && run.Endpoint != nil && permission.Hostname == run.Endpoint.Hostname && permission.Port == int(serviceendpoint.PermissionPort(run.Protocol)) && permission.VisitorToken != "" && permission.ExpiresAt.After(time.Now())
}

func validateConnectorPermissionMetadata(config Config, permission controlv1.VisitorTokenResponse) error {
	if permission.Resource.Kind != controlv1.VisitorResourceScopeKindService || permission.Resource.Id != config.ServiceID || permission.ServiceTrustRevision == nil || *permission.ServiceTrustRevision < 1 {
		return ErrServiceConnection
	}
	if *permission.ServiceTrustRevision != config.TrustRevision {
		return metadataReload(config.ServiceID, config.TrustRevision, *permission.ServiceTrustRevision)
	}
	return nil
}

func (p *connectorConnection) currentLocked() bool {
	return p.ownerCurrentLocked() && p.recoveryState != connectorRebinding && p.preparedUntil.After(time.Now())
}

func (p *connectorConnection) ownerCurrentLocked() bool {
	return p.ownerErrorLocked() == nil
}

// local entry guards snapshot the stop cause before starting work. a received
// operation or authority failure must never be reclassified through this guard.
func (p *connectorConnection) ownerErrorLocked() error {
	if cause := context.Cause(p.ctx); cause != nil {
		return cause
	}
	if p.closing || !p.authorityCurrentLocked(time.Now()) {
		return ErrServiceConnection
	}
	return nil
}

func (p *connectorConnection) notifyLocked() { close(p.changed); p.changed = make(chan struct{}) }

func connectorOpening(signer Signer, entry tunnelv1.ConnectorPeerVisitorEntry, token string) (tunnelv1.ConnectorPeerVisitorEntry, error) {
	entry.Permission = tunnelv1.ConnectorVisitorPermission{Token: token, PublicKey: base64.RawURLEncoding.EncodeToString(signer.PublicKey), Signature: base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))}
	message, err := tunnelv1.ConnectorPeerProofMessage(entry, nil)
	if err != nil {
		return entry, err
	}
	signature := signer.Sign(message)
	if !ed25519.Verify(signer.PublicKey, message, signature) {
		return entry, ErrServiceConnection
	}
	entry.Permission.Signature = base64.RawURLEncoding.EncodeToString(signature)
	return entry, nil
}

func (p *connectorConnection) fillOpenings() error {
	p.mu.Lock()
	if p.recoveryState == connectorRebinding {
		p.mu.Unlock()
		return nil
	}
	if !p.currentLocked() {
		p.mu.Unlock()
		return ErrServiceConnection
	}
	count := 64 - len(p.openings)
	run, pair, permission, source := p.run, p.pair, p.permission, p.source
	p.mu.Unlock()
	entries, err := prepareConnectorOpenings(p.signer, run, pair, permission, source, count)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.currentLocked() || p.permission.VisitorToken != permission.VisitorToken || p.pair.DeliveryGeneration != pair.DeliveryGeneration || p.source != source {
		return nil // a newer background refresh owns the next pool.
	}
	p.openings = append(p.openings, entries[:min(len(entries), 64-len(p.openings))]...)
	return nil
}

func prepareConnectorOpenings(signer Signer, run Run, pair controlv1.ConnectorPeerPair, permission controlv1.VisitorTokenResponse, source string, count int) ([]preparedOpening, error) {
	entries := make([]preparedOpening, 0, count)
	for range count {
		visitor, err := opaqueid.New(opaqueid.VisitorConnectionPrefix)
		if err != nil {
			return nil, err
		}
		entry, err := connectorOpening(signer, tunnelv1.ConnectorPeerVisitorEntry{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ConnectorPeerVisitorStream, PairID: pair.PairId, DeliveryID: pair.DeliveryId, DeliveryGeneration: pair.DeliveryGeneration,
			ServiceID: run.ServiceID, ServiceRunID: run.ServiceRunID, RunNumber: run.RunNumber, Subject: signer.Subject, SourceIP: source, VisitorConnectionID: visitor, MetadataRevision: uint64(run.TrustRevision)}, permission.VisitorToken)
		if err != nil {
			return nil, err
		}
		entries = append(entries, preparedOpening{entry, permission.ExpiresAt})
	}
	return entries, nil
}

func (p *connectorConnection) watch() {
	for {
		p.mu.Lock()
		until := earliestConnectorDeadline(p.until, p.run.ValidUntil, p.permission.ExpiresAt)
		current := p.ownerCurrentLocked()
		expiredDelivery := current && p.recoveryState != connectorRebinding && !p.preparedUntil.After(time.Now())
		if p.recoveryState != connectorRebinding {
			until = earliestConnectorDeadline(until, p.preparedUntil)
		}
		changed := p.changed
		var stopCause error
		if !current {
			cause := context.Cause(p.ctx)
			if cause == nil && p.permissions != nil {
				if err := p.permissions.Err(); err != nil {
					// watch may retire the owner before its permission worker runs.
					cause = fmt.Errorf("connector permission owner ended: %w", errors.Join(ErrServiceConnection, err))
				}
			}
			if cause == nil {
				authority := earliestConnectorDeadline(p.until, p.run.ValidUntil, p.permission.ExpiresAt)
				if !authority.After(time.Now()) {
					cause = &connectorAuthorityExpiry{owner: p, until: authority}
				} else {
					cause = ErrServiceConnection
				}
			}
			p.cleanup.begin()
			stopCause = cause
		}
		p.mu.Unlock()
		if stopCause != nil {
			p.cancel(stopCause)
		}
		if expiredDelivery {
			p.requestRecovery(connectorRebinding)
			continue
		}
		timer := time.NewTimer(time.Until(until))
		select {
		case <-p.ctx.Done():
			timer.Stop()
			return
		case <-p.session.Done():
			timer.Stop()
			cause := p.session.Err()
			if p.permissions != nil {
				// a terminal permission read may reset its stream and cause remote
				// session closure before the permission notification worker runs.
				cause = errors.Join(cause, p.permissions.Err())
			}
			p.cancel(fmt.Errorf("connector inner session ended: %w", errors.Join(ErrServiceConnection, cause)))
			return
		case <-changed:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func earliestConnectorDeadline(values ...time.Time) time.Time {
	until := values[0]
	for _, value := range values[1:] {
		if value.Before(until) {
			until = value
		}
	}
	return until
}

func (p *connectorConnection) refresh() {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	lastAuthority := time.Now()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
		case <-p.recover:
		}
		if result := p.recoverBinding(); result.err != nil {
			if cause := context.Cause(p.ctx); cause != nil {
				p.recordLegRecoveryFailure(result.err, cause)
				return
			}
			if !result.retry {
				p.cancel(fmt.Errorf("recover connector binding: %w", result.err))
				return
			}
		}
		p.mu.Lock()
		activationUncertain := p.rebind != nil && p.rebind.activate != nil
		authorityDelay := connectorAuthorityRefreshDelay(time.Until(p.preparedUntil))
		p.mu.Unlock()
		// an activation may have committed while its reply was lost. resolve
		// that exact phase before renewing with the old delivery generation;
		// the existing owner deadline remains fixed throughout this wait.
		if !activationUncertain && !lastAuthority.Add(authorityDelay).After(time.Now()) {
			lastAuthority = time.Now()
			if err := p.refreshAuthority(); err != nil {
				p.mu.Lock()
				pending := p.rebind != nil
				p.mu.Unlock()
				if !connectorTemporary(err) && !(pending && connectorPhaseConflict(err)) && p.ctx.Err() == nil {
					p.cancel(fmt.Errorf("renew connector authority: %w", err))
					return
				}
			}
		}
	}
}

// a lost phase reply can leave only a short conservative installation interval.
// observe fresh publisher confirmation before that fence instead of letting the
// normal two-second polling interval consume it. polling never renews a fence by
// itself, and the coordinator still owns at most one authority request at a time.
func connectorAuthorityRefreshDelay(remaining time.Duration) time.Duration {
	return min(2*time.Second, max(250*time.Millisecond, remaining/4))
}

// the coordinator is the only writer of refreshed authority and network binding
// state. neither leg recovery nor application arrival can run a second mutation.
func (p *connectorConnection) refreshAuthority() error {
	p.mu.Lock()
	run, previous, until := p.run, p.pair, p.until
	p.mu.Unlock()
	call, stop := context.WithDeadline(p.ctx, minConnectorCall(until))
	renewal, bound, err := renewConnectorPair(call, p.config.Control, p.signer, run, p.owner, previous)
	pair, permission, next := renewal.Pair, renewal.VisitorPermission, run
	if err == nil {
		if pair.ObservedAt.Equal(previous.ObservedAt) {
			bound = earliestConnectorDeadline(bound, until.Add(min(0, pair.ExpiresAt.Sub(previous.ExpiresAt))))
		}
		if !pair.ExpiresAt.After(previous.ExpiresAt) {
			bound = earliestConnectorDeadline(bound, until)
		}
		// all returned intervals share one authority observation. anchor each
		// at request start so RPC transit and background signing spend them.
		next.ValidUntil = bound.Add(renewal.RunValidUntil.Sub(pair.ExpiresAt))
		next.Protocol, next.TrustRevision, next.Endpoint = string(renewal.Protocol), renewal.TrustRevision, &renewal.Endpoint
		permission.ExpiresAt = bound.Add(permission.ExpiresAt.Sub(pair.ExpiresAt))
		err = validateConnectorPermissionMetadata(p.config, permission)
	}
	if err == nil {
		err = validateConnectorRun(p.config, next)
	}
	if err == nil {
		err = context.Cause(call)
	}
	if err != nil {
		stop()
		return fmt.Errorf("renew connector pair: %w", err)
	}
	// keep the previous ready pool behind its original authority fence while
	// background signing prepares the replacement. arrivals never see an empty
	// refresh gap and never perform this control or signing work themselves.
	openings, err := prepareConnectorOpenings(p.signer, next, pair, permission, p.source, 64)
	if err == nil {
		err = context.Cause(call)
	}
	stop()
	if err != nil {
		return fmt.Errorf("prepare connector renewal openings: %w", err)
	}
	p.mu.Lock()
	preparedUntil, reportedUntil := p.preparedUntil, p.reportedUntil
	if reported := pair.PublisherPreparedUntil; reported != nil {
		candidate := bound.Add(reported.Sub(pair.ExpiresAt))
		if reported.After(reportedUntil) {
			preparedUntil = candidate
			reportedUntil = *reported
		} else {
			// a narrowed pair cap cannot make an older installation report
			// fresh again when a later pair renewal restores that cap.
			preparedUntil = earliestConnectorDeadline(preparedUntil, candidate)
		}
	}
	now := time.Now()
	expiredDelivery := !p.preparedUntil.After(now) || !preparedUntil.After(now)
	paused := p.recoveryState == connectorRebinding || expiredDelivery
	if expiredDelivery {
		preparedUntil = earliestConnectorDeadline(preparedUntil, p.preparedUntil)
		reportedUntil = p.reportedUntil
	}
	if !p.ownerCurrentLocked() || !bound.After(now) || !next.ValidUntil.After(now) || !permission.ExpiresAt.After(now) {
		p.mu.Unlock()
		return fmt.Errorf("install connector renewal after authority expired: %w", ErrServiceConnection)
	}
	next.ServiceTLS = p.config.ServiceTLS
	// pair renewal is not publisher installation renewal. retain only a
	// current, independently reported installation deadline on this owner.
	p.preparedUntil, p.reportedUntil = preparedUntil, reportedUntil
	p.run, p.pair, p.until, p.permission = next, pair, bound, permission
	p.cleanup.observe(earliestConnectorDeadline(bound, next.ValidUntil, permission.ExpiresAt))
	if !paused {
		p.openings = openings
	}
	active := make([]*connectorUse, 0, len(p.active))
	for stream := range p.active {
		if stream.prepared != nil {
			active = append(active, stream)
		}
	}
	p.notifyLocked()
	p.mu.Unlock()
	if expiredDelivery {
		p.requestRecovery(connectorRebinding)
	}
	if !paused {
		p.renewActive(active, permission, earliestConnectorDeadline(bound, next.ValidUntil, permission.ExpiresAt))
	}
	return nil
}

func (p *connectorConnection) renewActive(active []*connectorUse, permission controlv1.VisitorTokenResponse, bound time.Time) {
	// signing stays off the arrival path. independent submissions retain #525's
	// isolation, but never write or change deadlines on an application stream.
	var renewals sync.WaitGroup
	for _, stream := range active {
		renewals.Go(func() {
			p.mu.Lock()
			previous := stream.entry
			p.mu.Unlock()
			entry, err := connectorOpening(p.signer, previous, permission.VisitorToken)
			if err == nil {
				err = stream.prepared.queuePermission(preparedPermissionRenewal{writer: p.permissions, update: tunnelv1.ConnectorPermissionUpdate{VisitorConnectionID: entry.VisitorConnectionID, DeliveryGeneration: entry.DeliveryGeneration, Permission: entry.Permission}, until: bound})
			}
			if err != nil {
				_ = stream.prepared.Close()
			}
		})
	}
	renewals.Wait()
}

func minConnectorCall(until time.Time) time.Time {
	return earliestConnectorDeadline(until, time.Now().Add(2*time.Second))
}

func (p *connectorConnection) maintainLeg(slot int) {
	for {
		p.mu.Lock()
		leg, changed, binding := p.paths[slot].leg, p.changed, p.bindingCtx
		paused := p.recoveryState != connectorBindingReady
		registered := !paused && p.ctx.Err() == nil
		if registered {
			p.legUses.Add(1)
		}
		p.mu.Unlock()
		if p.ctx.Err() != nil {
			if registered {
				p.legUses.Done()
			}
			return
		}
		if paused {
			select {
			case <-p.ctx.Done():
				return
			case <-changed:
			}
			continue
		}
		disposition, err := p.maintainConnectorLeg(binding, slot, leg, changed)
		p.legUses.Done()
		if cause := context.Cause(p.ctx); cause != nil {
			p.recordLegRecoveryFailure(err, cause)
			return
		}
		if binding.Err() != nil {
			if connectorRetryVeto(err) || connectorTerminalProtocol(err) {
				p.cancel(fmt.Errorf("maintain connector leg %d: %w", slot, err))
				return
			}
			p.recordLegRecoveryFailure(err, context.Cause(binding))
			continue // the coordinator joins old work before staging replacements.
		}
		if disposition == rebindConnection || disposition == retirePath {
			p.requestRecovery(connectorRebinding)
		}
		if disposition == terminateConnection {
			p.cancel(fmt.Errorf("maintain connector leg %d: %w", slot, err))
			return
		}
	}
}

func (p *connectorConnection) maintainConnectorLeg(binding context.Context, slot int, leg *connectorRelayLeg, changed <-chan struct{}) (reconnectDisposition, error) {
	p.mu.Lock()
	inspected, probeAfter := p.paths[slot].inspected, p.paths[slot].probeAfter
	p.mu.Unlock()
	if leg.session.Err() != nil || !p.endpoint.PathHealthy(slot) && !probeAfter.After(time.Now()) {
		if !inspected {
			p.mu.Lock()
			p.paths[slot].needsInspection = true
			p.mu.Unlock()
			p.requestRecovery(connectorInspecting)
			return retryAttempt, nil
		}
		return p.reconnectLeg(binding, slot, leg)
	}
	delay := min(2*time.Second, max(100*time.Millisecond, time.Until(leg.until)/4))
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-p.ctx.Done():
		return retirePath, p.idleLegStop()
	case <-binding.Done():
		return retirePath, context.Cause(binding)
	case <-leg.session.Done():
		return retryAttempt, nil
	case <-changed:
	case <-timer.C:
	}
	p.mu.Lock()
	pair, until := p.pair, p.until
	p.mu.Unlock()
	if cause := context.Cause(p.ctx); cause != nil {
		return retirePath, p.idleLegStop()
	}
	call, stop := context.WithDeadline(binding, minConnectorCall(earliestConnectorDeadline(until, leg.until)))
	defer stop()
	var proof tunnelv1.ConnectorPairLegProof
	err := ErrServiceConnection
	if pair.Relays[slot] == leg.relay {
		proof, err = connectorLegProof(p.signer, pair, slot)
	}
	var receipt tunnelv1.ConnectorPairLegAccepted
	started := time.Now()
	if err == nil {
		request, keyErr := opaqueid.New(opaqueid.IdempotencyPrefix)
		err = keyErr
		if err == nil {
			if cause := context.Cause(p.ctx); cause != nil {
				return retirePath, p.idleLegStop()
			}
			receipt, err = leg.session.RenewConnectorLeg(call, request, proof, leg.receipt)
		}
	}
	if cause := context.Cause(p.ctx); cause != nil {
		return retirePath, errors.Join(err, cause)
	}
	if err == nil && call.Err() == nil && leg.until.After(time.Now()) {
		nextUntil := started.Add(receipt.ExpiresAt.Sub(receipt.ObservedAt))
		if !receipt.ExpiresAt.After(leg.receipt.ExpiresAt) {
			nextUntil = earliestConnectorDeadline(nextUntil, leg.until)
		}
		leg.receipt, leg.until = receipt, nextUntil
		return retryAttempt, nil
	}
	if !leg.until.After(time.Now()) || leg.session.Err() != nil {
		return p.reconnectLeg(binding, slot, leg)
	}
	return connectorReconnectError(err), err
}

func (p *connectorConnection) reconnectLeg(binding context.Context, slot int, previous *connectorRelayLeg) (reconnectDisposition, error) {
	// replacement setup is serving work, unlike an entered renewal on the
	// retained carrier. join both cancellation sources before returning.
	reconnect, cancel := context.WithCancelCause(binding)
	stopped := make(chan struct{})
	stopServing := context.AfterFunc(p.ctx, func() { defer close(stopped); cancel(context.Cause(p.ctx)) })
	defer func() {
		cancel(context.Canceled)
		if !stopServing() {
			<-stopped
		}
	}()
	binding = reconnect
	if cleanup := connectorCleanupFailure(errors.Join(p.paths[slot].carrier.Install(nil), previous.Close())); cleanup != nil {
		return terminateConnection, errors.Join(context.Cause(p.ctx), cleanup)
	}
	// retain this operation across lost hello or activation replies. each
	// candidate still carries a fresh signed proof and socket-source claim.
	replacement, err := nextConnectorLegReplacement(previous)
	if err != nil {
		return terminateConnection, err
	}
	for delay := 100 * time.Millisecond; ; delay = min(2*delay, time.Second) {
		p.mu.Lock()
		pair := p.pair
		until := earliestConnectorDeadline(previous.until, p.until, p.preparedUntil, p.run.ValidUntil, p.permission.ExpiresAt)
		current := p.currentLocked() && pair.Relays[slot] == previous.relay
		p.mu.Unlock()
		if cause := context.Cause(p.ctx); cause != nil {
			return retirePath, cause
		}
		if !current || !until.After(time.Now()) {
			return retirePath, ErrServiceConnection
		}
		call, stop := context.WithDeadline(binding, until)
		timer := time.NewTimer(delay)
		select {
		case <-call.Done():
			timer.Stop()
			stop()
			return retirePath, context.Cause(call)
		case <-timer.C:
		}
		attempt, finish := context.WithDeadline(call, minConnectorCall(until))
		next, err := prepareConnectorLeg(attempt, p.packetCtx, p.config, p.signer, pair, p.key, slot, replacement, tunnelv1.ConnectorHandoffID{})
		if err == nil {
			err = context.Cause(attempt)
		}
		finish()
		stop()
		if err != nil {
			if next != nil {
				err = errors.Join(err, connectorCleanupFailure(next.Close()))
			}
			if disposition := connectorReconnectError(err); disposition != retryAttempt {
				return disposition, err
			}
			continue
		}
		p.mu.Lock()
		current = p.currentLocked() && until.After(time.Now()) && p.pair.Relays[slot] == previous.relay
		p.mu.Unlock()
		if !current {
			closeErr := connectorCleanupFailure(next.Close())
			if closeErr != nil {
				return terminateConnection, errors.Join(ErrServiceConnection, context.Cause(p.ctx), closeErr)
			}
			if cause := context.Cause(p.ctx); cause != nil {
				return retirePath, errors.Join(cause, closeErr)
			}
			return retirePath, errors.Join(ErrServiceConnection, closeErr)
		}
		// no authority lock spans physical cancellation or joined carrier work.
		if err := p.paths[slot].carrier.Install(connectorLegCarrier{next}); err != nil {
			if cleanup := connectorCleanupFailure(next.Close()); cleanup != nil {
				return terminateConnection, errors.Join(err, cleanup)
			}
			return retirePath, err
		}
		p.mu.Lock()
		current = p.currentLocked() && until.After(time.Now())
		if current {
			p.paths[slot].leg = next
			p.paths[slot].inspected = false
			p.paths[slot].probeAfter = time.Now().Add(3 * time.Second)
		}
		p.mu.Unlock()
		if !current {
			closeErr := connectorCleanupFailure(errors.Join(p.paths[slot].carrier.Install(nil), next.Close()))
			if closeErr != nil {
				return terminateConnection, errors.Join(ErrServiceConnection, context.Cause(p.ctx), closeErr)
			}
			if cause := context.Cause(p.ctx); cause != nil {
				return retirePath, errors.Join(cause, closeErr)
			}
			return retirePath, errors.Join(ErrServiceConnection, closeErr)
		}
		return retryAttempt, nil
	}
}

type reconnectDisposition uint8

const (
	retryAttempt reconnectDisposition = iota
	retirePath
	terminateConnection
	rebindConnection
)

func connectorProtocolDisposition(code tunnelv1.ErrorCode) reconnectDisposition {
	switch code {
	case tunnelv1.Unavailable, tunnelv1.CapacityExceeded:
		return retryAttempt
	case tunnelv1.StaleConnectionAssignment, tunnelv1.StaleNetworkBinding:
		return rebindConnection
	default:
		return terminateConnection
	}
}

// a raced candidate's temporary error must not hide another candidate's
// authorization rejection. capacity can clear as the old socket joins cleanup.
func connectorReconnectError(err error) reconnectDisposition {
	if connectorRetryVeto(err) {
		return terminateConnection
	}
	if attempt, ok := err.(*connectorLegAttemptError); ok {
		return attempt.disposition(false)
	}
	terminal, stale, retryable := false, false, false
	var visit func(error)
	visit = func(err error) {
		if _, owned := err.(*connectorLegAttemptError); owned {
			// only the direct owned return carries its decision. do not promote
			// a nested attempt through an unrelated aggregate or wrapper.
			terminal = true
			return
		}
		if protocol, ok := err.(*tunnel.ProtocolError); ok {
			switch connectorProtocolDisposition(protocol.Code) {
			case retryAttempt:
				retryable = true
			case rebindConnection:
				stale = true
			default:
				terminal = true
			}
		}
		retryable = retryable || connectorTemporary(err)
		switch wrapped := err.(type) {
		case interface{ Unwrap() []error }:
			for _, cause := range wrapped.Unwrap() {
				visit(cause)
			}
		case interface{ Unwrap() error }:
			visit(wrapped.Unwrap())
		}
	}
	visit(err)
	if terminal {
		return terminateConnection
	}
	if stale {
		return rebindConnection
	}
	if retryable {
		return retryAttempt
	}
	return terminateConnection
}

func (p *connectorConnection) Forward(ctx context.Context, local net.Conn) (result error) {
	p.mu.Lock()
	if !p.currentLocked() || ctx.Err() != nil || len(p.active) >= p.config.MaxConnections && p.warm == nil {
		p.mu.Unlock()
		return ErrServiceConnection
	}
	var use *connectorUse
	run := p.run
	if p.warm != nil {
		use, p.warm = p.warm, nil
	} else {
		for len(p.openings) > 0 && !p.openings[0].until.After(time.Now()) {
			p.openings = p.openings[1:]
		}
		if len(p.openings) == 0 {
			p.mu.Unlock()
			return ErrServiceConnection
		}
		use = &connectorUse{entry: p.openings[0].entry, until: p.openings[0].until, terminalKey: connectorTerminalKey(p.openings[0].entry)}
		p.openings = p.openings[1:]
		p.active[use] = struct{}{}
	}
	p.uses.Add(1)
	entry := use.entry
	if !use.until.IsZero() {
		run.ValidUntil = earliestConnectorDeadline(run.ValidUntil, p.until, use.until)
	}
	p.mu.Unlock()
	defer p.uses.Done()
	defer func() { p.mu.Lock(); delete(p.active, use); p.mu.Unlock() }()
	select {
	case p.refill <- struct{}{}:
	default:
	}
	result = p.forwardUse(ctx, local, use, run, entry)
	if operation := stdioOperationFor(ctx); operation != nil {
		return operation.terminalUse(result, func(result error) error { return p.terminalUse(use, result) })
	}
	result = p.terminalUse(use, result)
	// a visitor's setup/copy failure is not an owner authority decision. the
	// control and authority workers still fence the owner on their own failures.
	return result
}

func (p *connectorConnection) forwardUse(ctx context.Context, local net.Conn, use *connectorUse, run Run, entry tunnelv1.ConnectorPeerVisitorEntry) (result error) {
	var closeOnce sync.Once
	var closeErr error
	closeLocal := func() error { closeOnce.Do(func() { closeErr = local.Close() }); return closeErr }
	localDone := make(chan struct{})
	stopLocal := context.AfterFunc(p.ctx, func() { defer close(localDone); _ = closeLocal() })
	defer func() {
		cleanupErr := closeLocal()
		if !stopLocal() {
			<-localDone
		}
		if use.prepared != nil {
			cleanupErr = errors.Join(cleanupErr, p.closePreparedForRetirement(use.prepared))
		}
		p.recordUseCleanup(cleanupErr)
		result = errors.Join(result, cleanupErr)
	}()
	if use.prepared == nil {
		setup, cancel := context.WithCancel(ctx)
		stopped := make(chan struct{})
		stop := context.AfterFunc(p.ctx, func() { cancel(); close(stopped) })
		defer func() {
			cancel()
			if !stop() {
				<-stopped
			}
		}()
		prepared, err := prepareConnector(p.ctx, setup, p.session, run, entry, func() {
			p.mu.Lock()
			use.admitted = true
			p.mu.Unlock()
		})
		if err != nil {
			return err
		}
		p.mu.Lock()
		use.prepared = prepared
		current := p.currentLocked()
		p.mu.Unlock()
		if !current {
			_ = prepared.Close()
			return ErrServiceConnection
		}
	}
	if operation := stdioOperationFor(ctx); operation != nil {
		if err := operation.activateWithAbort(use.prepared.stdio, func() error {
			err := p.terminalUse(use, context.Canceled)
			if failure.Only(err, context.Canceled) {
				return nil
			}
			return err
		}); err != nil {
			return err
		}
	}
	return use.prepared.Forward(ctx, &connectorLocalConn{Conn: local, close: closeLocal})
}

type connectorLocalConn struct {
	net.Conn
	close func() error
}

func (c *connectorLocalConn) Close() error { return c.close() }
func (c *connectorLocalConn) CloseWrite() error {
	if writer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return errors.ErrUnsupported
}

func (p *connectorConnection) Close(ctx context.Context) error {
	p.once.Do(func() {
		// publish the actual serving stop before closing changes currentLocked.
		// reconnect workers can then return its cause, not a synthetic failure.
		p.cancel(context.Canceled)
		p.mu.Lock()
		p.closing = true
		warm := p.warm
		p.warm = nil
		p.mu.Unlock()
		caller := ctx
		until, _ := p.cleanup.context().Deadline()
		if deadline, ok := caller.Deadline(); ok {
			until = earliestConnectorDeadline(until, deadline)
		}
		call, finish := context.WithDeadline(p.cleanup.context(), until)
		defer finish()
		ctx = call
		if cause := context.Cause(caller); cause != nil {
			finish()
			p.packetCancel(cause)
		}
		ctxDone := make(chan struct{})
		stopCaller := context.AfterFunc(caller, func() { defer close(ctxDone); finish(); p.packetCancel(context.Cause(caller)) })
		defer func() {
			if !stopCaller() {
				<-ctxDone
			}
		}()
		add := func(err error) {
			if err != nil && !muxsession.NormalSessionCloseOnly(err) {
				p.closeErr = errors.Join(p.closeErr, err)
			}
		}
		p.servingWorkers.Wait()
		if warm != nil {
			var err error
			if warm.prepared != nil {
				err = p.closePreparedForRetirement(warm.prepared)
			}
			// unused accepted preparation is genuine joined abort work.
			abortErr := p.terminalUse(warm, errors.Join(context.Canceled, err))
			if !failure.Only(abortErr, context.Canceled) {
				add(abortErr)
			}
		}
		p.uses.Wait()
		if p.retirement != nil {
			add(p.retirement.retire(ctx, p.config.Control, p.owner))
		}
		if p.session != nil {
			add(p.session.Close())
		}
		if p.permissions != nil {
			add(p.permissions.Close())
		}
		p.packetCancel(context.Canceled)
		if p.transport != nil {
			add(p.transport.Close())
		}
		if p.endpoint != nil {
			add(p.endpoint.Close())
		}
		p.workers.Wait()
		if p.ownedSocket {
			add(p.socket.Close())
		}
		if op := p.rebind; op != nil {
			for _, leg := range op.legs {
				if leg != nil {
					add(leg.Close())
				}
			}
		}
		for _, path := range p.paths {
			if path.carrier != nil {
				add(path.carrier.Close())
			}
			if path.leg != nil {
				add(path.leg.Close())
			}
		}
		if p.udpTransport != nil {
			add(p.udpTransport.Close())
		}
		if p.parentStop != nil && !p.parentStop() {
			<-p.parentDone
		}
		if p.packetStop != nil && !p.packetStop() {
			<-p.packetStopDone
		}
		p.mu.Lock()
		add(p.useErr)
		p.mu.Unlock()
		add(context.Cause(ctx))
		if !p.recoveryStarted.IsZero() && p.paths[0].leg != nil {
			outcome := telemetryv1.Canceled
			if cause := context.Cause(p.ctx); cause != nil && cause != context.Canceled {
				outcome = telemetryv1.Failed
			}
			p.config.telemetry.Record(telemetryv1.Recovery, clienttelemetry.Path(p.paths[0].leg.transport), outcome, time.Since(p.recoveryStarted))
		}
		p.config.telemetry.Close()
	})
	return p.closeErr
}
