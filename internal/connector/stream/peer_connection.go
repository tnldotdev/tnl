package stream

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/tlspolicy"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type preparedOpening struct {
	entry tunnelv1.ConnectorPeerVisitorEntry
	until time.Time
}

type connectorUse struct {
	entry    tunnelv1.ConnectorPeerVisitorEntry
	prepared *PreparedConnector
	until    time.Time
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
	ctx           context.Context
	cancel        context.CancelCauseFunc
	config        Config
	signer        Signer
	owner         string
	endpoint      *peer.Endpoint
	transport     *quic.Transport
	connection    *quic.Conn
	session       muxsession.Session
	permissions   *tunnel.ConnectorPermissionWriter
	mu            sync.Mutex
	run           Run
	pair          controlv1.ConnectorPeerPair
	until         time.Time
	preparedUntil time.Time
	reportedUntil time.Time
	source        string
	permission    controlv1.VisitorTokenResponse
	paths         [2]connectorPath
	key           [32]byte
	openings      []preparedOpening
	active        map[*connectorUse]struct{}
	warm          *connectorUse
	changed       chan struct{}
	refill        chan struct{}
	recover       chan struct{}
	recoveryState connectorRecoveryState
	rebind        *connectorRebindOperation
	inspection    *connectorRebindPhase
	highWater     int64
	bindingCtx    context.Context
	bindingCancel context.CancelFunc
	legUses       sync.WaitGroup
	workers       sync.WaitGroup
	uses          sync.WaitGroup
	once          sync.Once
}

func connectorTemporary(err error) bool {
	var protocol *tunnel.ProtocolError
	if errors.As(err, &protocol) {
		return protocol.Code == tunnelv1.Unavailable
	}
	if _, definition, ok := failure.Describe(err); ok {
		return definition.Retry == failure.RetryLater
	}
	var network net.Error
	return errors.As(err, &network) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func prepareConnectorConnection(ctx, setup context.Context, config Config, signer Signer) (_ *connectorConnection, result error) {
	life, cancel := context.WithCancelCause(ctx)
	p := &connectorConnection{ctx: life, cancel: cancel, config: config, signer: signer, changed: make(chan struct{}), refill: make(chan struct{}, 1), recover: make(chan struct{}, 1), active: make(map[*connectorUse]struct{})}
	p.bindingCtx, p.bindingCancel = context.WithCancel(life)
	stage := "owner"
	defer func() {
		if result != nil {
			p.Close()
			result = fmt.Errorf("prepare connector %s: %w", stage, result)
		}
	}()
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
	if result != nil {
		return nil, result
	}
	setup, stopAuthority := context.WithDeadline(setup, p.until)
	defer stopAuthority()
	var results [2]error
	var starts sync.WaitGroup
	stage = "relay legs"
	for slot := range 2 {
		starts.Go(func() {
			p.paths[slot].leg, results[slot] = connectConnectorLeg(setup, life, config, signer, p.pair, key, slot)
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
	p.endpoint, result = peer.New(life, peer.Config{Key: frameKey, Role: 0, Paths: [2]peer.Carrier{p.paths[0].carrier, p.paths[1].carrier}, Binding: initialBinding})
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
	p.permissions, result = tunnel.OpenConnectorPermissionControl(life, setup, p.session)
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
		prepared, err := prepareConnector(life, setup, p.session, preparedRun, opening.entry)
		if err != nil {
			return nil, err
		}
		p.warm = &connectorUse{entry: opening.entry, prepared: prepared, until: opening.until}
		p.active[p.warm] = struct{}{}
	}
	if setup.Err() != nil || !p.currentLocked() {
		return nil, errors.Join(ErrServiceConnection, context.Cause(setup))
	}
	p.workers.Go(p.watch)
	p.workers.Go(p.refresh)
	p.workers.Go(func() {
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
		p.workers.Go(func() { p.maintainLeg(slot) })
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
	if run.ServiceID != config.ServiceID || !opaqueid.Valid(run.ServiceRunID, opaqueid.ServiceRunPrefix) || run.RunNumber == 0 || !run.ValidUntil.After(time.Now()) || run.PairReady != nil && len(run.PairReady.Relays) != 2 {
		return ErrServiceConnection
	}
	if run.Protocol != config.Protocol || run.TrustRevision != config.TrustRevision || !sameEndpoint(run.Endpoint, config.Endpoint) {
		return metadataReload(config.ServiceID, config.TrustRevision, run.TrustRevision)
	}
	return nil
}

func validConnectorPermission(run Run, permission controlv1.VisitorTokenResponse) bool {
	return permission.Resource.Kind == controlv1.VisitorResourceScopeKindService && permission.Resource.Id == run.ServiceID && run.Endpoint != nil && permission.Hostname == run.Endpoint.Hostname && permission.Port == run.Endpoint.Port && permission.VisitorToken != "" && permission.ExpiresAt.After(time.Now())
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
	return p.ctx.Err() == nil && (p.permissions == nil || p.permissions.Err() == nil) && p.until.After(time.Now()) && p.run.ValidUntil.After(time.Now()) && p.permission.ExpiresAt.After(time.Now())
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
		if !current {
			cause := context.Cause(p.ctx)
			if cause == nil && p.permissions != nil {
				if err := p.permissions.Err(); err != nil {
					// watch may retire the owner before its permission worker runs.
					cause = fmt.Errorf("connector permission owner ended: %w", errors.Join(ErrServiceConnection, err))
				}
			}
			if cause == nil {
				cause = fmt.Errorf("connector authority expired (pair=%s run=%s permission=%s): %w", p.until.Format(time.RFC3339Nano), p.run.ValidUntil.Format(time.RFC3339Nano), p.permission.ExpiresAt.Format(time.RFC3339Nano), ErrServiceConnection)
			}
			p.cancel(cause)
		}
		p.mu.Unlock()
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
	nextAuthority := time.Now().Add(2 * time.Second)
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
		case <-p.recover:
		}
		if err := p.recoverBinding(); err != nil {
			if !connectorTemporary(err) && p.ctx.Err() == nil {
				p.cancel(fmt.Errorf("recover connector binding: %w", err))
				return
			}
		}
		p.mu.Lock()
		activationUncertain := p.rebind != nil && p.rebind.activate != nil
		p.mu.Unlock()
		// an activation may have committed while its reply was lost. resolve
		// that exact phase before renewing with the old delivery generation;
		// the existing owner deadline remains fixed throughout this wait.
		if !activationUncertain && !nextAuthority.After(time.Now()) {
			nextAuthority = time.Now().Add(2 * time.Second)
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
		if binding.Err() != nil {
			if connectorTerminalProtocol(err) {
				p.cancel(fmt.Errorf("maintain connector leg %d: %w", slot, err))
				return
			}
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
			receipt, err = leg.session.RenewConnectorLeg(call, request, proof, leg.receipt)
		}
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
	_ = p.paths[slot].carrier.Install(nil)
	_ = previous.Close()
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
		next, err := prepareConnectorLeg(attempt, p.ctx, p.config, p.signer, pair, p.key, slot, replacement, tunnelv1.ConnectorHandoffID{})
		if err == nil {
			err = context.Cause(attempt)
		}
		finish()
		stop()
		if err != nil {
			if next != nil {
				_ = next.Close()
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
			_ = next.Close()
			return retirePath, ErrServiceConnection
		}
		// no authority lock spans physical cancellation or joined carrier work.
		if err := p.paths[slot].carrier.Install(connectorLegCarrier{next}); err != nil {
			_ = next.Close()
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
			_ = p.paths[slot].carrier.Install(nil)
			_ = next.Close()
			return retirePath, ErrServiceConnection
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

// a raced candidate's temporary error must not hide another candidate's
// authorization rejection. capacity can clear as the old socket joins cleanup.
func connectorReconnectError(err error) reconnectDisposition {
	terminal, stale, retryable := false, false, false
	var visit func(error)
	visit = func(err error) {
		if protocol, ok := err.(*tunnel.ProtocolError); ok {
			retryable = retryable || protocol.Code == tunnelv1.CapacityExceeded
			stale = stale || protocol.Code == tunnelv1.StaleConnectionAssignment || protocol.Code == tunnelv1.StaleNetworkBinding
			terminal = terminal || protocol.Code != tunnelv1.Unavailable && protocol.Code != tunnelv1.CapacityExceeded && protocol.Code != tunnelv1.StaleConnectionAssignment && protocol.Code != tunnelv1.StaleNetworkBinding
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
		use = &connectorUse{entry: p.openings[0].entry, until: p.openings[0].until}
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
		prepared, err := prepareConnector(p.ctx, setup, p.session, run, entry)
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
		if err := operation.activate(use.prepared.stdio); err != nil {
			return err
		}
	}
	defer func() { result = errors.Join(result, use.prepared.Close()) }()
	return use.prepared.Forward(ctx, local)
}

func (p *connectorConnection) Close() {
	p.once.Do(func() {
		p.mu.Lock()
		p.cancel(context.Canceled)
		warm := p.warm
		p.warm = nil
		p.mu.Unlock()
		if p.session != nil {
			_ = p.session.Close()
		}
		if p.permissions != nil {
			p.permissions.Close()
		}
		if p.transport != nil {
			_ = p.transport.Close()
		}
		if p.endpoint != nil {
			_ = p.endpoint.Close()
		}
		p.workers.Wait()
		if op := p.rebind; op != nil {
			for _, leg := range op.legs {
				if leg != nil {
					_ = leg.Close()
				}
			}
		}
		for _, path := range p.paths {
			if path.carrier != nil {
				_ = path.carrier.Close()
			}
			if path.leg != nil {
				_ = path.leg.Close()
			}
		}
		if warm != nil {
			_ = warm.prepared.Close()
		}
		p.uses.Wait()
	})
}
