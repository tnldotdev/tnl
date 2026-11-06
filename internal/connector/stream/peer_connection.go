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
}

type connectorPath struct {
	leg     *connectorRelayLeg
	carrier *peer.CarrierSlot
	done    bool
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
	p := &connectorConnection{ctx: life, cancel: cancel, config: config, signer: signer, changed: make(chan struct{}), refill: make(chan struct{}, 1), active: make(map[*connectorUse]struct{})}
	defer func() {
		if result != nil {
			p.Close()
		}
	}()
	p.owner, result = opaqueid.New(opaqueid.IdempotencyPrefix)
	if result != nil {
		return nil, result
	}
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
	p.pair, key, p.until, create, result = prepareConnectorPair(setup, config.Control, signer, p.run, p.owner)
	if result != nil {
		return nil, result
	}
	setup, stopAuthority := context.WithDeadline(setup, p.until)
	defer stopAuthority()
	var results [2]error
	var starts sync.WaitGroup
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
	if p.preparedUntil, p.reportedUntil, result = awaitConnectorPublisher(setup, config.Control, p.run.ServiceID, create, p.pair); result != nil {
		return nil, result
	}
	p.key = key
	for slot := range 2 {
		path := &p.paths[slot]
		path.carrier = peer.NewCarrierSlot()
		if result = path.carrier.Install(connectorLegCarrier{path.leg}); result != nil {
			return nil, result
		}
	}
	p.endpoint, result = peer.New(life, peer.Config{Key: key, Role: 0, Paths: [2]peer.Carrier{p.paths[0].carrier, p.paths[1].carrier}})
	if result != nil {
		return nil, result
	}
	if result = awaitConnectorPaths(setup, p.endpoint); result != nil {
		return nil, result
	}
	p.transport = &quic.Transport{Conn: p.endpoint}
	trust := config.ServiceTLS.Clone()
	trust.ServerName, trust.NextProtos = p.run.Endpoint.Hostname, []string{muxsession.ALPN}
	innerConfig := tunnel.ConnectorQUICConfig()
	innerConfig.MaxIncomingStreams = -1
	p.connection, result = p.transport.Dial(setup, p.endpoint.RemoteAddr(), trust, innerConfig)
	if result != nil {
		return nil, failure.Wrap("prepare connector peer TLS", failure.ConnectionTLSRejected, result)
	}
	p.session, result = muxsession.AdoptQUIC(p.connection)
	if result != nil {
		return nil, result
	}
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
		prepared, err := prepareConnector(life, setup, p.session, p.run, opening.entry)
		if err != nil {
			return nil, err
		}
		p.warm = &connectorUse{entry: opening.entry, prepared: prepared}
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
					cancel(err)
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
	return p.ctx.Err() == nil && (p.permissions == nil || p.permissions.Err() == nil) && p.until.After(time.Now()) && p.preparedUntil.After(time.Now()) && p.run.ValidUntil.After(time.Now()) && p.permission.ExpiresAt.After(time.Now())
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
	if !p.currentLocked() || p.permission.VisitorToken != permission.VisitorToken {
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
		until := earliestConnectorDeadline(p.until, p.preparedUntil, p.run.ValidUntil, p.permission.ExpiresAt)
		changed := p.changed
		if !p.currentLocked() {
			p.cancel(fmt.Errorf("connector authority expired: %w", ErrServiceConnection))
		}
		p.mu.Unlock()
		timer := time.NewTimer(time.Until(until))
		select {
		case <-p.ctx.Done():
			timer.Stop()
			return
		case <-p.session.Done():
			timer.Stop()
			p.cancel(fmt.Errorf("connector inner session ended: %w", errors.Join(ErrServiceConnection, p.session.Err())))
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
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
		}
		p.mu.Lock()
		run, previous, until := p.run, p.pair, p.until
		p.mu.Unlock()
		call, stop := context.WithDeadline(p.ctx, minConnectorCall(until))
		renewal, bound, err := renewConnectorPair(call, p.config.Control, p.signer, run, p.owner, previous)
		pair, permission, next := renewal.Pair, renewal.VisitorPermission, run
		if err == nil {
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
			if !connectorTemporary(err) && p.ctx.Err() == nil {
				p.cancel(fmt.Errorf("renew connector pair: %w", err))
				return
			}
			continue
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
			if !connectorTemporary(err) && p.ctx.Err() == nil {
				p.cancel(fmt.Errorf("prepare connector renewal openings: %w", err))
				return
			}
			continue
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
		if !p.currentLocked() || !bound.After(now) || !preparedUntil.After(now) || !next.ValidUntil.After(now) || !permission.ExpiresAt.After(now) {
			p.mu.Unlock()
			p.cancel(fmt.Errorf("install connector renewal after authority expired: %w", ErrServiceConnection))
			return
		}
		next.ServiceTLS = p.config.ServiceTLS
		// pair renewal is not publisher installation renewal. retain only a
		// current, independently reported installation deadline on this owner.
		p.preparedUntil, p.reportedUntil = preparedUntil, reportedUntil
		p.run, p.pair, p.until, p.permission = next, pair, bound, permission
		p.openings = openings
		active := make([]*connectorUse, 0, len(p.active))
		for stream := range p.active {
			if stream.prepared != nil {
				active = append(active, stream)
			}
		}
		p.notifyLocked()
		p.mu.Unlock()
		p.renewActive(active, permission, earliestConnectorDeadline(bound, next.ValidUntil, permission.ExpiresAt))
	}
}

func (p *connectorConnection) renewActive(active []*connectorUse, permission controlv1.VisitorTokenResponse, bound time.Time) {
	// signing stays off the arrival path. independent submissions retain #525's
	// isolation, but never write or change deadlines on an application stream.
	var renewals sync.WaitGroup
	for _, stream := range active {
		renewals.Go(func() {
			entry, err := connectorOpening(p.signer, stream.entry, permission.VisitorToken)
			if err == nil {
				err = stream.prepared.queuePermission(preparedPermissionRenewal{writer: p.permissions, update: tunnelv1.ConnectorPermissionUpdate{VisitorConnectionID: entry.VisitorConnectionID, Permission: entry.Permission}, until: bound})
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
	defer func() {
		p.mu.Lock()
		p.paths[slot].done = true
		ended := p.paths[0].done && p.paths[1].done
		p.mu.Unlock()
		// both-path temporary loss retains inner QUIC. only exhausted authority
		// or terminal rejection ends a leg worker; neither can revive a session.
		if ended {
			p.cancel(fmt.Errorf("connector relay legs retired: %w", ErrServiceConnection))
		}
	}()
	for {
		p.mu.Lock()
		leg, changed := p.paths[slot].leg, p.changed
		p.mu.Unlock()
		if leg.session.Err() != nil {
			disposition, err := p.reconnectLeg(slot, leg)
			if disposition == terminateConnection {
				p.cancel(err)
			}
			if disposition != retryAttempt {
				return
			}
			continue
		}
		delay := min(2*time.Second, max(100*time.Millisecond, time.Until(leg.until)/4))
		timer := time.NewTimer(delay)
		select {
		case <-p.ctx.Done():
			timer.Stop()
			return
		case <-leg.session.Done():
			timer.Stop()
			continue
		case <-changed:
			timer.Stop()
		case <-timer.C:
		}
		p.mu.Lock()
		pair, until := p.pair, p.until
		p.mu.Unlock()
		call, stop := context.WithDeadline(p.ctx, minConnectorCall(earliestConnectorDeadline(until, leg.until)))
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
			leg.receipt, leg.until = receipt, started.Add(receipt.ExpiresAt.Sub(receipt.ObservedAt))
			stop()
			continue
		}
		stop()
		if p.ctx.Err() != nil {
			return
		}
		if !leg.until.After(time.Now()) || leg.session.Err() != nil {
			disposition, err := p.reconnectLeg(slot, leg)
			if disposition == terminateConnection {
				p.cancel(err)
			}
			if disposition != retryAttempt {
				return
			}
			continue
		}
		if !connectorTemporary(err) {
			p.cancel(err)
			return
		}
		// an unavailable renewal never extends the last confirmed deadline.
	}
}

func (p *connectorConnection) reconnectLeg(slot int, previous *connectorRelayLeg) (reconnectDisposition, error) {
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
		call, stop := context.WithDeadline(p.ctx, until)
		timer := time.NewTimer(delay)
		select {
		case <-call.Done():
			timer.Stop()
			stop()
			return retirePath, context.Cause(call)
		case <-timer.C:
		}
		attempt, finish := context.WithDeadline(call, minConnectorCall(until))
		next, err := prepareConnectorLeg(attempt, p.ctx, p.config, p.signer, pair, p.key, slot, replacement)
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
)

// a raced candidate's temporary error must not hide another candidate's
// authorization rejection. capacity can clear as the old socket joins cleanup.
func connectorReconnectError(err error) reconnectDisposition {
	terminal, stale, retryable := false, false, false
	var visit func(error)
	visit = func(err error) {
		if protocol, ok := err.(*tunnel.ProtocolError); ok {
			retryable = retryable || protocol.Code == tunnelv1.CapacityExceeded
			stale = stale || protocol.Code == tunnelv1.StaleConnectionAssignment
			terminal = terminal || protocol.Code != tunnelv1.Unavailable && protocol.Code != tunnelv1.CapacityExceeded && protocol.Code != tunnelv1.StaleConnectionAssignment
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
		// stop this path without transferring authority from its retained sibling.
		return retirePath
	}
	if retryable {
		return retryAttempt
	}
	return terminateConnection
}

func (p *connectorConnection) Forward(ctx context.Context, local net.Conn) error {
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
		use = &connectorUse{entry: p.openings[0].entry}
		p.openings = p.openings[1:]
		p.active[use] = struct{}{}
	}
	p.uses.Add(1)
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
		prepared, err := prepareConnector(p.ctx, setup, p.session, run, use.entry)
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
	defer use.prepared.Close()
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
