package stream

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type preparedOpening struct {
	entry tunnelv1.NativePeerVisitorEntry
	until time.Time
}

type nativeUse struct {
	entry    tunnelv1.NativePeerVisitorEntry
	prepared *PreparedNative
}

// nativeConnection owns one selected run and retained inner QUIC connection.
// background workers own authority renewal and proof generation;
// local arrivals consume immutable signed openings and never call control.
type nativeConnection struct {
	ctx           context.Context
	cancel        context.CancelCauseFunc
	config        Config
	signer        Signer
	owner         string
	endpoint      *peer.Endpoint
	transport     *quic.Transport
	connection    *quic.Conn
	session       muxsession.Session
	mu            sync.Mutex
	run           Run
	pair          controlv1.NativePeerPair
	key           [32]byte
	until         time.Time
	preparedUntil time.Time
	source        string
	permission    controlv1.VisitorTokenResponse
	legs          [2]*nativeRelayLeg
	legDone       [2]bool
	openings      []preparedOpening
	active        map[*nativeUse]struct{}
	warm          *nativeUse
	changed       chan struct{}
	refill        chan struct{}
	workers       sync.WaitGroup
	uses          sync.WaitGroup
	once          sync.Once
}

func nativeTemporary(err error) bool {
	if _, definition, ok := failure.Describe(err); ok {
		return definition.Retry == failure.RetryLater
	}
	var network net.Error
	return errors.As(err, &network) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func prepareNativeConnection(ctx, setup context.Context, config Config, signer Signer) (_ *nativeConnection, result error) {
	life, cancel := context.WithCancelCause(ctx)
	p := &nativeConnection{ctx: life, cancel: cancel, config: config, signer: signer, changed: make(chan struct{}), refill: make(chan struct{}, 1), active: make(map[*nativeUse]struct{})}
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
	if result = validateNativeRun(config, p.run); result != nil {
		return nil, result
	}
	p.run.ServiceTLS = config.ServiceTLS
	var create controlv1.NativePeerPairRequest
	p.pair, p.key, p.until, create, result = prepareNativePair(setup, config.Control, signer, p.run, p.owner, nil)
	if result != nil {
		return nil, result
	}
	setup, stopAuthority := context.WithDeadline(setup, p.until)
	defer stopAuthority()
	var results [2]error
	var starts sync.WaitGroup
	for slot := range 2 {
		starts.Go(func() {
			p.legs[slot], results[slot] = connectNativeLeg(setup, life, config, signer, p.pair, p.key, slot)
		})
	}
	starts.Wait()
	if result = errors.Join(results[:]...); result != nil {
		return nil, result
	}
	if p.legs[0].receipt.SourceIP != p.legs[1].receipt.SourceIP {
		return nil, ErrServiceConnection
	}
	p.source = p.legs[0].receipt.SourceIP
	if p.preparedUntil, result = awaitNativePublisher(setup, config.Control, p.run.ServiceID, create, p.pair); result != nil {
		return nil, result
	}
	p.endpoint, result = peer.New(life, peer.Config{Key: p.key, Role: 0, Paths: [2]peer.Carrier{p.legs[0].carrier, p.legs[1].carrier}})
	if result != nil {
		return nil, result
	}
	if result = awaitNativePaths(setup, p.endpoint); result != nil {
		return nil, result
	}
	p.transport = &quic.Transport{Conn: p.endpoint}
	trust := config.ServiceTLS.Clone()
	trust.ServerName, trust.NextProtos = p.run.Endpoint.Hostname, []string{muxsession.ALPN}
	p.connection, result = p.transport.Dial(setup, p.endpoint.RemoteAddr(), trust, &quic.Config{InitialPacketSize: tunnelv1.MaxPeerPacketBytes, DisablePathMTUDiscovery: true, MaxIncomingStreams: 0, MaxIncomingUniStreams: 1, MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 10 * time.Second})
	if result != nil {
		return nil, failure.Wrap("prepare native peer TLS", failure.ConnectionTLSRejected, result)
	}
	p.session, result = muxsession.AdoptQUIC(p.connection)
	if result != nil {
		return nil, result
	}
	p.permission, result = config.Control.VisitorPermission(setup, config.ServiceID)
	if result != nil || !validNativePermission(p.run, p.permission) || setup.Err() != nil {
		return nil, errors.Join(ErrServiceConnection, result, context.Cause(setup))
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
		prepared, err := prepareNative(life, setup, p.session, p.run, opening.entry)
		if err != nil {
			return nil, err
		}
		p.warm = &nativeUse{entry: opening.entry, prepared: prepared}
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

func awaitNativePaths(ctx context.Context, endpoint *peer.Endpoint) error {
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

func validateNativeRun(config Config, run Run) error {
	if run.ServiceID != config.ServiceID || !opaqueid.Valid(run.ServiceRunID, opaqueid.ServiceRunPrefix) || run.RunNumber == 0 || !run.ValidUntil.After(time.Now()) || run.PairReady != nil && len(run.PairReady.Relays) != 2 {
		return ErrServiceConnection
	}
	if run.Protocol != config.Protocol || run.TrustRevision != config.TrustRevision || !sameEndpoint(run.Endpoint, config.Endpoint) {
		return metadataReload(config.ServiceID, config.TrustRevision, run.TrustRevision)
	}
	return nil
}

func validNativePermission(run Run, permission controlv1.VisitorTokenResponse) bool {
	return permission.Resource.Kind == controlv1.VisitorResourceScopeKindService && permission.Resource.Id == run.ServiceID && run.Endpoint != nil && permission.Hostname == run.Endpoint.Hostname && permission.Port == run.Endpoint.Port && permission.VisitorToken != "" && permission.ExpiresAt.After(time.Now())
}

func (p *nativeConnection) currentLocked() bool {
	return p.ctx.Err() == nil && p.until.After(time.Now()) && p.preparedUntil.After(time.Now()) && p.run.ValidUntil.After(time.Now()) && p.permission.ExpiresAt.After(time.Now())
}

func (p *nativeConnection) notifyLocked() { close(p.changed); p.changed = make(chan struct{}) }

func nativeOpening(signer Signer, entry tunnelv1.NativePeerVisitorEntry, token string) (tunnelv1.NativePeerVisitorEntry, error) {
	entry.Permission = tunnelv1.NativeVisitorPermission{Token: token, PublicKey: base64.RawURLEncoding.EncodeToString(signer.PublicKey), Signature: base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))}
	message, err := tunnelv1.NativePeerProofMessage(entry, nil)
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

func (p *nativeConnection) fillOpenings() error {
	p.mu.Lock()
	if !p.currentLocked() {
		p.mu.Unlock()
		return ErrServiceConnection
	}
	count := 64 - len(p.openings)
	run, pair, permission, source := p.run, p.pair, p.permission, p.source
	p.mu.Unlock()
	entries := make([]preparedOpening, 0, count)
	for range count {
		visitor, err := opaqueid.New(opaqueid.VisitorConnectionPrefix)
		if err != nil {
			return err
		}
		entry, err := nativeOpening(p.signer, tunnelv1.NativePeerVisitorEntry{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.NativePeerVisitorStream, PairID: pair.PairId, DeliveryID: pair.DeliveryId, DeliveryGeneration: pair.DeliveryGeneration,
			ServiceID: run.ServiceID, ServiceRunID: run.ServiceRunID, RunNumber: run.RunNumber, Subject: p.signer.Subject, SourceIP: source, VisitorConnectionID: visitor, MetadataRevision: uint64(run.TrustRevision)}, permission.VisitorToken)
		if err != nil {
			return err
		}
		entries = append(entries, preparedOpening{entry, permission.ExpiresAt})
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.currentLocked() || p.permission.VisitorToken != permission.VisitorToken {
		return nil // a newer background refresh owns the next pool.
	}
	p.openings = append(p.openings, entries[:min(len(entries), 64-len(p.openings))]...)
	return nil
}

func (p *nativeConnection) watch() {
	for {
		p.mu.Lock()
		until := earliestNativeDeadline(p.until, p.preparedUntil, p.run.ValidUntil, p.permission.ExpiresAt)
		changed := p.changed
		if !p.currentLocked() {
			p.cancel(ErrServiceConnection)
		}
		p.mu.Unlock()
		timer := time.NewTimer(time.Until(until))
		select {
		case <-p.ctx.Done():
			timer.Stop()
			return
		case <-p.session.Done():
			timer.Stop()
			p.cancel(ErrServiceConnection)
			return
		case <-changed:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func earliestNativeDeadline(values ...time.Time) time.Time {
	until := values[0]
	for _, value := range values[1:] {
		if value.Before(until) {
			until = value
		}
	}
	return until
}

func (p *nativeConnection) refresh() {
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
		call, stop := context.WithDeadline(p.ctx, minNativeCall(until))
		next, err := p.config.Control.ResolveService(call, run.ServiceID)
		if err == nil {
			err = validateNativeRun(p.config, next)
		}
		if err == nil && (next.ServiceRunID != run.ServiceRunID || next.RunNumber != run.RunNumber || next.PairReady != nil && next.PairReady.PublisherIdentityId != run.PairReady.PublisherIdentityId) {
			err = ErrServiceConnection
		}
		var pair controlv1.NativePeerPair
		var key [32]byte
		var bound time.Time
		if err == nil {
			pair, key, bound, _, err = prepareNativePair(call, p.config.Control, p.signer, next, p.owner, &previous)
		}
		var permission controlv1.VisitorTokenResponse
		if err == nil {
			permission, err = p.config.Control.VisitorPermission(call, run.ServiceID)
			if err == nil && !validNativePermission(next, permission) {
				err = ErrServiceConnection
			}
		}
		if err == nil {
			err = context.Cause(call)
		}
		stop()
		if err != nil {
			if !nativeTemporary(err) && p.ctx.Err() == nil {
				p.cancel(err)
				return
			}
			continue
		}
		p.mu.Lock()
		if !p.currentLocked() || key != p.key {
			p.mu.Unlock()
			p.cancel(ErrServiceConnection)
			return
		}
		next.ServiceTLS = p.config.ServiceTLS
		// pair renewal is not publisher installation renewal. retain only a
		// current, independently reported installation deadline on this owner.
		if pair.PublisherPreparedUntil != nil && !pair.PublisherPreparedUntil.After(pair.ExpiresAt) {
			p.preparedUntil = bound.Add(pair.PublisherPreparedUntil.Sub(pair.ExpiresAt))
		}
		p.run, p.pair, p.until, p.permission = next, pair, bound, permission
		p.openings = nil
		active := make([]*nativeUse, 0, len(p.active))
		for stream := range p.active {
			if stream.prepared != nil {
				active = append(active, stream)
			}
		}
		p.notifyLocked()
		p.mu.Unlock()
		if err := p.fillOpenings(); err != nil {
			p.cancel(err)
			return
		}
		renewUntil := minNativeCall(earliestNativeDeadline(bound, next.ValidUntil, permission.ExpiresAt))
		for _, stream := range active {
			entry, err := nativeOpening(p.signer, stream.entry, permission.VisitorToken)
			if err == nil {
				err = stream.prepared.writer.RenewUntil(entry.Permission, renewUntil)
			}
			if err != nil {
				_ = stream.prepared.Close()
			}
		}
	}
}

func minNativeCall(until time.Time) time.Time {
	return earliestNativeDeadline(until, time.Now().Add(2*time.Second))
}

func (p *nativeConnection) maintainLeg(slot int) {
	defer func() {
		p.mu.Lock()
		p.legDone[slot] = true
		ended := p.legDone[0] && p.legDone[1]
		p.mu.Unlock()
		// one lost carrier leaves the retained inner session on its sibling.
		// after both are terminal, no reconnect can deliver a remote close; end
		// local children now rather than waiting for QUIC's idle timeout.
		if ended {
			p.cancel(ErrServiceConnection)
		}
	}()
	for {
		p.mu.Lock()
		leg, changed := p.legs[slot], p.changed
		p.mu.Unlock()
		delay := min(2*time.Second, max(100*time.Millisecond, time.Until(leg.until)/4))
		timer := time.NewTimer(delay)
		select {
		case <-p.ctx.Done():
			timer.Stop()
			return
		case <-leg.session.Done():
			timer.Stop()
		case <-changed:
			timer.Stop()
		case <-timer.C:
		}
		p.mu.Lock()
		pair, until := p.pair, p.until
		p.mu.Unlock()
		call, stop := context.WithDeadline(p.ctx, minNativeCall(earliestNativeDeadline(until, leg.until)))
		var proof tunnelv1.NativePairLegProof
		err := ErrServiceConnection
		if pair.Relays[slot] == leg.relay {
			proof, err = nativeLegProof(p.signer, pair, slot)
		}
		var receipt tunnelv1.NativePairLegAccepted
		started := time.Now()
		if err == nil {
			request, keyErr := opaqueid.New(opaqueid.IdempotencyPrefix)
			err = keyErr
			if err == nil {
				receipt, err = leg.session.RenewNativeLeg(call, request, proof, leg.receipt)
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
			_ = leg.Close()
			return
		}
		if !nativeTemporary(err) {
			p.cancel(err)
			return
		}
		// an unavailable renewal never extends the last confirmed deadline.
		// a lost carrier is not reconnected; inner QUIC uses its warm sibling.
	}
}

func (p *nativeConnection) Forward(ctx context.Context, local net.Conn) error {
	p.mu.Lock()
	if !p.currentLocked() || ctx.Err() != nil || len(p.active) >= p.config.MaxConnections && p.warm == nil {
		p.mu.Unlock()
		return ErrServiceConnection
	}
	var use *nativeUse
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
		use = &nativeUse{entry: p.openings[0].entry}
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
		prepared, err := prepareNative(p.ctx, setup, p.session, run, use.entry)
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

func (p *nativeConnection) Close() {
	p.once.Do(func() {
		p.mu.Lock()
		p.cancel(context.Canceled)
		warm := p.warm
		p.warm = nil
		p.mu.Unlock()
		if p.session != nil {
			_ = p.session.Close()
		}
		if p.transport != nil {
			_ = p.transport.Close()
		}
		if p.endpoint != nil {
			_ = p.endpoint.Close()
		}
		p.workers.Wait()
		for _, leg := range p.legs {
			if leg != nil {
				_ = leg.Close()
			}
		}
		if warm != nil {
			_ = warm.prepared.Close()
		}
		p.uses.Wait()
	})
}
