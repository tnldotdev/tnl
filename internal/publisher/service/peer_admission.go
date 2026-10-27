package service

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const (
	maxPublisherPeerSessions = 64
	maxPeerVisitorHistory    = 4096
)

// PeerSession owns one prepared pair's local stream lifetime. the run shares
// capacity and replay history across both relay carriers of its inner QUIC
// session. callers install only a control-prepared binding, then join Close.
type PeerSession struct {
	bound           *Bound
	binding         PeerBinding
	ctx             context.Context
	cancel          context.CancelFunc
	closed          bool
	replayUntil     time.Time
	seen            map[string]struct{}
	streams         map[net.Conn]struct{}
	changed         chan struct{}
	done            chan struct{}
	workers         sync.WaitGroup
	delivery        sync.WaitGroup
	deliveryStarted bool
	packetReady     chan struct{}
}

func (*PeerSession) String() string   { return "publisher native peer session" }
func (*PeerSession) GoString() string { return "publisher native peer session" }

func (b *Bound) peerBindingCurrentLocked(binding PeerBinding, now time.Time) bool {
	if b.closed || !binding.valid(now) || b.prepared.policy == nil ||
		binding.serviceID != b.prepared.Preparation.ServiceId || binding.serviceRunID != b.prepared.Preparation.ServiceRunId ||
		binding.runNumber != b.prepared.Preparation.RunNumber || binding.publisherIdentityID != b.prepared.Preparation.PublisherIdentityId {
		return false
	}
	for slot, relay := range binding.relays {
		a := b.connections[slot]
		if a.PublisherConnectionId != relay.PublisherConnectionId || a.ConnectionAssignmentRevision != relay.AssignmentRevision ||
			a.RelayServiceId != relay.RelayLease.RelayServiceId || a.RelayAddress != relay.RelayAddress || a.TlsServerName != relay.TlsServerName {
			return false
		}
	}
	return true
}

// BindPeer installs independently authorized pair material before stream arrival.
// a second outer carrier does not create another local peer owner or replay set.
func (b *Bound) BindPeer(ctx context.Context, binding PeerBinding) (*PeerSession, error) {
	if b == nil || b.boundState == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrPrivateStream
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	if !b.peerBindingCurrentLocked(binding, now) {
		return nil, ErrPrivateStream
	}
	b.prunePeersLocked(now)
	if b.peers[binding.pairID] != nil || len(b.peers) >= maxPublisherPeerSessions {
		return nil, ErrPrivateStream
	}
	if b.peers == nil {
		b.peers = make(map[string]*PeerSession)
	}
	life, cancel := context.WithCancel(ctx)
	p := &PeerSession{bound: b, binding: binding, ctx: life, cancel: cancel,
		seen: make(map[string]struct{}), streams: make(map[net.Conn]struct{}), changed: make(chan struct{}), done: make(chan struct{}), packetReady: make(chan struct{})}
	b.peers[binding.pairID] = p
	go p.watch()
	return p, nil
}

func (b *Bound) prunePeersLocked(now time.Time) {
	for id, old := range b.peers {
		if old.closed && !old.replayUntil.After(now) {
			delete(b.peers, id)
		}
	}
}

// Renew accepts only a freshly control-prepared binding of the same delivery.
// it can narrow a live deadline; stopped or expired peers cannot be revived.
func (p *PeerSession) Renew(binding PeerBinding) error {
	b := p.bound
	b.mu.Lock()
	defer b.mu.Unlock()
	old := p.binding
	if p.closed || p.ctx.Err() != nil || !old.expiresAt.After(time.Now()) || !b.peerBindingCurrentLocked(binding, time.Now()) ||
		binding.pairID != old.pairID || binding.deliveryID != old.deliveryID || binding.generation != old.generation || binding.key != old.key ||
		binding.sourceIP != old.sourceIP || binding.relays != old.relays || !visitorsubject.Same(binding.subject, old.subject) {
		return ErrPrivateStream
	}
	p.binding = binding
	close(p.changed)
	p.changed = make(chan struct{})
	return nil
}

func (p *PeerSession) watch() {
	defer close(p.done)
	for {
		p.bound.mu.Lock()
		deadline, changed := p.binding.expiresAt, p.changed
		current := !p.closed && p.bound.peerBindingCurrentLocked(p.binding, time.Now())
		p.bound.mu.Unlock()
		if !current {
			p.stop()
			return
		}
		timer := time.NewTimer(time.Until(deadline))
		select {
		case <-p.ctx.Done():
			timer.Stop()
			p.stop()
			return
		case <-changed:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (p *PeerSession) stop() {
	b := p.bound
	b.mu.Lock()
	if p.closed {
		b.mu.Unlock()
		return
	}
	p.closed = true
	// a stopped pair cannot lose its replay fence while a visitor token could
	// still be current, even if delivery is prepared again on a later carrier.
	p.replayUntil = time.Now().Add(5 * time.Minute)
	if p.binding.expiresAt.After(p.replayUntil) {
		p.replayUntil = p.binding.expiresAt
	}
	p.cancel()
	streams := make([]net.Conn, 0, len(p.streams))
	for stream := range p.streams {
		streams = append(streams, stream)
	}
	b.mu.Unlock()
	for _, stream := range streams {
		_ = stream.Close()
	}
}

func (p *PeerSession) Close() {
	p.stop()
	<-p.done
	p.delivery.Wait()
	p.workers.Wait()
}

// ServeStream consumes one inner-QUIC application stream. only local prepared
// facts are read here; no control call or carrier choice occurs on arrival.
func (p *PeerSession) ServeStream(ctx context.Context, stream net.Conn) error {
	if stream == nil {
		return ErrPrivateStream
	}
	defer stream.Close()
	b := p.bound
	b.mu.Lock()
	limit := b.streamCapacity
	if limit == 0 {
		limit = 64
	}
	if p.closed || p.ctx.Err() != nil || ctx.Err() != nil || !b.peerBindingCurrentLocked(p.binding, time.Now()) || b.reservedStreams >= limit {
		b.mu.Unlock()
		return ErrPrivateStream
	}
	binding := p.binding
	p.streams[stream] = struct{}{}
	b.active[stream] = struct{}{}
	b.reservedStreams++
	p.workers.Add(1)
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(p.streams, stream)
		delete(b.active, stream)
		b.reservedStreams--
		b.mu.Unlock()
		p.workers.Done()
	}()
	life, cancel := context.WithCancel(p.ctx)
	stopCaller := context.AfterFunc(ctx, cancel)
	closed := make(chan struct{})
	stopStream := context.AfterFunc(life, func() { _ = stream.Close(); close(closed) })
	defer func() {
		stopCaller()
		cancel()
		if !stopStream() {
			<-closed
		}
	}()
	if err := stream.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	entry, initial, err := tunnelv1.ReadNativePeerVisitorOpening(stream)
	if err != nil {
		return ErrPrivateStream
	}
	subject, err := visitorsubject.Parse(binding.subject)
	if err != nil {
		return ErrPrivateStream
	}
	expected := tunnelv1.NativePeerSession{PairID: binding.pairID, DeliveryID: base64.RawURLEncoding.EncodeToString(binding.deliveryID[:]),
		DeliveryGeneration: binding.generation, ServiceID: binding.serviceID, ServiceRunID: binding.serviceRunID,
		RunNumber: uint64(binding.runNumber), Subject: subject, SourceIP: binding.sourceIP.String(), ExpiresAt: binding.expiresAt}
	view, enabled, _ := b.prepared.policy.Current()
	if !enabled || entry.MetadataRevision != uint64(b.prepared.metadataRevision) {
		return ErrPrivateStream
	}
	permission, err := visitortoken.VerifyNativePeerSession(entry, initial, expected, view, time.Now())
	if err != nil {
		return ErrPrivateStream
	}
	guard, err := b.prepared.policy.BindNative(permission, binding.sourceIP, int64(entry.MetadataRevision), cancel)
	if err != nil {
		return ErrPrivateStream
	}
	defer guard.Close()
	if err := guard.AllowRenewal(); err != nil {
		return ErrPrivateStream
	}
	b.mu.Lock()
	_, replay := p.seen[entry.VisitorConnectionID]
	valid := !p.closed && life.Err() == nil && b.peerBindingCurrentLocked(p.binding, time.Now()) && !replay && len(p.seen) < maxPeerVisitorHistory
	if valid {
		p.seen[entry.VisitorConnectionID] = struct{}{}
	}
	b.mu.Unlock()
	if !valid {
		return ErrPrivateStream
	}
	reader := tunnel.NewNativeRequestReader(stream, initial, func(proof tunnelv1.NativeVisitorPermission) error {
		nextEntry := entry
		nextEntry.Permission = proof
		view, enabled, _ := b.prepared.policy.Current()
		if !enabled {
			return ErrPrivateStream
		}
		b.mu.Lock()
		expected.ExpiresAt = p.binding.expiresAt
		b.mu.Unlock()
		next, err := visitortoken.VerifyNativePeerRenewalProof(nextEntry, nil, expected, view, time.Now())
		if err != nil || !next.SameIdentity(permission) {
			return ErrPrivateStream
		}
		return guard.Renew(next)
	})
	visitor := publisher.ConnectorVisitor{Check: func(context.Context) (publisher.ServiceVisitorDecision, error) {
		deadline, err := guard.Deadline()
		b.mu.Lock()
		current := !p.closed && b.peerBindingCurrentLocked(p.binding, time.Now())
		if deadline.After(p.binding.expiresAt) {
			deadline = p.binding.expiresAt
		}
		b.mu.Unlock()
		if !current || life.Err() != nil {
			err = errors.Join(err, ErrPrivateStream)
		}
		return publisher.ServiceVisitorDecision{Allowed: err == nil, ValidUntil: deadline}, err
	}}
	if err := stream.SetDeadline(time.Time{}); err != nil {
		return err
	}
	return b.forwardManaged(life, reader, visitor, false)
}
