package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// nativePacketSession borrows one authenticated outer session. registrations
// carry encrypted packets, not application streams or target authority.
type nativePacketSession struct {
	ctx       context.Context
	cancel    context.CancelFunc
	datagrams *peer.SharedDatagrams
	streams   *peer.SharedStreams
	mu        sync.Mutex
	closed    bool
	jobs      map[*nativePairDelivery]struct{}
	bridges   map[[16]byte]*nativePairBridge
	once      sync.Once
}

func newNativePacketSession(parent context.Context, transport muxsession.Session) (*nativePacketSession, error) {
	ctx, cancel := context.WithCancel(parent)
	p := &nativePacketSession{ctx: ctx, cancel: cancel, jobs: make(map[*nativePairDelivery]struct{}), bridges: make(map[[16]byte]*nativePairBridge)}
	var err error
	if datagrams, ok := transport.(muxsession.DatagramSession); ok {
		// a QUIC session must have negotiated datagrams on both sides; do not
		// silently turn it into an ordered stream carrier.
		p.datagrams, err = peer.NewSharedDatagrams(ctx, datagrams)
	} else {
		p.streams, err = peer.NewSharedStreams(ctx, transport)
	}
	if err != nil {
		cancel()
		return nil, err
	}
	return p, nil
}

func (p *nativePacketSession) register(ctx context.Context, binding peer.PairBinding, open bool) (peer.Carrier, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.datagrams != nil {
		return p.datagrams.Register(binding)
	}
	pair, err := p.streams.Register(binding)
	if err != nil {
		return nil, err
	}
	return pair.Carrier(open), nil
}

func (p *nativePacketSession) Close() {
	p.once.Do(func() {
		p.mu.Lock()
		p.closed = true
		jobs := make([]*nativePairDelivery, 0, len(p.jobs))
		for job := range p.jobs {
			jobs = append(jobs, job)
		}
		bridges := make([]*nativePairBridge, 0, len(p.bridges))
		for _, bridge := range p.bridges {
			bridges = append(bridges, bridge)
		}
		p.mu.Unlock()
		p.cancel()
		if p.datagrams != nil {
			_ = p.datagrams.Close()
		}
		if p.streams != nil {
			_ = p.streams.Close()
		}
		for _, job := range jobs {
			<-job.done
		}
		for _, bridge := range bridges {
			<-bridge.done
		}
	})
}

type nativePairDelivery struct {
	ctx                        context.Context
	cancel                     context.CancelFunc
	stopPublisher              func() bool
	publisher                  *nativePacketSession
	connector                  *nativePacketSession
	towardPublisher            peer.Carrier
	towardConnector            peer.Carrier
	connection                 *serviceConnection
	transport                  muxsession.Session
	done                       chan struct{}
	mu                         sync.Mutex
	closed, serving, activated bool
	workers                    sync.WaitGroup
	once                       sync.Once
	deadline                   time.Time
	changed                    chan struct{}
	authorityDone              chan struct{}
	bridge                     *nativePairBridge
}

func (*nativePairDelivery) String() string   { return "native pair packet delivery" }
func (*nativePairDelivery) GoString() string { return "native pair packet delivery" }

// nativeCandidate requires the exact locally claimed publisher connection and
// the same process lease that control checked. registry presence alone is not a
// serving grant, and a newer assignment cannot inherit an old pair.
func (r *ServiceRegistry) nativeCandidate(ref tunnelv1.ServicePublisherConnectionRef, lease relayv1.RelayLease, now time.Time) (*serviceConnection, bool) {
	if ref.Validate() != nil || lease.Draining || !lease.LeaseExpiresAt.After(now) || ref.RelayServiceID != lease.RelayServiceId {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.connections[ref.PublisherConnectionID]
	if r.closed || c == nil || c.ref != ref || c.packets == nil || c.lease.RelayServiceId != lease.RelayServiceId ||
		c.lease.RelayId != lease.RelayId || c.lease.RelayRunId != lease.RelayRunId || c.lease.RelayLeaseRevision != lease.RelayLeaseRevision {
		return nil, false
	}
	c.paths.mu.Lock()
	current := c.paths.stateErrorLocked() == nil
	c.paths.mu.Unlock()
	return c, current
}

func (a *NativeConnectorAcceptor) prepareDelivery(setup, lifetime context.Context, transport muxsession.Session, proof tunnelv1.NativePairLegProof, claim nativeConnectorClaim) (_ *nativePairDelivery, err error) {
	lease, valid := a.currentLease(proof, a.now())
	if !valid {
		return nil, &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
	}
	connection, valid := a.Publishers.nativeCandidate(claim.ref, lease, a.now())
	if !valid {
		return nil, &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
	}
	id, parseErr := tunnelv1.ParsePeerDeliveryIdentifier(claim.receipt.DeliveryID)
	if parseErr != nil || claim.key == [32]byte{} || !claim.receipt.ExpiresAt.After(a.now()) {
		return nil, &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	}
	ctx, cancel := context.WithCancel(lifetime)
	d := &nativePairDelivery{ctx: ctx, cancel: cancel, publisher: connection.packets, connection: connection, done: make(chan struct{}),
		transport: transport, deadline: claim.receipt.ExpiresAt, changed: make(chan struct{}), authorityDone: make(chan struct{})}
	d.stopPublisher = context.AfterFunc(d.publisher.ctx, cancel)
	d.publisher.mu.Lock()
	if d.publisher.closed || d.publisher.ctx.Err() != nil {
		d.publisher.mu.Unlock()
		d.stopPublisher()
		cancel()
		return nil, net.ErrClosed
	}
	d.publisher.jobs[d] = struct{}{}
	d.publisher.mu.Unlock()
	go d.watchAuthority(a)
	defer func() {
		if err != nil {
			d.Close()
		}
	}()
	binding := peer.PairBinding{Delivery: tunnelv1.PeerDelivery{Pair: id, Generation: uint64(claim.receipt.DeliveryGeneration)},
		Key: claim.key, Kind: peer.NativePeer, Path: uint8(claim.receipt.ConnectionSlot), Role: 0}
	d.connector, err = newNativePacketSession(ctx, transport)
	if err != nil {
		return nil, errors.Join(err, &tunnel.ProtocolError{Code: tunnelv1.Unavailable})
	}
	binding.Role = 1
	d.towardConnector, err = d.connector.register(setup, binding, false)
	if err != nil {
		return nil, errors.Join(err, &tunnel.ProtocolError{Code: tunnelv1.Unavailable})
	}
	if current, ok := a.Publishers.nativeCandidate(claim.ref, lease, a.now()); !ok || current != connection || ctx.Err() != nil {
		return nil, &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
	}
	return d, nil
}

func (d *nativePairDelivery) serve(a *NativeConnectorAcceptor, session *tunnel.Session, proof tunnelv1.NativePairLegProof, claim nativeConnectorClaim) (retErr error) {
	finished := make(chan error, 1)
	defer func() {
		d.Close()
		// session shutdown may win the select after the peer reads a denial.
		// joining the control owner must retain that completed protocol result.
		select {
		case err := <-finished:
			var protocol *tunnel.ProtocolError
			if errors.As(err, &protocol) {
				retErr = errors.Join(retErr, err)
			}
		default:
		}
	}()
	d.mu.Lock()
	if d.closed || d.serving || d.ctx.Err() != nil {
		d.mu.Unlock()
		return net.ErrClosed
	}
	d.serving = true
	d.workers.Go(func() {
		finished <- session.HandleNativeLegControl(d.ctx, func(ctx context.Context, selection tunnelv1.NativeLegBinding) error {
			return d.activate(ctx, a, proof, claim, selection)
		}, func(ctx context.Context, proof tunnelv1.NativePairLegProof) (tunnelv1.NativePairLegAccepted, error) {
			return d.renewClaim(ctx, a, d.transport, proof, claim)
		})
	})
	d.mu.Unlock()
	leaseCheck := time.NewTicker(100 * time.Millisecond)
	defer leaseCheck.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return nil
		case <-session.Done():
			return nil
		case err := <-finished:
			var protocol *tunnel.ProtocolError
			if errors.As(err, &protocol) {
				return err
			}
			if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case <-leaseCheck.C:
			lease, valid := a.currentLease(proof, a.now())
			if !valid {
				return nil
			}
			if current, ok := a.Publishers.nativeCandidate(claim.ref, lease, a.now()); !ok || current != d.connection {
				return nil
			}
		}
	}
}

// only the explicitly selected carrier may install publisher registration state.
// closing an authenticated but unselected candidate cannot spend its tombstone
// or displace a sibling's live replay state. handoff selects an exact predecessor.
func (d *nativePairDelivery) activate(ctx context.Context, a *NativeConnectorAcceptor, proof tunnelv1.NativePairLegProof, claim nativeConnectorClaim, selection tunnelv1.NativeLegBinding) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.activated || d.ctx.Err() != nil || ctx.Err() != nil || !d.deadline.After(a.now()) {
		return &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	}
	lease, valid := a.currentLease(proof, a.now())
	if current, present := a.Publishers.nativeCandidate(claim.ref, lease, a.now()); !valid || !present || current != d.connection {
		return &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
	}
	id, err := tunnelv1.ParsePeerDeliveryIdentifier(claim.receipt.DeliveryID)
	if err != nil {
		return errors.Join(&tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}, err)
	}
	d.bridge, err = d.publisher.selectNativeBridge(ctx, a, d, proof, claim, id, selection)
	if err != nil {
		return err
	}
	d.towardPublisher = d.bridge.publisher
	d.activated = true
	return nil
}

func forwardNativePackets(ctx context.Context, source, destination peer.Carrier, ready chan<- struct{}) error {
	for {
		frame, err := source.Receive(ctx)
		if err != nil {
			return err
		}
		write, cancel := context.WithTimeout(ctx, time.Second)
		err = destination.Send(write, frame)
		cancel()
		if err != nil {
			return err
		}
		if ready != nil {
			close(ready)
			ready = nil
		}
	}
}

func (d *nativePairDelivery) Close() {
	d.once.Do(func() {
		d.mu.Lock()
		d.closed = true
		d.mu.Unlock()
		d.cancel()
		d.stopPublisher()
		<-d.authorityDone
		if d.bridge != nil {
			d.bridge.detach(d)
		}
		if d.towardConnector != nil {
			_ = d.towardConnector.Close()
		}
		if d.connector != nil {
			d.connector.Close()
		}
		d.workers.Wait()
		d.publisher.mu.Lock()
		delete(d.publisher.jobs, d)
		d.publisher.mu.Unlock()
		close(d.done)
	})
}
