package peer

import (
	"context"
	"net"
	"sync"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

// SharedSession owns packet registrations on a borrowed, authenticated relay
// transport. role owners authorize registrations; this owner only selects QUIC
// datagrams or framed TLS streams and joins their readers before retirement.
type SharedSession struct {
	ctx       context.Context
	cancel    context.CancelFunc
	datagrams *SharedDatagrams
	streams   *SharedStreams
	done      chan struct{}
	once      sync.Once
}

// NewSharedSession takes exclusive acceptance of packet streams, not ownership
// of the transport. call it only after the transport's control handshake.
func NewSharedSession(ctx context.Context, outer muxsession.Session) (*SharedSession, error) {
	return newSharedSession(ctx, outer, false)
}

// NewDispatchedSharedSession leaves stream acceptance to the role's sole
// dispatcher, which must call AcceptIntroduction and join before Close.
func NewDispatchedSharedSession(ctx context.Context, outer muxsession.Session) (*SharedSession, error) {
	return newSharedSession(ctx, outer, true)
}

func newSharedSession(parent context.Context, outer muxsession.Session, dispatched bool) (*SharedSession, error) {
	if parent == nil || parent.Err() != nil || outer == nil {
		return nil, ErrConfiguration
	}
	ctx, cancel := context.WithCancel(parent)
	s := &SharedSession{ctx: ctx, cancel: cancel, done: make(chan struct{})}
	var err error
	if packets, ok := outer.(muxsession.DatagramSession); ok {
		// an unnegotiated QUIC transport is not a TLS stream fallback.
		s.datagrams, err = NewSharedDatagrams(ctx, packets)
	} else if dispatched {
		s.streams, err = NewDispatchedSharedStreams(ctx, outer)
	} else {
		s.streams, err = NewSharedStreams(ctx, outer)
	}
	if err != nil {
		cancel()
		return nil, err
	}
	go func() {
		defer close(s.done)
		select {
		case <-outer.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	return s, nil
}

func (s *SharedSession) Done() <-chan struct{} { return s.ctx.Done() }

func (s *SharedSession) Register(binding PairBinding, initiate bool) (Carrier, error) {
	return s.register(binding, initiate, nil)
}

// RegisterForwarding binds incoming packet admission to a replaceable destination
// before the registration is visible to readers. it retains that fence for the
// registration's lifetime, including while the destination is absent.
func (s *SharedSession) RegisterForwarding(binding PairBinding, initiate bool, destination *CarrierSlot) (*ForwardingRegistration, error) {
	if destination == nil {
		return nil, ErrConfiguration
	}
	publisher, err := s.register(binding, initiate, destination)
	if err != nil {
		return nil, err
	}
	return &ForwardingRegistration{publisher: publisher, connector: destination}, nil
}

func (s *SharedSession) register(binding PairBinding, initiate bool, destination *CarrierSlot) (forwardingCarrier, error) {
	if s.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if s.datagrams != nil {
		return s.datagrams.register(binding, destination)
	}
	pair, err := s.streams.register(binding, destination)
	if err != nil {
		return nil, err
	}
	return pair.Carrier(initiate), nil
}

func (s *SharedSession) AcceptIntroduction(ctx context.Context, stream muxsession.Stream) {
	if s.streams != nil {
		s.streams.AcceptIntroduction(ctx, stream)
	} else if stream != nil {
		_ = stream.Close()
	}
}

// Close retires only registrations, never the borrowed outer transport.
func (s *SharedSession) Close() error {
	s.once.Do(func() {
		s.cancel()
		if s.datagrams != nil {
			_ = s.datagrams.Close()
		}
		if s.streams != nil {
			_ = s.streams.Close()
		}
		<-s.done
	})
	return nil
}
