package service

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	yamux "github.com/libp2p/go-yamux/v5"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func claimedAwait[T any](t *testing.T, result <-chan T) T {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("claimed-session worker did not join")
		var zero T
		return zero
	}
}

// both sides use real verified WSS/yamux and the production tunnel handshake.
// wrapping the publisher transport changes only the explicitly injected fault.
func newClaimedTestPair(t *testing.T, bound *Bound, slot uint8, wrap func(muxsession.Session) muxsession.Session, wrapRelay ...func(muxsession.Session) muxsession.Session) (*Claimed, *tunnel.Session) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	serverTLS, roots := privateTransportTLS(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ref := bound.prepared.connectionRef(bound.connections[slot])
	type accepted struct {
		session *tunnel.Session
		err     error
	}
	remote, joined := make(chan accepted, 1), make(chan struct{})
	go func() {
		defer close(joined)
		conn, err := listener.Accept()
		if err != nil {
			remote <- accepted{err: err}
			return
		}
		outer, err := muxsession.AcceptWebSocket(ctx, conn, serverTLS, muxsession.WebSocketConfig{})
		if err != nil {
			_ = conn.Close()
			remote <- accepted{err: err}
			return
		}
		for _, apply := range wrapRelay {
			outer = apply(outer)
		}
		session, _, err := tunnel.Accept(ctx, outer, func(_ context.Context, hello tunnelv1.Message) error {
			if hello.ServiceConnection == nil || *hello.ServiceConnection != ref {
				return ErrPrivateStream
			}
			return nil
		})
		if err != nil {
			_ = outer.Close()
		}
		remote <- accepted{session, err}
	}()
	t.Cleanup(func() { cancel(); _ = listener.Close(); claimedAwait(t, joined) })
	outer, err := (muxsession.WebSocketConnector{TLSConfig: roots}).Connect(ctx, muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "relay.test"})
	if err != nil {
		t.Fatal(err)
	}
	if wrap != nil {
		outer = wrap(outer)
	}
	session, err := tunnel.Dial(ctx, outer, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version,
		Role: tunnelv1.Publisher, Credential: bound.connections[slot].PublisherConnectionCredential, ServiceConnection: &ref})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	relay := claimedAwait(t, remote)
	if relay.err != nil {
		t.Fatal(relay.err)
	}
	t.Cleanup(func() { _ = relay.session.Close() })
	dispatcher, err := tunnel.NewServiceStreamDispatcher(t.Context(), session, nil)
	if err != nil {
		t.Fatal(err)
	}
	claimed := &Claimed{bound: bound, ref: ref, session: session, dispatcher: dispatcher, transport: tunnel.TransportWSS}
	t.Cleanup(func() { _ = claimed.Close() })
	return claimed, relay.session
}

type claimedTerminalTransport struct {
	muxsession.Session
	entered chan struct{}
	result  chan error
	cleanup error
	closes  atomic.Int32
}

func (s *claimedTerminalTransport) AcceptStream(context.Context) (muxsession.Stream, error) {
	close(s.entered)
	return nil, <-s.result
}

func (s *claimedTerminalTransport) Close() error {
	s.closes.Add(1)
	return errors.Join(s.Session.Close(), s.cleanup)
}

func TestClaimedServeRetainsTerminalAcceptAndOwnerCloseFailures(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "accept-failure", true: "owner-cancellation"}[canceled], func(t *testing.T) {
			_, bound, _, _ := privateFixture(t, "127.0.0.1:1")
			acceptErr, closeErr := errors.New("terminal accept failed"), errors.New("owned session close failed")
			var wire *claimedTerminalTransport
			claimed, _ := newClaimedTestPair(t, bound, 0, func(outer muxsession.Session) muxsession.Session {
				wire = &claimedTerminalTransport{Session: outer, entered: make(chan struct{}), result: make(chan error, 1), cleanup: closeErr}
				return wire
			})
			type observation struct {
				err      error
				expected bool
			}
			observed := make(chan observation, 1)
			claimed.endObservation = func(err error, expected bool) {
				select {
				case observed <- observation{err, expected}:
				default:
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- claimed.Serve(ctx) }()
			claimedAwait(t, wire.entered)
			if canceled {
				cancel()
			}
			wire.result <- errors.Join(muxsession.ErrClosed, acceptErr)
			err := claimedAwait(t, done)
			if !errors.Is(err, acceptErr) || !errors.Is(err, closeErr) || wire.closes.Load() != 1 {
				t.Fatal("claimed owner discarded terminal failures or closed twice", err, wire.closes.Load())
			}
			summary := claimedAwait(t, observed)
			if !errors.Is(summary.err, acceptErr) || !errors.Is(summary.err, closeErr) || summary.expected != canceled {
				t.Fatal("claimed cleanup replaced the actual result observation", summary)
			}
			if err := claimed.Close(); !errors.Is(err, closeErr) || wire.closes.Load() != 1 {
				t.Fatal("claimed close lost its stable cleanup result", err)
			}
		})
	}
}

type acceptanceFaultTransport struct {
	muxsession.Session
	bound            *Bound
	calls            atomic.Int32
	resets           atomic.Int32
	permitsAtFailure atomic.Int32
	gated            chan struct{}
	proceed          chan struct{}
}

func (s *acceptanceFaultTransport) AcceptStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	switch s.calls.Add(1) {
	case 1:
		return &failedAcceptanceStream{Stream: stream, owner: s}, nil
	case 2:
		return &gatedAcceptanceStream{Stream: stream, owner: s}, nil
	default:
		return stream, nil
	}
}

type failedAcceptanceStream struct {
	muxsession.Stream
	owner *acceptanceFaultTransport
	once  sync.Once
}

func (s *failedAcceptanceStream) Write(p []byte) (int, error) {
	s.once.Do(func() {
		s.owner.bound.mu.Lock()
		s.owner.permitsAtFailure.Store(int32(s.owner.bound.reservedStreams))
		s.owner.bound.mu.Unlock()
		s.owner.resets.Add(1)
		_ = s.Stream.Reset(17)
	})
	return s.Stream.Write(p)
}

type gatedAcceptanceStream struct {
	muxsession.Stream
	owner *acceptanceFaultTransport
	once  sync.Once
}

func (s *gatedAcceptanceStream) SetDeadline(at time.Time) error {
	s.once.Do(func() {
		close(s.owner.gated)
		<-s.owner.proceed
	})
	return s.Stream.SetDeadline(at)
}

func TestClaimedAcceptanceFailureReleasesPermitAndKeepsHealthySibling(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var dials atomic.Int32
	targetDone := make(chan struct{})
	go func() {
		defer close(targetDone)
		conn, err := target.Accept()
		if err != nil {
			return
		}
		dials.Add(1)
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()
	t.Cleanup(func() { _ = target.Close(); claimedAwait(t, targetDone) })
	_, bound, ref, trust := privateFixture(t, target.Addr().String())
	var wire *acceptanceFaultTransport
	claimed, relay := newClaimedTestPair(t, bound, 0, func(outer muxsession.Session) muxsession.Session {
		wire = &acceptanceFaultTransport{Session: outer, bound: bound, gated: make(chan struct{}), proceed: make(chan struct{})}
		return wire
	})
	unblock := sync.OnceFunc(func() { close(wire.proceed) })
	t.Cleanup(unblock)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- claimed.Serve(ctx) }()
	t.Cleanup(func() {
		unblock()
		cancel()
		_ = relay.Close()
		if err := claimedAwait(t, done); err != nil {
			t.Error("stream-local failure escaped claimed owner shutdown", err)
		}
		bound.mu.Lock()
		defer bound.mu.Unlock()
		if bound.reservedStreams != 0 || len(bound.active) != 0 {
			t.Error("claimed owner returned before joining visitor capacity", bound.reservedStreams, len(bound.active))
		}
	})
	if stream, err := relay.OpenServiceForwardingStream(ctx, privateHeader(t, ref)); err == nil {
		_ = stream.Close()
		t.Fatal("failed acceptance was acknowledged")
	} else {
		var reset *yamux.StreamError
		if !errors.As(err, &reset) || !reset.Remote || reset.ErrorCode != 17 {
			t.Fatal("failed acceptance lost actual stream reset code", err)
		}
	}
	type opened struct {
		stream muxsession.Stream
		err    error
	}
	second := make(chan opened, 1)
	header := privateHeader(t, ref)
	go func() {
		stream, err := relay.OpenServiceForwardingStream(ctx, header)
		second <- opened{stream, err}
	}()
	claimedAwait(t, wire.gated)
	bound.mu.Lock()
	permits, visitors := bound.reservedStreams, len(bound.active)
	bound.mu.Unlock()
	if permits != 0 || visitors != 0 || dials.Load() != 0 || wire.resets.Load() != 1 || wire.permitsAtFailure.Load() != 1 {
		t.Fatal("failed acceptance retained capacity, target work, or a visitor", permits, visitors, dials.Load(), wire.resets.Load())
	}
	unblock()
	next := claimedAwait(t, second)
	if next.err != nil {
		t.Fatal("healthy sibling could not open on the same session", next.err)
	}
	defer next.stream.Close()
	metadata, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.10:40000"), Destination: netip.MustParseAddrPort("203.0.113.1:25443")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := next.stream.Write(metadata); err != nil {
		t.Fatal(err)
	}
	secure := tls.Client(next.stream, trust)
	if err := secure.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	const message = "healthy same-session sibling"
	if _, err := io.WriteString(secure, message); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(message))
	if _, err := io.ReadFull(secure, reply); err != nil || string(reply) != message || dials.Load() != 1 {
		t.Fatal("acceptance failure broke healthy target forwarding", string(reply), err, dials.Load())
	}
	if claimed.session.Err() != nil || relay.Err() != nil {
		t.Fatal("stream-local acceptance failure retired its shared session")
	}
}
