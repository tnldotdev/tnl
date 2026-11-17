package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/testutil/transporttest"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// hold physical output after the peer consumes the header. only the producer's
// acknowledgement read releases it; no test barrier delays session cleanup.
func TestPublisherRejectionRetainsQueuedFrame(t *testing.T) {
	for _, kind := range []string{"wss", "quic"} {
		t.Run(kind, func(t *testing.T) {
			ctx := tunnelContext(t)
			serverTLS, clientTLS := realTunnelTLS(t)
			probe := &rejectionDeliveryProbe{ctx: ctx, quic: kind == "quic",
				headerRead: make(chan struct{}), frameRead: make(chan struct{}), writesReleased: make(chan struct{})}
			probe.releaseWrites = sync.OnceFunc(func() { close(probe.writesReleased) })
			var address string
			var accept func() (muxsession.Session, error)
			var closeListener func() error
			var connector muxsession.Connector
			if probe.quic {
				packet, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				listener, err := muxsession.ListenQUICPacket(&rejectionPacketConn{PacketConn: packet, probe: probe}, serverTLS, muxsession.QUICConfig{BasicPacketConn: true})
				if err != nil {
					t.Fatal(err)
				}
				address, closeListener = listener.Addr().String(), listener.Close
				accept = func() (muxsession.Session, error) { return listener.Accept(ctx) }
				connector = muxsession.QUICConnector{TLSConfig: clientTLS, Dialer: transporttest.QUICTransport(t)}
			} else {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				address, closeListener = listener.Addr().String(), listener.Close
				accept = func() (muxsession.Session, error) {
					network, err := listener.Accept()
					if err != nil {
						return nil, err
					}
					return muxsession.AcceptWebSocket(ctx, &rejectionPhysicalConn{Conn: network, probe: probe}, serverTLS, muxsession.WebSocketConfig{})
				}
				connector = muxsession.WebSocketConnector{TLSConfig: clientTLS}
			}
			t.Cleanup(func() { probe.releaseWrites(); _ = closeListener() })
			cause := errors.New("durable claim rejected")
			rejection := errors.Join(cause, &ProtocolError{Code: tunnelv1.StaleConnectionAssignment})
			local := tunnelWorker(t, func() { probe.releaseWrites(); _ = closeListener() }, func() error {
				transport, err := accept()
				if err != nil {
					return err
				}
				_, _, err = Accept(ctx, &rejectionDeliverySession{Session: transport, probe: probe, server: true}, func(context.Context, tunnelv1.Message) error {
					return rejection
				})
				// Accept owns failed-handshake cleanup; no fixture session close
				// runs before this result is returned and all its i/o has joined.
				return err
			})
			transport, err := connector.Connect(ctx, muxsession.Endpoint{Address: address, ServerName: "relay.test"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = transport.Close() })
			session, peerErr := Dial(ctx, &rejectionDeliverySession{Session: transport, probe: probe}, publisherHello())
			localErr := await(t, local)
			if session != nil || !failure.Only(localErr, rejection) || !errors.Is(localErr, cause) || context.Cause(ctx) != nil {
				t.Fatalf("rejection changed authority, cleanup, or deadline: session=%v local=%v context=%v", session != nil, localErr, context.Cause(ctx))
			}
			probe.mu.Lock()
			defer probe.mu.Unlock()
			t.Logf("events=%v; peer=%v; local=%v; peer_close=%v", probe.events, peerErr, localErr, probe.peerCloseErr)
			var wire bytes.Buffer
			if err := tunnelv1.WriteControl(&wire, tunnelv1.Message{Type: tunnelv1.Error, ProtocolVersion: tunnelv1.Version, Code: tunnelv1.StaleConnectionAssignment}); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(probe.queued, wire.Bytes()) || !probe.socketClosed || probe.closeBeforeFrame ||
				!probe.serverAckRead || !probe.peerEndObserved || probe.peerClosedBeforeEnd {
				t.Fatal("rejected hello retired before the exact frame, acknowledgement, and session end joined")
			}
			var protocol *ProtocolError
			if !bytes.Equal(probe.received, wire.Bytes()) || probe.physicalAfterHeader == 0 ||
				!errors.As(peerErr, &protocol) || protocol.Code != tunnelv1.StaleConnectionAssignment || !failure.Only(peerErr, protocol) {
				t.Fatal("producer lost the exact rejection or joined an independent operation/cleanup failure", peerErr)
			}
			if probe.peerCloseErr != nil && !errors.Is(peerErr, probe.peerCloseErr) {
				t.Fatal("dial lost the actual owned cleanup result", peerErr, probe.peerCloseErr)
			}
		})
	}
}

type rejectionDeliveryProbe struct {
	ctx            context.Context
	quic           bool
	headerRead     chan struct{}
	frameRead      chan struct{}
	writesReleased chan struct{}
	releaseWrites  func()
	armed          atomic.Bool
	headerOnce     sync.Once
	frameOnce      sync.Once

	mu                  sync.Mutex
	events              []string
	queued              []byte
	received            []byte
	physicalAfterHeader int
	socketClosed        bool
	closeBeforeFrame    bool
	peerCloseErr        error
	serverAckRead       bool
	peerEndObserved     bool
	peerClosedBeforeEnd bool
}

type rejectionPacketConn struct {
	net.PacketConn
	probe *rejectionDeliveryProbe
}

func (c *rejectionPacketConn) WriteTo(p []byte, address net.Addr) (int, error) {
	gated := c.probe.armed.Load()
	if gated {
		<-c.probe.writesReleased
	}
	n, err := c.PacketConn.WriteTo(p, address)
	if gated {
		c.probe.mu.Lock()
		c.probe.physicalAfterHeader += n
		c.probe.events = append(c.probe.events, fmt.Sprintf("physical packet after header=%d err=%v", n, err))
		c.probe.mu.Unlock()
	}
	return n, err
}

type rejectionPhysicalConn struct {
	net.Conn
	probe *rejectionDeliveryProbe
}

func (c *rejectionPhysicalConn) Write(p []byte) (int, error) {
	gated := c.probe.armed.Load()
	if gated {
		<-c.probe.writesReleased
	}
	// use the actual socket result, including when production closes it while
	// this physical write is held. no synthetic eof or reset is introduced.
	n, err := c.Conn.Write(p)
	if gated {
		c.probe.mu.Lock()
		c.probe.physicalAfterHeader += n
		c.probe.events = append(c.probe.events, fmt.Sprintf("physical write after header=%d err=%v", n, err))
		c.probe.mu.Unlock()
	}
	return n, err
}

func (c *rejectionPhysicalConn) Close() error {
	err := c.Conn.Close()
	c.probe.mu.Lock()
	c.probe.socketClosed = true
	c.probe.events = append(c.probe.events, fmt.Sprintf("physical socket close err=%v", err))
	c.probe.mu.Unlock()
	c.probe.releaseWrites()
	return err
}

type rejectionDeliverySession struct {
	muxsession.Session
	probe  *rejectionDeliveryProbe
	server bool
}

func (s *rejectionDeliverySession) AcceptStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &rejectionDeliveryStream{Stream: stream, probe: s.probe, server: true}, nil
}

func (s *rejectionDeliverySession) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	return &rejectionDeliveryStream{Stream: stream, probe: s.probe}, nil
}

func (s *rejectionDeliverySession) Close() error {
	if s.server {
		s.probe.mu.Lock()
		s.probe.closeBeforeFrame = len(s.probe.received) < len(s.probe.queued)
		s.probe.events = append(s.probe.events, "production requested outer session close")
		s.probe.socketClosed = true
		s.probe.mu.Unlock()
		if s.probe.quic {
			// unblock transport shutdown too, but record premature close above.
			// this does not hold or replace the producer's actual Close.
			s.probe.releaseWrites()
		}
		return s.Session.Close()
	}
	s.probe.mu.Lock()
	s.probe.peerClosedBeforeEnd = !s.probe.peerEndObserved
	s.probe.mu.Unlock()
	err := s.Session.Close()
	s.probe.mu.Lock()
	s.probe.peerCloseErr = err
	s.probe.mu.Unlock()
	return err
}

func (s *rejectionDeliverySession) Err() error {
	err := s.Session.Err()
	if !s.server {
		select {
		case <-s.Session.Done():
			s.probe.mu.Lock()
			s.probe.peerEndObserved = true
			s.probe.events = append(s.probe.events, fmt.Sprintf("peer joined session end=%v", err))
			s.probe.mu.Unlock()
		default:
		}
	}
	return err
}

type rejectionDeliveryStream struct {
	muxsession.Stream
	probe  *rejectionDeliveryProbe
	server bool
}

func (s *rejectionDeliveryStream) Write(p []byte) (int, error) {
	n, err := s.Stream.Write(p)
	if s.server {
		s.probe.mu.Lock()
		s.probe.queued = append(s.probe.queued, p[:n]...)
		total := len(s.probe.queued)
		s.probe.events = append(s.probe.events, fmt.Sprintf("stream queued=%d err=%v", n, err))
		s.probe.mu.Unlock()
		if total == 4 && err == nil {
			// let the real peer consume the frame header before holding all
			// subsequent physical writes, including the queued json payload.
			select {
			case <-s.probe.headerRead:
				s.probe.armed.Store(true)
			case <-s.probe.ctx.Done():
				return n, context.Cause(s.probe.ctx)
			}
		}
	}
	return n, err
}

func (s *rejectionDeliveryStream) Read(p []byte) (int, error) {
	if s.server {
		s.probe.mu.Lock()
		ack := len(s.probe.queued) > 4
		s.probe.mu.Unlock()
		if ack {
			s.probe.releaseWrites()
		}
	}
	n, err := s.Stream.Read(p)
	if s.server && n == 0 && err == io.EOF {
		s.probe.mu.Lock()
		s.probe.serverAckRead = true
		s.probe.events = append(s.probe.events, "server consumed acknowledgement FIN")
		s.probe.mu.Unlock()
	} else if !s.server {
		s.probe.mu.Lock()
		s.probe.received = append(s.probe.received, p[:n]...)
		total := len(s.probe.received)
		s.probe.events = append(s.probe.events, fmt.Sprintf("peer read=%d err=%v", n, err))
		if total >= 4 {
			s.probe.headerOnce.Do(func() { close(s.probe.headerRead) })
			if total == 4+int(binary.BigEndian.Uint32(s.probe.received[:4])) {
				s.probe.frameOnce.Do(func() { close(s.probe.frameRead) })
			}
		}
		s.probe.mu.Unlock()
	}
	return n, err
}
