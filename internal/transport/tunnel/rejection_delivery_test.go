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
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// this contrast diagnoses rejection delivery, not an allowed peer error. the
// unmodified acceptor closes with the payload queued; holding that same close
// until the peer reads the frame proves the bytes and tls/yamux path are valid.
func TestPublisherRejectionSocketCloseOrdering(t *testing.T) {
	for _, holdClose := range []bool{false, true} {
		t.Run(map[bool]string{false: "production close", true: "close after frame read"}[holdClose], func(t *testing.T) {
			ctx := tunnelContext(t)
			serverTLS, clientTLS := realTunnelTLS(t)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			probe := &rejectionDeliveryProbe{ctx: ctx, holdClose: holdClose,
				headerRead: make(chan struct{}), frameRead: make(chan struct{}), writesReleased: make(chan struct{})}
			probe.releaseWrites = sync.OnceFunc(func() { close(probe.writesReleased) })
			cause := errors.New("durable claim rejected")
			rejection := errors.Join(cause, &ProtocolError{Code: tunnelv1.StaleConnectionAssignment})
			local := tunnelWorker(t, func() { probe.releaseWrites(); _ = listener.Close() }, func() error {
				network, err := listener.Accept()
				if err != nil {
					return err
				}
				transport, err := muxsession.AcceptTLSYamux(ctx, &rejectionPhysicalConn{Conn: network, probe: probe}, serverTLS, muxsession.TLSYamuxConfig{})
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
			transport, err := (muxsession.TLSYamuxConnector{TLSConfig: clientTLS}).Connect(ctx,
				muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "relay.test"})
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
			t.Logf("hold_close=%t; events=%v; peer=%v; local=%v; peer_close=%v",
				holdClose, probe.events, peerErr, localErr, probe.peerCloseErr)
			var wire bytes.Buffer
			if err := tunnelv1.WriteControl(&wire, tunnelv1.Message{Type: tunnelv1.Error, ProtocolVersion: tunnelv1.Version, Code: tunnelv1.StaleConnectionAssignment}); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(probe.queued, wire.Bytes()) || !probe.socketClosed || !probe.closeBeforeFrame {
				t.Fatal("contrast did not queue the exact rejection before production initiated socket cleanup")
			}
			if holdClose {
				var protocol *ProtocolError
				if !bytes.Equal(probe.received, wire.Bytes()) || probe.physicalAfterHeader == 0 ||
					!errors.As(peerErr, &protocol) || protocol.Code != tunnelv1.StaleConnectionAssignment || errors.Is(peerErr, io.ErrUnexpectedEOF) {
					t.Fatal("holding only socket close did not deliver the unchanged rejection", peerErr)
				}
			} else if len(probe.received) != 4 || probe.physicalAfterHeader != 0 || !errors.Is(peerErr, io.ErrUnexpectedEOF) {
				t.Fatal("production close did not reproduce header-only truncation", peerErr)
			}
			if probe.peerCloseErr != nil && !errors.Is(peerErr, probe.peerCloseErr) {
				t.Fatal("dial lost the actual owned cleanup result", peerErr, probe.peerCloseErr)
			}
		})
	}
}

type rejectionDeliveryProbe struct {
	ctx            context.Context
	holdClose      bool
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
		s.probe.mu.Unlock()
		if s.probe.holdClose {
			s.probe.releaseWrites()
			select {
			case <-s.probe.frameRead:
			case <-s.probe.ctx.Done():
				return errors.Join(context.Cause(s.probe.ctx), s.Session.Close())
			}
		}
		return s.Session.Close()
	}
	err := s.Session.Close()
	s.probe.mu.Lock()
	s.probe.peerCloseErr = err
	s.probe.mu.Unlock()
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
	n, err := s.Stream.Read(p)
	if !s.server {
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
