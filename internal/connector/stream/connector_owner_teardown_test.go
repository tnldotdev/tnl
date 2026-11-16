package stream

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/testutil/connectorfixture"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// these causal controls project the current shared cancellation lifetime and an
// explicitly retained packet lifetime onto real endpoints and inner QUIC. they
// do not replace default-composition, authority, audit, or publisher-drain tests.
func TestConnectorOwnerTeardownSeparatesCompletionProductionFromDelivery(t *testing.T) {
	for _, retainPackets := range []bool{false, true} {
		t.Run(map[bool]string{false: "current-shared-cancellation", true: "packets-kept-alive"}[retainPackets], func(t *testing.T) {
			f := newOwnerTeardownFixture(t, retainPackets, false)
			response := bytes.Repeat([]byte("return-delivery\n"), 180224/16+1)[:180224]
			forward := f.forward(t)
			f.request(t)
			target := f.respond(response)

			ownerTeardownAwait(t, f.ctx, f.returnWrite.entered)
			ownerTeardownPending(t, forward, "blocked actual return copy joined")
			ownerTeardownPending(t, f.writes, "blocked return copy produced completion")
			ownerTeardownPending(t, f.receipts, "request FIN acknowledged return delivery")
			f.returnWrite.open()
			got, err := io.ReadAll(f.input)
			if err != nil || !bytes.Equal(got, response) {
				t.Fatal("actual return copy lost bytes", len(got), len(response), err)
			}
			if err := ownerTeardownAwait(t, f.ctx, target); err != nil {
				t.Fatal("target response", err)
			}
			ownerTeardownAwait(t, f.ctx, f.cleanup.latch.entered)
			// the local destination has emitted EOF, but the real prepared owner
			// has not returned from physical cleanup or joined its permission work.
			ownerTeardownPending(t, forward, "local EOF was mistaken for joined cleanup")
			ownerTeardownPending(t, f.writes, "unfinished cleanup produced completion")
			f.cleanup.latch.open()

			written := ownerTeardownAwait(t, f.ctx, f.writes)
			if written.err != nil || written.n != written.size || written.receipt != f.receipt {
				t.Fatal("completion did not write its exact original identity", written)
			}
			ownerTeardownPending(t, forward, "local completion write fabricated a matched remote result")
			ownerTeardownAwait(t, f.ctx, f.outbound.entered)
			ownerTeardownPending(t, f.receipts, "gated completion was already decoded")
			f.stopOwner(context.Canceled)
			f.owner.mu.Lock()
			current := f.owner.currentLocked()
			f.owner.mu.Unlock()
			if current {
				t.Fatal("retaining packets retained local serving authority")
			}

			if !retainPackets {
				if err := ownerTeardownAwait(t, f.ctx, forward); err == nil {
					t.Fatal("lost completion/result was classified as successful")
				}
				// this is the actual current close operation. the endpoint joins
				// its canceled carrier sends before the gate is released.
				_ = f.owner.Close(context.WithoutCancel(f.ctx))
				ownerTeardownAwait(t, f.ctx, f.outbound.interrupted)
				f.outbound.open()
				ownerTeardownPending(t, f.receipts, "canceled carrier delivered after joining")
				ownerTeardownPending(t, f.controlDone, "fixture close invented remote termination")
				if f.server.Err() != nil || f.ctx.Err() != nil {
					t.Fatal("missing completion was caused by expired publisher lifetime", f.server.Err(), f.ctx.Err())
				}
				t.Log("causal failure observed: successful joined copy and completion write, canceled packet delivery, no publisher completion")
				return
			}

			// only local operation cancellation differs. no frame, permission,
			// source, generation, target, copy workload, or deadline is replaced.
			f.outbound.open()
			if got := ownerTeardownAwait(t, f.ctx, f.receipts); got != f.receipt {
				t.Fatal("retained packet delivery changed exact completion", got)
			}
			if err := ownerTeardownAwait(t, f.ctx, forward); err != nil {
				t.Fatal("actual return copy, remote join, result, and observed write did not join", err)
			}
			if f.owner.permissions.Err() != nil || f.ctx.Err() != nil {
				t.Fatal("completion required permission renewal or expired its original budget", f.owner.permissions.Err(), f.ctx.Err())
			}
		})
	}
}

func TestConnectorOwnerTeardownSeparatesLocalAbortFromRemoteReadTermination(t *testing.T) {
	for _, retainPackets := range []bool{false, true} {
		t.Run(map[bool]string{false: "current-shared-cancellation", true: "packets-kept-alive"}[retainPackets], func(t *testing.T) {
			f := newOwnerTeardownFixture(t, retainPackets, false)
			f.returnWrite.open()
			f.cleanup.latch.open()
			forward := f.forward(t)
			if _, err := io.WriteString(f.input, "request\n"); err != nil {
				t.Fatal(err)
			}
			var request [8]byte
			if _, err := io.ReadFull(f.remote, request[:]); err != nil || string(request[:]) != "request\n" {
				t.Fatal("admitted request did not reach the remote copy", request, err)
			}
			if _, err := io.WriteString(f.remote, "response"); err != nil {
				t.Fatal(err)
			}
			var response [8]byte
			if _, err := io.ReadFull(f.input, response[:]); err != nil || string(response[:]) != "response" {
				t.Fatal("active stream did not serve return traffic", response, err)
			}
			remoteRead := make(chan error, 1)
			f.remoteWorkers.Go(func() { _, err := io.Copy(io.Discard, f.remote); remoteRead <- err })
			f.outbound.arm()
			// hold real application data so cancellation and the following TLS
			// close/inner FIN have a deterministically unavailable packet path.
			if _, err := io.WriteString(f.input, "unfinished\n"); err != nil {
				t.Fatal(err)
			}
			ownerTeardownAwait(t, f.ctx, f.outbound.entered)
			ownerTeardownPending(t, remoteRead, "active remote read ended before owner stop")
			f.stopOwner(context.Canceled)
			ownerTeardownAwait(t, f.ctx, f.local.ctx.Done())
			ownerTeardownPending(t, f.writes, "aborted local copy sent successful completion")
			if !retainPackets {
				if err := ownerTeardownAwait(t, f.ctx, forward); err == nil {
					t.Fatal("aborted local copy manufactured success")
				}
				_ = f.owner.Close(context.WithoutCancel(f.ctx))
				ownerTeardownAwait(t, f.ctx, f.outbound.interrupted)
				f.outbound.open()
				ownerTeardownPending(t, remoteRead, "local cancellation invented remote termination")
				if f.server.Err() != nil || f.ctx.Err() != nil {
					t.Fatal("remote read was not live within its original authority", f.server.Err(), f.ctx.Err())
				}
				t.Log("causal failure observed: local copy joined its abort while the remote application read remained live")
				return
			}
			ownerTeardownPending(t, forward, "local abort fabricated remote joined abort")
			f.outbound.open()
			if err := ownerTeardownAwait(t, f.ctx, forward); err == nil {
				t.Fatal("joined abort erased the original copy failure")
			}
			if err := ownerTeardownAwait(t, f.ctx, remoteRead); err != nil {
				var timeout net.Error
				if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout() {
					t.Fatal("retained packets did not deliver termination before the original deadline", err)
				}
			}
			ownerTeardownPending(t, f.receipts, "remote termination fabricated successful delivery")
		})
	}
}

func TestConnectorOwnerTeardownDoesNotCompleteFailedCopyOrCleanup(t *testing.T) {
	for _, failure := range []string{"remote-reset", "independent-cleanup", "cleanup-racing-cancellation"} {
		t.Run(failure, func(t *testing.T) {
			f := newOwnerTeardownFixture(t, true, false)
			independent := errors.New("independent physical connector cleanup failure")
			if failure != "remote-reset" {
				f.cleanup.failure = independent
			}
			f.returnWrite.open()
			if failure != "cleanup-racing-cancellation" {
				f.cleanup.latch.open()
			}
			forward := f.forward(t)
			f.request(t)
			if failure == "remote-reset" {
				if err := f.remoteRaw.Reset(9); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := ownerTeardownAwait(t, f.ctx, f.respond([]byte("final response"))); err != nil {
					t.Fatal(err)
				}
				if got, err := io.ReadAll(f.input); err != nil || string(got) != "final response" {
					t.Fatal("cleanup control did not first deliver the response", string(got), err)
				}
				if failure == "cleanup-racing-cancellation" {
					ownerTeardownAwait(t, f.ctx, f.cleanup.latch.entered)
					f.stopOwner(context.Canceled)
					f.cleanup.latch.open()
				}
			}
			ownerTeardownAwait(t, f.ctx, f.outbound.entered)
			ownerTeardownPending(t, forward, "failed local work fabricated a remote joined abort")
			ownerTeardownPending(t, f.receipts, "failed local work produced completion")
			f.outbound.open()
			err := ownerTeardownAwait(t, f.ctx, forward)
			if err == nil {
				t.Fatal("failed forwarding was classified as successful")
			}
			if failure == "remote-reset" {
				var reset *quic.StreamError
				if !errors.As(err, &reset) || !reset.Remote || reset.ErrorCode != 9 {
					t.Fatal("copy lost its independent remote reset", err)
				}
			} else if !errors.Is(err, independent) {
				t.Fatal("joined cleanup failure was lost", err)
			}
			if failure != "cleanup-racing-cancellation" && f.owner.ctx.Err() != nil {
				t.Fatal("one visitor's failure retired the still-current owner", context.Cause(f.owner.ctx))
			}
			if failure != "remote-reset" {
				f.owner.mu.Lock()
				cleanupErr := f.owner.useErr
				f.owner.mu.Unlock()
				if !errors.Is(cleanupErr, independent) {
					t.Fatal("owner shutdown lost its independent child cleanup failure", cleanupErr)
				}
			}
			f.stopOwner(context.Canceled)
			ownerTeardownPending(t, f.writes, "failed copy or cleanup produced completion")
			ownerTeardownPending(t, f.receipts, "failed copy or cleanup fabricated delivery")
			if f.owner.permissions.Err() != nil {
				t.Fatal("one failed application stopped retained permission control", f.owner.permissions.Err())
			}
		})
	}
}

// actual carrier delivery of CONNECTION_CLOSE is still not application-reader
// consumption of an earlier completion. the control decoder is held after its
// real handshake while application preparation and both copies run normally.
func TestConnectorOwnerTeardownDeliveredConnectionCloseDoesNotAcknowledgeCompletion(t *testing.T) {
	f := newOwnerTeardownFixture(t, true, true)
	f.returnWrite.open()
	f.cleanup.latch.open()
	forward := f.forward(t)
	f.request(t)
	target := f.respond([]byte("complete response"))
	if got, err := io.ReadAll(f.input); err != nil || string(got) != "complete response" {
		t.Fatal("return copy did not finish", string(got), err)
	}
	if err := ownerTeardownAwait(t, f.ctx, target); err != nil {
		t.Fatal(err)
	}
	written := ownerTeardownAwait(t, f.ctx, f.writes)
	if written.err != nil || written.n != written.size || written.receipt != f.receipt {
		t.Fatal("completion was not successfully produced", written)
	}
	ownerTeardownPending(t, forward, "held decoder fabricated a matched result")
	ownerTeardownAwait(t, f.ctx, f.controlRead.entered)
	ownerTeardownAwait(t, f.ctx, f.outbound.entered)
	ownerTeardownPending(t, f.receipts, "held control reader dispatched completion")
	if err := f.owner.session.Close(); err != nil {
		t.Fatal("local inner QUIC close", err)
	}
	ownerTeardownPending(t, f.server.Done(), "gated carriers invented remote close")
	f.outbound.open()
	ownerTeardownAwait(t, f.ctx, f.server.Done())
	var remoteClose *quic.ApplicationError
	if !errors.As(f.server.Err(), &remoteClose) || !remoteClose.Remote || remoteClose.ErrorCode != 0 {
		t.Fatal("retained carriers did not deliver actual normal connection close", f.server.Err())
	}
	f.controlRead.open()
	err := ownerTeardownAwait(t, f.ctx, f.controlDone)
	if !errors.As(err, &remoteClose) || !remoteClose.Remote || remoteClose.ErrorCode != 0 {
		t.Fatal("held control decoder did not observe connection shutdown", err)
	}
	ownerTeardownPending(t, f.receipts, "connection close fabricated completion dispatch")
	if err := ownerTeardownAwait(t, f.ctx, forward); err == nil {
		t.Fatal("delivered connection close manufactured completion success")
	}
	if f.ctx.Err() != nil {
		t.Fatal("fixture expiry, not delivered close, ended the control decoder", context.Cause(f.ctx))
	}
	t.Log("causal failure observed: joined copy and successful completion write, actually delivered normal close, no publisher completion dispatch")
}

type ownerTeardownLatch struct {
	entered chan struct{}
	release chan struct{}
	enter   sync.Once
	unblock sync.Once
}

func newOwnerTeardownLatch() *ownerTeardownLatch {
	return &ownerTeardownLatch{entered: make(chan struct{}), release: make(chan struct{})}
}

func (g *ownerTeardownLatch) open() { g.unblock.Do(func() { close(g.release) }) }

func (g *ownerTeardownLatch) wait(ctx context.Context) error {
	g.enter.Do(func() { close(g.entered) })
	select {
	case <-g.release:
		return context.Cause(ctx)
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

type ownerTeardownOutbound struct {
	*ownerTeardownLatch
	mu          sync.Mutex
	armed       bool
	interrupted chan struct{}
	interrupt   sync.Once
}

func (g *ownerTeardownOutbound) arm() { g.mu.Lock(); g.armed = true; g.mu.Unlock() }

func (g *ownerTeardownOutbound) waitCarrier(ctx, carrier context.Context) error {
	g.enter.Do(func() { close(g.entered) })
	select {
	case <-g.release:
	case <-ctx.Done():
	case <-carrier.Done():
	}
	return errors.Join(context.Cause(ctx), context.Cause(carrier))
}

// the carrier blocks only authenticated peer data after setup, on both relay
// paths. probe frames are not themselves gated. no tracer grants authority.
type ownerTeardownCarrier struct {
	ctx      context.Context
	cancel   context.CancelFunc
	input    chan []byte
	output   chan []byte
	key      [32]byte
	outbound *ownerTeardownOutbound
}

func (c *ownerTeardownCarrier) Send(ctx context.Context, frame []byte) error {
	if c.outbound != nil {
		packet, err := tunnelv1.VerifyPeerPacketFrame(frame, c.key)
		if err != nil {
			return err
		}
		c.outbound.mu.Lock()
		hold := c.outbound.armed && packet.Kind == tunnelv1.PeerData
		c.outbound.mu.Unlock()
		if hold {
			if err := c.outbound.waitCarrier(ctx, c.ctx); err != nil {
				c.outbound.interrupt.Do(func() { close(c.outbound.interrupted) })
				return err
			}
		}
	}
	// a released test gate is not permission to deliver a canceled send.
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if err := context.Cause(c.ctx); err != nil {
		return err
	}
	select {
	case c.output <- bytes.Clone(frame):
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-c.ctx.Done():
		return context.Cause(c.ctx)
	}
}

func (c *ownerTeardownCarrier) Receive(ctx context.Context) ([]byte, error) {
	select {
	case frame := <-c.input:
		return frame, nil
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-c.ctx.Done():
		return nil, context.Cause(c.ctx)
	}
}

// local carrier closure deliberately does not notify the remote carrier. real
// relay packet loss also does not create an inner QUIC FIN or completion.
func (c *ownerTeardownCarrier) Close() error { c.cancel(); return nil }

type ownerTeardownReturnConn struct {
	net.Conn
	tcp    *net.TCPConn
	ctx    context.Context
	cancel context.CancelFunc
	latch  *ownerTeardownLatch
}

func (c *ownerTeardownReturnConn) Write(p []byte) (int, error) {
	if err := c.latch.wait(c.ctx); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

func (c *ownerTeardownReturnConn) CloseWrite() error { return c.tcp.CloseWrite() }

func (c *ownerTeardownReturnConn) Close() error { c.cancel(); return c.Conn.Close() }

type ownerTeardownCleanupConn struct {
	net.Conn
	ctx      context.Context
	latch    *ownerTeardownLatch
	outbound *ownerTeardownOutbound
	failure  error
	once     sync.Once
	err      error
}

func (c *ownerTeardownCleanupConn) CloseWrite() error {
	return c.Conn.(*tls.Conn).CloseWrite()
}

func (c *ownerTeardownCleanupConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.outbound.arm()
		c.err = errors.Join(c.err, c.latch.wait(c.ctx), c.failure)
	})
	return c.err
}

type ownerTeardownCompletionWrite struct {
	receipt tunnelv1.ConnectorVisitorCompletion
	n, size int
	err     error
}

type ownerTeardownPermissionSession struct {
	muxsession.Session
	writes chan ownerTeardownCompletionWrite
}

func (s ownerTeardownPermissionSession) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	return ownerTeardownPermissionStream{Stream: stream, writes: s.writes}, nil
}

type ownerTeardownPermissionStream struct {
	muxsession.Stream
	writes chan ownerTeardownCompletionWrite
}

func (s ownerTeardownPermissionStream) Write(p []byte) (int, error) {
	n, err := s.Stream.Write(p)
	var receipt tunnelv1.ConnectorVisitorCompletion
	if json.Unmarshal(p, &receipt) == nil && receipt.Kind == tunnelv1.ConnectorVisitorCompleted {
		s.writes <- ownerTeardownCompletionWrite{receipt: receipt, n: n, size: len(p), err: err}
	}
	return n, err
}

type ownerTeardownControlStream struct {
	muxsession.Stream
	ctx   context.Context
	latch *ownerTeardownLatch
}

func (s ownerTeardownControlStream) Read(p []byte) (int, error) {
	if err := s.latch.wait(s.ctx); err != nil {
		return 0, err
	}
	return s.Stream.Read(p)
}

type ownerTeardownFixture struct {
	ctx             context.Context
	stopOwner       context.CancelCauseFunc
	owner           *connectorConnection
	prepared        *PreparedConnector
	server          muxsession.Session
	serverPacket    *peer.Endpoint
	serverQUIC      *quic.Transport
	listener        *quic.Listener
	local           *ownerTeardownReturnConn
	input           *net.TCPConn
	remote          *tls.Conn
	remoteRaw       muxsession.Stream
	cleanup         *ownerTeardownCleanupConn
	returnWrite     *ownerTeardownLatch
	controlRead     *ownerTeardownLatch
	outbound        *ownerTeardownOutbound
	writes          chan ownerTeardownCompletionWrite
	receipts        chan tunnelv1.ConnectorVisitorCompletion
	controlDone     chan error
	receipt         tunnelv1.ConnectorVisitorCompletion
	workers         sync.WaitGroup
	remoteWorkers   sync.WaitGroup
	remoteMu        sync.Mutex
	remoteSealed    bool
	remoteErr       error
	remoteVisitor   *connectorfixture.JoinedVisitor
	remoteInitDone  chan struct{}
	terminalEntered chan tunnelv1.ConnectorVisitorTerminalRequest
}

func newOwnerTeardownFixture(t *testing.T, retainPackets, holdControlRead bool) *ownerTeardownFixture {
	t.Helper()
	ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
	operation, stopOwner := context.WithCancelCause(ctx)
	f := &ownerTeardownFixture{ctx: ctx, stopOwner: stopOwner,
		returnWrite: newOwnerTeardownLatch(),
		controlRead: newOwnerTeardownLatch(),
		outbound:    &ownerTeardownOutbound{ownerTeardownLatch: newOwnerTeardownLatch(), interrupted: make(chan struct{})},
		writes:      make(chan ownerTeardownCompletionWrite, 4), receipts: make(chan tunnelv1.ConnectorVisitorCompletion, 4),
		controlDone: make(chan error, 1), remoteInitDone: make(chan struct{}), terminalEntered: make(chan tunnelv1.ConnectorVisitorTerminalRequest, 1)}
	if !holdControlRead {
		f.controlRead.open()
	}
	cleanupLatch := newOwnerTeardownLatch()
	t.Cleanup(func() {
		stop()
		stopOwner(context.Canceled)
		f.returnWrite.open()
		f.controlRead.open()
		cleanupLatch.open()
		f.outbound.open()
		if f.input != nil {
			_ = f.input.Close()
		}
		if f.local != nil {
			_ = f.local.Close()
		}
		if f.prepared != nil {
			_ = f.prepared.Close()
		}
		if f.owner != nil {
			_ = f.owner.Close(context.WithoutCancel(ctx))
		}
		if f.server != nil {
			_ = f.server.Close()
		}
		if f.listener != nil {
			_ = f.listener.Close()
		}
		if f.serverQUIC != nil {
			_ = f.serverQUIC.Close()
		}
		if f.serverPacket != nil {
			_ = f.serverPacket.Close()
		}
		f.workers.Wait()
	})
	packetLife := operation
	if retainPackets {
		packetLife = ctx
	}
	key := [32]byte{7, 11, 19}
	var connectorPaths, publisherPaths [2]peer.Carrier
	for slot := range 2 {
		left, right := make(chan []byte, 64), make(chan []byte, 64)
		localLife, closeLocal := context.WithCancel(packetLife)
		remoteLife, closeRemote := context.WithCancel(ctx)
		connectorPaths[slot] = &ownerTeardownCarrier{ctx: localLife, cancel: closeLocal, input: left, output: right, key: key, outbound: f.outbound}
		publisherPaths[slot] = &ownerTeardownCarrier{ctx: remoteLife, cancel: closeRemote, input: right, output: left, key: key}
	}
	endpoint, err := peer.New(packetLife, peer.Config{Key: key, Role: 0, Paths: connectorPaths})
	if err != nil {
		t.Fatal(err)
	}
	packetCtx, packetCancel := context.WithCancelCause(packetLife)
	f.owner = &connectorConnection{ctx: operation, endpoint: endpoint, packetCtx: packetCtx, packetCancel: packetCancel, cleanup: newConnectorCleanup(ctx, func() context.Context { return ctx }),
		active: make(map[*connectorUse]struct{}), refill: make(chan struct{}, 1)}
	f.stopOwner = func(cause error) { f.owner.cleanup.begin(); stopOwner(cause) }
	f.owner.cancel = f.stopOwner
	f.serverPacket, err = peer.New(ctx, peer.Config{Key: key, Role: 1, Paths: publisherPaths})
	if err != nil {
		t.Fatal(err)
	}
	root, certificate := providerCertificate(t)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(root) {
		t.Fatal("test certificate root")
	}
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{muxsession.ALPN}, Certificates: []tls.Certificate{certificate}}
	clientTLS := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{muxsession.ALPN}, RootCAs: roots, ServerName: "db.example"}
	f.owner.transport, f.serverQUIC = &quic.Transport{Conn: endpoint}, &quic.Transport{Conn: f.serverPacket}
	f.listener, err = f.serverQUIC.Listen(serverTLS, tunnel.ConnectorQUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan *quic.Conn, 1)
	acceptErr := make(chan error, 1)
	f.workers.Go(func() {
		connection, err := f.listener.Accept(ctx)
		if err != nil {
			acceptErr <- err
		} else {
			accepted <- connection
		}
	})
	connection, err := f.owner.transport.Dial(ctx, endpoint.RemoteAddr(), clientTLS, tunnel.ConnectorQUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	f.owner.connection = connection
	f.owner.session, err = muxsession.AdoptQUIC(connection)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case connection := <-accepted:
		f.server, err = muxsession.AdoptQUIC(connection)
	case err = <-acceptErr:
	case <-ctx.Done():
		err = context.Cause(ctx)
	}
	if err != nil {
		t.Fatal(err)
	}
	f.workers.Go(func() {
		control, err := tunnel.AcceptConnectorPermissionControl(ctx, f.server)
		if err != nil {
			f.controlDone <- err
			return
		}
		var suspension tunnel.ConnectorPermissionGate
		observed := ownerTeardownControlStream{Stream: control, ctx: ctx, latch: f.controlRead}
		controlOwner := connectorfixture.NewJoinedControl(ctx, connectorTestControlScope(), func(key tunnelv1.ConnectorVisitorTerminalKey) *connectorfixture.JoinedVisitor {
			f.remoteMu.Lock()
			defer f.remoteMu.Unlock()
			return f.remoteVisitor
		})
		controlOwner.Permission = func(tunnelv1.ConnectorPermissionUpdate, *tunnel.ConnectorPermissionResponder) {
			t.Error("teardown attempted authority renewal")
		}
		controlOwner.Entered = func(request tunnelv1.ConnectorVisitorTerminalRequest) {
			if request.Purpose == tunnelv1.ConnectorTerminalCompletion {
				f.receipts <- tunnelv1.ConnectorVisitorCompletion{Kind: tunnelv1.ConnectorVisitorCompleted, VisitorConnectionID: request.Key.VisitorConnectionID,
					DeliveryGeneration: request.Key.DeliveryGeneration, TerminalNumber: request.TerminalNumber}
			}
			f.terminalEntered <- request
		}
		f.controlDone <- controlOwner.Serve(observed, &suspension)
	})
	f.owner.permissions, err = tunnel.OpenConnectorPermissionControl(packetCtx, ctx, ownerTeardownPermissionSession{Session: f.owner.session, writes: f.writes}, connectorTestControlScope())
	if err != nil {
		t.Fatal(err)
	}
	until, _ := ctx.Deadline()
	run := Run{ServiceID: "svc_aaaaaaaaaaaaaaaaaaaaaa", ServiceRunID: "srun_aaaaaaaaaaaaaaaaaaaaaa", RunNumber: 1,
		Protocol: "tcp", TrustRevision: 1, ValidUntil: until,
		Endpoint: &controlv1.ServiceEndpoint{Hostname: "db.example", Port: 25443}, ServiceTLS: clientTLS}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, ed25519.SeedSize))
	signer := Signer{Subject: tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, DeviceID: "vdev_aaaaaaaaaaaaaaaaaaaaaa", IdentityID: "ident_aaaaaaaaaaaaaaaaaaaaaa"},
		PublicKey: private.Public().(ed25519.PublicKey), Sign: func(message []byte) []byte { return ed25519.Sign(private, message) }}
	// use the defining opening validator and real preparation, not an alternate
	// permission engine. this fixture does not claim control authorization.
	entry, err := connectorOpening(signer, tunnelv1.ConnectorPeerVisitorEntry{ProtocolVersion: tunnelv1.Version,
		Kind: tunnelv1.ConnectorPeerVisitorStream, PairID: "cpp_aaaaaaaaaaaaaaaaaaaaaa", DeliveryID: "AQEBAQEBAQEBAQEBAQEBAQ",
		DeliveryGeneration: 7, ServiceID: run.ServiceID, ServiceRunID: run.ServiceRunID, RunNumber: run.RunNumber,
		Subject: signer.Subject, SourceIP: "127.0.0.1", VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", MetadataRevision: 1}, "signed-fixture-visitor-permission")
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan error, 1)
	f.workers.Go(func() {
		defer close(f.remoteInitDone)
		raw, err := f.server.AcceptStream(ctx)
		if err != nil {
			ready <- err
			return
		}
		f.remoteRaw = raw
		got, initial, err := tunnelv1.ReadConnectorPeerVisitorOpening(raw)
		if err != nil || len(initial) != 0 || got.VisitorConnectionID != entry.VisitorConnectionID || got.DeliveryGeneration != entry.DeliveryGeneration {
			ready <- errors.Join(errors.New("fixture opening changed"), err)
			return
		}
		if err := tunnelv1.WriteConnectorPeerVisitorAccepted(raw, got.VisitorConnectionID); err != nil {
			ready <- err
			return
		}
		f.remoteMu.Lock()
		f.remoteVisitor = connectorfixture.NewJoinedVisitor(ctx, got, until, raw.Close)
		f.remoteMu.Unlock()
		f.remote = tls.Server(raw, serverTLS)
		ready <- f.remote.HandshakeContext(ctx)
	})
	prepared, err := PrepareConnector(operation, ctx, f.owner.session, run, entry)
	if err != nil {
		t.Fatal(err)
	}
	f.prepared = prepared
	if err := ownerTeardownAwait(t, ctx, ready); err != nil {
		_ = prepared.Close()
		t.Fatal(err)
	}
	f.cleanup = &ownerTeardownCleanupConn{Conn: prepared.conn, ctx: ctx, latch: cleanupLatch, outbound: f.outbound}
	prepared.conn = f.cleanup
	f.owner.run, f.owner.until, f.owner.preparedUntil = run, until, until
	f.owner.permission = controlv1.VisitorTokenResponse{ExpiresAt: until}
	f.owner.cleanup.observe(until)
	f.owner.config = Config{Protocol: "tcp", MaxConnections: 1}
	f.owner.warm = &connectorUse{entry: entry, prepared: prepared, until: until, terminalKey: connectorTerminalKey(entry), admitted: true}
	f.owner.active[f.owner.warm] = struct{}{}
	f.receipt = tunnelv1.ConnectorVisitorCompletion{Kind: tunnelv1.ConnectorVisitorCompleted, VisitorConnectionID: entry.VisitorConnectionID, DeliveryGeneration: entry.DeliveryGeneration, TerminalNumber: 1}
	f.workers.Go(func() {
		<-f.remoteInitDone
		var request tunnelv1.ConnectorVisitorTerminalRequest
		select {
		case request = <-f.terminalEntered:
		case <-ctx.Done():
		}
		f.remoteMu.Lock()
		f.remoteSealed = true
		f.remoteMu.Unlock()
		var closeErr error
		if request.Purpose != tunnelv1.ConnectorTerminalCompletion {
			closeErr = f.remoteRaw.Close()
		}
		f.remoteWorkers.Wait()
		closeErr = errors.Join(closeErr, f.remote.Close())
		f.remoteMu.Lock()
		joinedErr, visitor := f.remoteErr, f.remoteVisitor
		f.remoteMu.Unlock()
		visitor.Join(errors.Join(closeErr, joinedErr))
	})

	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.SetDeadline(until); err != nil {
		t.Fatal(err)
	}
	f.input, err = net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	local, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	// embedding only net.Conn prevents TCP's ReaderFrom from bypassing the
	// actual return-copy Write barrier.
	localLife, closeLocal := context.WithCancel(ctx)
	f.local = &ownerTeardownReturnConn{Conn: local, tcp: local, ctx: localLife, cancel: closeLocal, latch: f.returnWrite}
	if err := errors.Join(f.input.SetDeadline(until), local.SetDeadline(until), f.remote.SetDeadline(until)); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *ownerTeardownFixture) forward(t *testing.T) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	f.workers.Go(func() { done <- f.owner.Forward(f.owner.ctx, f.local) })
	return done
}

func (f *ownerTeardownFixture) request(t *testing.T) {
	t.Helper()
	if _, err := io.WriteString(f.input, "request\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.input.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(f.remote); err != nil || string(got) != "request\n" {
		t.Fatal("request FIN changed the admitted request", string(got), err)
	}
}

func (f *ownerTeardownFixture) respond(response []byte) <-chan error {
	done := make(chan error, 1)
	f.remoteMu.Lock()
	if f.remoteSealed {
		f.remoteMu.Unlock()
		done <- errors.New("fixture remote work was already sealed")
		return done
	}
	f.remoteWorkers.Add(1)
	f.remoteMu.Unlock()
	go func() {
		defer f.remoteWorkers.Done()
		n, err := f.remote.Write(response)
		if err == nil && n != len(response) {
			err = fmt.Errorf("target wrote %d of %d bytes", n, len(response))
		}
		err = errors.Join(err, f.remote.CloseWrite())
		f.remoteMu.Lock()
		f.remoteErr = errors.Join(f.remoteErr, err)
		f.remoteMu.Unlock()
		done <- err
	}()
	return done
}

func ownerTeardownAwait[T any](t *testing.T, ctx context.Context, result <-chan T) T {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-ctx.Done():
		t.Fatal("connector teardown event exceeded its original deadline", context.Cause(ctx))
		var zero T
		return zero
	}
}

func ownerTeardownPending[T any](t *testing.T, result <-chan T, message string) {
	t.Helper()
	select {
	case value := <-result:
		t.Fatal(message, value)
	default:
	}
}
