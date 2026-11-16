package service

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type drainingConnectorWire struct {
	net.Conn
	half, closed chan struct{}
	once         sync.Once
	closes       atomic.Int32
	closeErr     error
}

func (c *drainingConnectorWire) CloseWrite() error      { close(c.half); return nil }
func (*drainingConnectorWire) Read([]byte) (int, error) { return 0, io.EOF }
func (c *drainingConnectorWire) Close() error {
	c.once.Do(func() { c.closes.Add(1); close(c.closed) })
	return c.closeErr
}

type connectorBlockedReadWire struct{ *drainingConnectorWire }

func (c *connectorBlockedReadWire) Read(p []byte) (int, error) { return c.Conn.Read(p) }
func (c *connectorBlockedReadWire) Close() error {
	return errors.Join(c.drainingConnectorWire.Close(), c.Conn.Close())
}

func TestConnectorHTTPCloseUnblocksReadWithoutWaitingForDelivery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b, peer, _, opening, _ := connectorPeerFixture(t, "127.0.0.1:1")
		b.prepared.managedProtocol = config.ProtocolHTTP
		b.drainUntil = time.Now().Add(time.Minute)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		raw, remote := net.Pipe()
		defer remote.Close()
		wire := &connectorBlockedReadWire{&drainingConnectorWire{Conn: raw, half: make(chan struct{}), closed: make(chan struct{})}}
		a := &connectorAdmission{peer: peer, ctx: ctx, caller: ctx, cancel: cancel,
			stream: wire, state: readyConnectorAdmission{}, completed: make(chan struct{})}
		view, _, _ := b.prepared.policy.Current()
		permission, err := visitortoken.VerifyConnectorPeerSession(opening("D"), nil, peer.bindingSnapshot().expected(), view, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		a.guard, err = b.prepared.policy.BindConnector(permission, netip.MustParseAddr("192.0.2.1"), b.prepared.metadataRevision, a.stopAndClose)
		if err != nil {
			t.Fatal(err)
		}
		defer a.guard.Close()
		owned := &connectorOwnedConn{Conn: wire, admission: a, prefix: bytes.NewReader(nil)}
		read, closed := make(chan error, 1), make(chan error, 1)
		go func() { _, err := owned.Read(make([]byte, 1)); read <- err }()
		go func() { closed <- owned.Close() }()
		synctest.Wait()
		// HTTP/2 cannot finish its connection worker until Close unblocks the
		// concurrent frame read. return-delivery receipt belongs to its owner.
		select {
		case err := <-closed:
			if err != nil {
				t.Error("physical close failed", err)
			}
		default:
			t.Error("net.Conn.Close waited for delivery instead of unblocking I/O")
		}
		select {
		case err := <-read:
			if !errors.Is(err, io.ErrClosedPipe) {
				t.Error("close did not interrupt the blocked frame read", err)
			}
		default:
			t.Error("HTTP/2 frame read remained blocked after Close")
		}
		cancel()
		_ = raw.Close()
	})
}

func TestConnectorHTTPDrainKeepsCarrierUntilCompletionReceiptWithinOriginalAuthority(t *testing.T) {
	for _, protocol := range []config.ProtocolName{config.ProtocolHTTP, config.ProtocolTCP, config.ProtocolPostgres, config.ProtocolMySQL, config.ProtocolKubernetes} {
		for _, finish := range []string{"consumed", "revoked", "deadline", "authority"} {
			t.Run(string(protocol)+"/"+finish, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					b, peer, _, opening, _ := connectorPeerFixture(t, "127.0.0.1:1")
					b.prepared.managedProtocol = protocol
					b.drainUntil = time.Now().Add(time.Second)
					if finish == "authority" {
						b.drainUntil = time.Now().Add(2 * time.Second)
						peer.owner.until = time.Now().Add(time.Second)
					}
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					wire := &drainingConnectorWire{half: make(chan struct{}), closed: make(chan struct{})}
					a := &connectorAdmission{peer: peer, ctx: ctx, caller: ctx, cancel: cancel, stream: wire, state: readyConnectorAdmission{}, completed: make(chan struct{})}
					entry := opening("D")
					view, _, _ := b.prepared.policy.Current()
					permission, err := visitortoken.VerifyConnectorPeerSession(entry, nil, peer.bindingSnapshot().expected(), view, time.Now())
					if err != nil {
						t.Fatal(err)
					}
					a.guard, err = b.prepared.policy.BindConnector(permission, netip.MustParseAddr("192.0.2.1"), b.prepared.metadataRevision, a.stopAndClose)
					if err != nil {
						t.Fatal(err)
					}
					defer a.guard.Close()
					a.audit.VisitorConnectionID, a.audit.DeliveryGeneration = entry.VisitorConnectionID, entry.DeliveryGeneration
					peer.streams[a] = struct{}{}
					defer delete(peer.streams, a)
					owned := &connectorOwnedConn{Conn: wire, admission: a, prefix: bytes.NewReader(nil)}
					done := make(chan error, 1)
					if err := owned.Close(); !errors.Is(err, wire.closeErr) {
						t.Fatal("physical close lost its cleanup failure", err)
					}
					b.visitorWorkers.Add(1)
					go func() { defer b.visitorWorkers.Done(); done <- a.finishDelivery(nil) }()
					joined := make(chan error, 1)
					go func() { joined <- b.joinDrain() }()
					<-wire.closed
					synctest.Wait()
					// even a request-side FIN before the response cannot acknowledge
					// return delivery, nor can a wrong visitor or delivery receipt.
					peer.completeVisitor(tunnelv1.ConnectorVisitorCompletion{Kind: tunnelv1.ConnectorVisitorCompleted, VisitorConnectionID: opening("E").VisitorConnectionID, DeliveryGeneration: entry.DeliveryGeneration})
					peer.completeVisitor(tunnelv1.ConnectorVisitorCompletion{Kind: tunnelv1.ConnectorVisitorCompleted, VisitorConnectionID: entry.VisitorConnectionID, DeliveryGeneration: entry.DeliveryGeneration + 1})
					other := &PeerSession{bound: b, streams: make(map[*connectorAdmission]struct{})}
					other.completeVisitor(tunnelv1.ConnectorVisitorCompletion{Kind: tunnelv1.ConnectorVisitorCompleted, VisitorConnectionID: entry.VisitorConnectionID, DeliveryGeneration: entry.DeliveryGeneration})
					synctest.Wait()
					select {
					case err := <-done:
						t.Fatal("request FIN or another receipt completed return delivery", err)
					default:
					}
					select {
					case err := <-joined:
						t.Fatal("run retired its carriers before return delivery joined", err)
					default:
					}
					var want error
					before := time.Now()
					switch finish {
					case "revoked":
						a.guard.Revoke()
						want = context.Canceled
					case "deadline", "authority":
						time.Sleep(time.Second)
						want = context.DeadlineExceeded
					default:
						receipt := tunnelv1.ConnectorVisitorCompletion{Kind: tunnelv1.ConnectorVisitorCompleted, VisitorConnectionID: entry.VisitorConnectionID, DeliveryGeneration: entry.DeliveryGeneration}
						peer.completeVisitor(receipt)
						peer.completeVisitor(receipt)
					}
					if err := <-done; !errors.Is(err, want) {
						t.Fatal("HTTP drain lost its independent close or cancellation failure", err, want)
					}
					if err := a.finishDelivery(nil); !errors.Is(err, want) {
						t.Fatal("repeated HTTP cleanup changed its result", err, want)
					}
					<-joined
					if err := owned.Close(); !errors.Is(err, wire.closeErr) {
						t.Fatal("delivery wait changed the physical Close result", err)
					}
					if wire.closes.Load() != 1 {
						t.Fatal("concurrent HTTP cleanup physically closed more than once")
					}
					elapsed := time.Duration(0)
					if errors.Is(want, context.DeadlineExceeded) {
						elapsed = time.Second
					}
					if time.Since(before) != elapsed {
						t.Fatal("completion or revocation waited for or extended the original bound", time.Since(before), elapsed)
					}
				})
			})
		}
	}
}

func TestConnectorHTTPConcurrentCloseJoinsCompletionAndPhysicalFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	b, peer, _, opening, _ := connectorPeerFixture(t, "127.0.0.1:1")
	b.prepared.managedProtocol = config.ProtocolHTTP
	b.drainUntil, _ = ctx.Deadline()
	cause := errors.New("independent concurrent physical close failure")
	wire := &drainingConnectorWire{half: make(chan struct{}), closed: make(chan struct{}), closeErr: cause}
	a := &connectorAdmission{peer: peer, ctx: ctx, caller: ctx, cancel: cancel, stream: wire,
		state: readyConnectorAdmission{}, completed: make(chan struct{})}
	entry := opening("D")
	view, _, _ := b.prepared.policy.Current()
	permission, err := visitortoken.VerifyConnectorPeerSession(entry, nil, peer.bindingSnapshot().expected(), view, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a.guard, err = b.prepared.policy.BindConnector(permission, netip.MustParseAddr("192.0.2.1"), b.prepared.metadataRevision, a.stopAndClose)
	if err != nil {
		t.Fatal(err)
	}
	defer a.guard.Close()
	a.audit.VisitorConnectionID, a.audit.DeliveryGeneration = entry.VisitorConnectionID, entry.DeliveryGeneration
	peer.streams[a] = struct{}{}
	defer func() {
		b.mu.Lock()
		delete(peer.streams, a)
		b.mu.Unlock()
	}()
	owned := &connectorOwnedConn{Conn: wire, admission: a, prefix: bytes.NewReader(nil)}
	done := make(chan error, 2)
	entered := make(chan struct{}, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Go(func() {
			entered <- struct{}{}
			closed := owned.Close()
			done <- errors.Join(closed, a.finishDelivery(closed))
		})
	}
	defer func() { cancel(); workers.Wait() }()
	for range 2 {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("concurrent close did not start", ctx.Err())
		}
	}
	select {
	case <-wire.closed:
	case <-ctx.Done():
		t.Fatal("HTTP close did not send its return FIN", ctx.Err())
	}
	if wire.closes.Load() != 1 {
		t.Fatal("HTTP completion did not physically close its stream before waiting")
	}
	peer.completeVisitor(tunnelv1.ConnectorVisitorCompletion{Kind: tunnelv1.ConnectorVisitorCompleted,
		VisitorConnectionID: entry.VisitorConnectionID, DeliveryGeneration: entry.DeliveryGeneration})
	for range 2 {
		select {
		case err := <-done:
			if !errors.Is(err, cause) {
				t.Fatal("concurrent close lost its independent cleanup failure", err)
			}
		case <-ctx.Done():
			t.Fatal("concurrent HTTP close did not join", ctx.Err())
		}
	}
	if wire.closes.Load() != 1 {
		t.Fatal("concurrent HTTP cleanup physically closed more than once")
	}
	if err := owned.Close(); !errors.Is(err, cause) {
		t.Fatal("physical close lost its independent cleanup failure", err)
	}
}

func TestConnectorHTTPCompletionWaitsForRunPublishedDrainDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b, peer, _, opening, _ := connectorPeerFixture(t, "127.0.0.1:1")
		b.prepared.managedProtocol = config.ProtocolHTTP
		b.drainStarted = make(chan struct{})
		budget, err := requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Total: new(1)})
		if err != nil {
			t.Fatal(err)
		}
		b.prepared.serviceHTTPRequests = budget
		request, ok := budget.Reserve(httptest.NewRecorder(), httptest.NewRequest("GET", "https://service.example.test/", nil))
		if !ok {
			t.Fatal("fixture could not reserve its final application request")
		}
		request.Finish()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		wire := &drainingConnectorWire{closed: make(chan struct{})}
		a := &connectorAdmission{peer: peer, ctx: ctx, caller: ctx, cancel: cancel,
			stream: wire, state: readyConnectorAdmission{}, completed: make(chan struct{})}
		view, _, _ := b.prepared.policy.Current()
		permission, err := visitortoken.VerifyConnectorPeerSession(opening("D"), nil, peer.bindingSnapshot().expected(), view, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		a.guard, err = b.prepared.policy.BindConnector(permission, netip.MustParseAddr("192.0.2.1"), b.prepared.metadataRevision, a.stopAndClose)
		if err != nil {
			t.Fatal(err)
		}
		defer a.guard.Close()
		done := make(chan error, 1)
		go func() { done <- a.finishDelivery(nil) }()
		<-wire.closed
		time.Sleep(2 * time.Second)
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatal("application completion invented or skipped the owner's drain budget", err)
		default:
		}
		until := time.Now().Add(time.Second)
		if err := b.startDrain(until); err != nil {
			t.Fatal(err)
		}
		if err := <-done; !errors.Is(err, context.DeadlineExceeded) || !time.Now().Equal(until) {
			t.Fatal("delivery did not use the run owner's exact published deadline", err, time.Now(), until)
		}
	})
}

func TestConnectorHTTPDrainClosesUnusedOpeningsWithoutInterruptingReadyVisitors(t *testing.T) {
	b, peer, _, _, _ := connectorPeerFixture(t, "127.0.0.1:1")
	b.prepared.managedProtocol = config.ProtocolHTTP
	pendingCtx, cancelPending := context.WithCancel(t.Context())
	defer cancelPending()
	activeCtx, cancelActive := context.WithCancel(t.Context())
	defer cancelActive()
	cause := errors.New("pending opening physical cleanup failed")
	pendingWire := &drainingConnectorWire{closed: make(chan struct{}), closeErr: cause}
	activeWire := &drainingConnectorWire{closed: make(chan struct{})}
	pending := &connectorAdmission{peer: peer, ctx: pendingCtx, cancel: cancelPending,
		stream: pendingWire, state: admittedConnectorAdmission{}}
	active := &connectorAdmission{peer: peer, ctx: activeCtx, cancel: cancelActive,
		stream: activeWire, state: readyConnectorAdmission{}}
	peer.streams[pending], peer.streams[active] = struct{}{}, struct{}{}
	defer delete(peer.streams, pending)
	defer delete(peer.streams, active)
	until := time.Now().Add(time.Second)
	if err := b.startDrain(until); !errors.Is(err, cause) {
		t.Fatal("drain lost unused opening cleanup failure", err)
	}
	if pendingCtx.Err() == nil || pendingWire.closes.Load() != 1 || !pending.retiringLocked() {
		t.Fatal("unused signed opening waited for application arrival or its setup deadline")
	}
	if activeCtx.Err() != nil || activeWire.closes.Load() != 0 || active.retiringLocked() {
		t.Fatal("drain interrupted a ready visitor before its completion receipt")
	}
	if err := b.startDrain(until.Add(time.Hour)); err != nil || !b.drainUntil.Equal(until) || pendingWire.closes.Load() != 1 {
		t.Fatal("repeated drain extended its deadline or repeated physical cleanup", err)
	}
	if _, err := peer.reserve(t.Context(), activeWire); !errors.Is(err, ErrPrivateStream) {
		t.Fatal("draining run reserved a new connector opening", err)
	}
}
