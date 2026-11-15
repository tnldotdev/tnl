package service

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
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

func TestConnectorHTTPDrainKeepsCarrierUntilCompletionReceiptWithinOriginalAuthority(t *testing.T) {
	for _, finish := range []string{"consumed", "revoked", "deadline", "authority", "cleanup failure"} {
		t.Run(finish, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				b, peer, _, opening, _ := connectorPeerFixture(t, "127.0.0.1:1")
				b.prepared.managedProtocol = config.ProtocolHTTP
				b.httpDrainUntil = time.Now().Add(time.Second)
				if finish == "authority" {
					b.httpDrainUntil = time.Now().Add(2 * time.Second)
					peer.owner.until = time.Now().Add(time.Second)
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				wire := &drainingConnectorWire{half: make(chan struct{}), closed: make(chan struct{})}
				cause := errors.New("independent physical close failure")
				if finish == "cleanup failure" {
					wire.closeErr = cause
				}
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
				go func() { done <- owned.Close() }()
				<-wire.half
				synctest.Wait()
				// even a request-side FIN before the response cannot acknowledge
				// return delivery, nor can a wrong visitor or delivery receipt.
				peer.completeVisitor(tunnelv1.ConnectorVisitorCompletion{Kind: tunnelv1.ConnectorVisitorCompleted, VisitorConnectionID: opening("E").VisitorConnectionID, DeliveryGeneration: entry.DeliveryGeneration})
				peer.completeVisitor(tunnelv1.ConnectorVisitorCompletion{Kind: tunnelv1.ConnectorVisitorCompleted, VisitorConnectionID: entry.VisitorConnectionID, DeliveryGeneration: entry.DeliveryGeneration + 1})
				other := &PeerSession{bound: b, streams: make(map[*connectorAdmission]struct{})}
				other.completeVisitor(tunnelv1.ConnectorVisitorCompletion{Kind: tunnelv1.ConnectorVisitorCompleted, VisitorConnectionID: entry.VisitorConnectionID, DeliveryGeneration: entry.DeliveryGeneration})
				synctest.Wait()
				if wire.closes.Load() != 0 {
					t.Fatal("request FIN or another receipt retired the response's carrier")
				}
				var want error
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
					if finish == "cleanup failure" {
						want = cause
					}
				}
				if err := <-done; !errors.Is(err, want) {
					t.Fatal("HTTP drain lost its independent close or cancellation failure", err, want)
				}
				if err := owned.Close(); !errors.Is(err, want) {
					t.Fatal("repeated HTTP cleanup changed its result", err, want)
				}
				if wire.closes.Load() != 1 {
					t.Fatal("concurrent HTTP cleanup physically closed more than once")
				}
			})
		})
	}
}

func TestConnectorHTTPConcurrentCloseJoinsCompletionAndPhysicalFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	b, peer, _, opening, _ := connectorPeerFixture(t, "127.0.0.1:1")
	b.prepared.managedProtocol = config.ProtocolHTTP
	b.httpDrainUntil, _ = ctx.Deadline()
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
		workers.Go(func() { entered <- struct{}{}; done <- owned.Close() })
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
	case <-wire.half:
	case <-ctx.Done():
		t.Fatal("HTTP close did not send its return FIN", ctx.Err())
	}
	if wire.closes.Load() != 0 {
		t.Fatal("HTTP close retired its carrier before completion")
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
	if err := b.startHTTPDrain(until); !errors.Is(err, cause) {
		t.Fatal("drain lost unused opening cleanup failure", err)
	}
	if pendingCtx.Err() == nil || pendingWire.closes.Load() != 1 || !pending.retiringLocked() {
		t.Fatal("unused signed opening waited for application arrival or its setup deadline")
	}
	if activeCtx.Err() != nil || activeWire.closes.Load() != 0 || active.retiringLocked() {
		t.Fatal("drain interrupted a ready visitor before its completion receipt")
	}
	if err := b.startHTTPDrain(until.Add(time.Hour)); err != nil || !b.httpDrainUntil.Equal(until) || pendingWire.closes.Load() != 1 {
		t.Fatal("repeated drain extended its deadline or repeated physical cleanup", err)
	}
	if _, err := peer.reserve(t.Context(), activeWire); !errors.Is(err, ErrPrivateStream) {
		t.Fatal("draining run reserved a new connector opening", err)
	}
}
