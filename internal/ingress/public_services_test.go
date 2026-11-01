package ingress

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type publicServiceControlFixture struct {
	mu                                   sync.Mutex
	service, run                         string
	relays                               []ingressv1.ServiceRelay
	claimStarted, claimGate              chan struct{}
	recheckStarted, recheckGate          chan struct{}
	promoteStarted                       chan struct{}
	recheckActive                        atomic.Int32
	rechecks, closed                     int
	deny, pending, authenticated         bool
	recheckErr, promoteErr               error
	initialValidUntil, recheckValidUntil time.Time
}

func (c *publicServiceControlFixture) AdmitPublicServiceVisitor(ctx context.Context, id string, claim ingressv1.PublicServiceVisitorClaim) (ingressv1.PublicServiceVisitorAdmission, error) {
	if id != "ingress-a" || claim.IngressLeaseRevision != 1 || claim.ObservedSourceIp != "192.0.2.4" || claim.DestinationPort != 20000 || !opaqueid.Valid(claim.VisitorConnectionId, opaqueid.VisitorConnectionPrefix) {
		return ingressv1.PublicServiceVisitorAdmission{}, ErrServiceAdmission
	}
	if c.claimStarted != nil {
		c.claimStarted <- struct{}{}
	}
	if c.claimGate != nil {
		select {
		case <-c.claimGate:
		case <-ctx.Done():
			return ingressv1.PublicServiceVisitorAdmission{}, ctx.Err()
		}
	}
	until := c.initialValidUntil
	if until.IsZero() {
		until = time.Now().Add(time.Minute)
	}
	return ingressv1.PublicServiceVisitorAdmission{ServiceId: c.service, ServiceRunId: c.run, RunNumber: 1, VisitorConnectionId: claim.VisitorConnectionId, ExpiresAt: until, ConnectedRelays: append([]ingressv1.ServiceRelay(nil), c.relays...)}, nil
}

func (c *publicServiceControlFixture) PublicServiceVisitorStatus(ctx context.Context, _ string, _ ingressv1.PublicServiceVisitorLookup) (ingressv1.PublicServiceVisitorStatus, error) {
	c.recheckActive.Add(1)
	defer c.recheckActive.Add(-1)
	c.mu.Lock()
	c.rechecks++
	gate, started, denied, pending, authenticated, problem, until := c.recheckGate, c.recheckStarted, c.deny, c.pending, c.authenticated, c.recheckErr, c.recheckValidUntil
	c.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return ingressv1.PublicServiceVisitorStatus{}, ctx.Err()
		}
	}
	if problem != nil {
		return ingressv1.PublicServiceVisitorStatus{}, problem
	}
	state := ingressv1.PublicServiceVisitorAllowed
	if pending {
		state = ingressv1.PublicServiceVisitorPending
	}
	if authenticated {
		state = ingressv1.PublicServiceVisitorAuthenticated
	}
	if denied {
		state = ingressv1.PublicServiceVisitorDenied
	}
	if until.IsZero() {
		until = time.Now().Add(time.Minute)
	}
	return ingressv1.PublicServiceVisitorStatus{State: state, ValidUntil: until}, nil
}

func (c *publicServiceControlFixture) PromotePublicServiceVisitor(context.Context, string, ingressv1.PublicServiceVisitorLookup) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.promoteStarted != nil {
		select {
		case c.promoteStarted <- struct{}{}:
		default:
		}
	}
	return c.promoteErr
}

func (c *publicServiceControlFixture) ClosePublicServiceVisitor(context.Context, string, ingressv1.PublicServiceVisitorLookup) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed++
	return nil
}

type publicServiceForwarderFixture struct {
	mu                                        sync.Mutex
	calls                                     int
	failFirst, closeAfterByte, holdAfterReply bool
	workers                                   sync.WaitGroup
	relayDone                                 chan struct{}
	observed                                  chan tunnelv1.ServiceForwardingHeader
	metadata                                  chan proxyproto.Header
	data                                      chan []byte
}

func (f *publicServiceForwarderFixture) OpenPrivate(_ context.Context, relay ingressv1.ServiceRelay, h tunnelv1.ServiceForwardingHeader) (net.Conn, error) {
	f.mu.Lock()
	f.calls++
	call := f.calls
	f.mu.Unlock()
	if h.Validate() != nil || h.RelayID != relay.RelayId || h.PublisherConnectionID != relay.PublisherConnectionId || h.ConnectionSlot != uint8(relay.ConnectionSlot) || h.PublicService == nil {
		return nil, ErrServiceAdmission
	}
	if f.failFirst && call == 1 {
		return nil, errors.New("relay unavailable before visitor byte")
	}
	connection, upstream := net.Pipe()
	f.workers.Go(func() {
		defer upstream.Close()
		defer func() { f.relayDone <- struct{}{} }()
		meta, remaining, err := proxyproto.Decode(upstream)
		if err != nil {
			return
		}
		f.metadata <- meta
		f.observed <- h
		if f.closeAfterByte {
			var first [1]byte
			if _, err := io.ReadFull(remaining, first[:]); err == nil {
				f.data <- first[:]
			}
			return
		}
		value := make([]byte, 4)
		if _, err = io.ReadFull(remaining, value); err != nil {
			return
		}
		f.data <- value
		_, _ = upstream.Write([]byte("pong"))
		if f.holdAfterReply {
			_, _ = io.Copy(io.Discard, remaining)
		}
	})
	return connection, nil
}

func (f *publicServiceForwarderFixture) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

func publicServiceTestID(t *testing.T, prefix string) string {
	t.Helper()
	id, err := opaqueid.New(prefix)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func publicServiceTestSetup(t *testing.T) (*PublicServices, *publicServiceControlFixture, *publicServiceForwarderFixture, ingressv1.IngressLease) {
	t.Helper()
	lease := ingressv1.IngressLease{IngressId: "ingress-a", IngressRunId: publicServiceTestID(t, opaqueid.IngressRunPrefix), IngressLeaseRevision: 1, LeaseExpiresAt: time.Now().Add(time.Minute)}
	control := &publicServiceControlFixture{service: publicServiceTestID(t, opaqueid.ServicePrefix), run: publicServiceTestID(t, opaqueid.ServiceRunPrefix)}
	for slot := range 2 {
		control.relays = append(control.relays, ingressv1.ServiceRelay{PublisherConnectionId: publicServiceTestID(t, opaqueid.PublisherConnectionPrefix), ConnectionSlot: slot, ConnectionAssignmentRevision: 1, RelayServiceId: []string{"a", "b"}[slot], RelayId: []string{"relay-a", "relay-b"}[slot], RelayRunId: publicServiceTestID(t, opaqueid.RelayRunPrefix), RelayLeaseRevision: 1, InternalRelayAddress: "127.0.0.1:443", TlsServerName: "relay.test", LeaseExpiresAt: time.Now().Add(time.Minute)})
	}
	forwarder := &publicServiceForwarderFixture{observed: make(chan tunnelv1.ServiceForwardingHeader, 8), metadata: make(chan proxyproto.Header, 8), data: make(chan []byte, 8), relayDone: make(chan struct{}, 8)}
	direct, err := NewPublicServices(PublicServicesConfig{Control: control, Forwarder: forwarder, CurrentLease: func() ingressv1.IngressLease { return lease }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = direct.Close(); forwarder.workers.Wait() })
	return direct, control, forwarder, lease
}

func publicServiceTestConnect(t *testing.T, p *PublicServices) (net.Conn, <-chan error, func()) {
	t.Helper()
	connection, visitor := net.Pipe()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		defer connection.Close()
		done <- p.AcceptPublic(ctx, connection, netip.MustParseAddrPort("192.0.2.4:42000"), netip.MustParseAddrPort("203.0.113.8:20000"))
		close(done)
	}()
	stop := sync.OnceFunc(func() {
		cancel()
		_ = visitor.Close()
		_ = connection.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("public service visitor did not join")
		}
	})
	t.Cleanup(stop)
	return visitor, done, stop
}

func publicServiceActiveStream(t *testing.T, p *PublicServices, forwarder *publicServiceForwarderFixture) (net.Conn, func()) {
	t.Helper()
	forwarder.holdAfterReply = true
	visitor, _, stop := publicServiceTestConnect(t, p)
	_ = visitor.SetDeadline(time.Now().Add(time.Second))
	if _, err := visitor.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var reply [4]byte
	if _, err := io.ReadFull(visitor, reply[:]); err != nil || string(reply[:]) != "pong" {
		t.Fatalf("active response = %q: %v", reply, err)
	}
	_ = visitor.SetDeadline(time.Time{})
	return visitor, stop
}

func TestPublicServiceVisitorAuthorizesBeforeForwardingAndPreservesProxy(t *testing.T) {
	p, control, forwarder, lease := publicServiceTestSetup(t)
	control.claimStarted, control.claimGate = make(chan struct{}, 1), make(chan struct{})
	forwarder.failFirst = true
	visitor, _, _ := publicServiceTestConnect(t, p)
	select {
	case <-control.claimStarted:
	case <-time.After(time.Second):
		t.Fatal("control admission did not start")
	}
	if forwarder.count() != 0 {
		t.Fatal("forwarded before admission")
	}
	close(control.claimGate)
	_ = visitor.SetDeadline(time.Now().Add(time.Second))
	if _, err := visitor.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var reply [4]byte
	if _, err := io.ReadFull(visitor, reply[:]); err != nil || string(reply[:]) != "pong" {
		t.Fatalf("forwarding = %q: %v", reply, err)
	}
	header, meta := <-forwarder.observed, <-forwarder.metadata
	if header.ServiceID != control.service || header.ServiceRunID != control.run || header.RunNumber != 1 || header.PublicService.IngressRunID != lease.IngressRunId || header.PublicService.IngressLeaseRevision != 1 || header.SourceIP != "192.0.2.4" || header.VisitorConnectionID == "" {
		t.Fatalf("lost direct binding: %+v", header)
	}
	if meta.Source != netip.MustParseAddrPort("192.0.2.4:42000") || meta.Destination != netip.MustParseAddrPort("203.0.113.8:20000") || string(<-forwarder.data) != "ping" || forwarder.count() != 2 {
		t.Fatalf("changed PROXY/bytes or missed retry: %+v, opens=%d", meta, forwarder.count())
	}
}

func TestPublicServiceVisitorNeverReplaysAfterVisitorByte(t *testing.T) {
	p, _, forwarder, _ := publicServiceTestSetup(t)
	forwarder.closeAfterByte = true
	visitor, done, stop := publicServiceTestConnect(t, p)
	_ = visitor.SetDeadline(time.Now().Add(time.Second))
	_, _ = visitor.Write([]byte("ping"))
	select {
	case <-forwarder.data:
	case <-time.After(time.Second):
		t.Fatal("first byte did not reach relay")
	}
	time.Sleep(25 * time.Millisecond)
	if forwarder.count() != 1 {
		t.Fatalf("replayed committed visitor: %d opens", forwarder.count())
	}
	stop()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled copy did not join")
	}
}

func TestPublicServiceVisitorRejectsLeaseLostDuringAdmission(t *testing.T) {
	for _, mode := range []string{"draining", "replacement", "expired"} {
		t.Run(mode, func(t *testing.T) {
			p, control, forwarder, lease := publicServiceTestSetup(t)
			var lost atomic.Bool
			p.config.CurrentLease = func() ingressv1.IngressLease {
				current := lease
				if lost.Load() {
					switch mode {
					case "draining":
						current.Draining = true
					case "replacement":
						current.IngressLeaseRevision++
					case "expired":
						current.LeaseExpiresAt = lease.LeaseExpiresAt.Add(-2 * time.Minute)
					}
				}
				return current
			}
			control.claimStarted, control.claimGate = make(chan struct{}, 1), make(chan struct{})
			_, done, _ := publicServiceTestConnect(t, p)
			select {
			case <-control.claimStarted:
			case <-time.After(time.Second):
				t.Fatal("admission did not start")
			}
			lost.Store(true)
			close(control.claimGate)
			select {
			case err := <-done:
				if !errors.Is(err, ErrServiceAdmission) {
					t.Fatalf("stale admission: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("stale admission did not join")
			}
			if forwarder.count() != 0 {
				t.Fatal("forwarded with stale ingress authority")
			}
		})
	}
}

func TestPublicServicesCloseJoinsBlockedAdmission(t *testing.T) {
	p, control, forwarder, _ := publicServiceTestSetup(t)
	control.claimStarted, control.claimGate = make(chan struct{}, 1), make(chan struct{})
	_, _, _ = publicServiceTestConnect(t, p)
	select {
	case <-control.claimStarted:
	case <-time.After(time.Second):
		t.Fatal("admission did not start")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if p.Load() != 0 || p.pending != 0 || p.active != 0 || forwarder.count() != 0 || control.closed != 1 {
		t.Fatal("close left setup or capacity owned")
	}
}
