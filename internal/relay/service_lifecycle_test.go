package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func privateLifecycleHeader() tunnelv1.ServiceForwardingHeader {
	return tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{
		ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ServiceForwardingStream,
		ServiceID: privateRelayID(opaqueid.ServicePrefix), ServiceRunID: privateRelayID(opaqueid.ServiceRunPrefix), RunNumber: 3,
		PublisherConnectionID: privateRelayID(opaqueid.PublisherConnectionPrefix), ConnectionAssignmentRevision: 2,
		PublicService: &tunnelv1.PublicServiceAdmission{IngressID: "ingress", IngressRunID: privateRelayID(opaqueid.IngressRunPrefix), IngressLeaseRevision: 1, DestinationPort: 8443},
		SourceIP:      "192.0.2.4", VisitorConnectionID: privateRelayID(opaqueid.VisitorConnectionPrefix), ExpiresAt: time.Now().Add(time.Minute),
	}, ConnectionSlot: 1, RelayServiceID: "relay-a", RelayID: "relay-process", RelayRunID: privateRelayID(opaqueid.RelayRunPrefix),
		RelayLeaseRevision: 4, LeaseExpiresAt: time.Now().Add(time.Minute)}
}

func TestPrivateCandidateRequiresEveryAssignmentAndLeaseField(t *testing.T) {
	header := privateLifecycleHeader()
	lease := relayv1.RelayLease{RelayServiceId: header.RelayServiceID, RelayId: header.RelayID, RelayRunId: header.RelayRunID,
		RelayLeaseRevision: int64(header.RelayLeaseRevision), LeaseExpiresAt: header.LeaseExpiresAt}
	connection := &serviceConnection{ref: tunnel.ServiceForwardingRef(header), lease: lease}
	registry := NewServiceRegistry()
	registry.connections[header.PublisherConnectionID] = connection
	if got, ok := registry.candidate(header, lease, time.Now()); !ok || got != connection {
		t.Fatal("exact private assignment was not selected")
	}
	for _, field := range []string{"ServiceID", "ServiceRunID", "RunNumber", "PublisherConnectionID", "ConnectionSlot", "ConnectionAssignmentRevision", "RelayServiceID", "RelayID", "RelayRunID", "RelayLeaseRevision"} {
		for _, missing := range []bool{false, true} {
			name := "substitute/"
			if missing {
				name = "missing/"
			}
			t.Run(name+field, func(t *testing.T) {
				changed := header
				value := reflect.ValueOf(&changed).Elem().FieldByName(field)
				if missing {
					value.SetZero()
				} else if value.Kind() == reflect.String {
					text := value.String()
					value.SetString(text[:len(text)-1] + "b")
				} else if field == "ConnectionSlot" {
					value.SetUint(0)
				} else {
					value.SetUint(value.Uint() + 1)
				}
				if got, ok := registry.candidate(changed, lease, time.Now()); ok || got != nil {
					t.Fatal("changed private identity was selected")
				}
			})
		}
	}
	for name, mutate := range map[string]func(*relayv1.RelayLease){
		"service":  func(l *relayv1.RelayLease) { l.RelayServiceId += "other" },
		"process":  func(l *relayv1.RelayLease) { l.RelayId += "other" },
		"run":      func(l *relayv1.RelayLease) { l.RelayRunId += "other" },
		"revision": func(l *relayv1.RelayLease) { l.RelayLeaseRevision++ },
		"expired":  func(l *relayv1.RelayLease) { l.LeaseExpiresAt = time.Now().Add(-time.Second) },
		"draining": func(l *relayv1.RelayLease) { l.Draining = true },
	} {
		t.Run("lease/"+name, func(t *testing.T) {
			changed := lease
			mutate(&changed)
			if _, ok := registry.candidate(header, changed, time.Now()); ok {
				t.Fatal("stale lease selected")
			}
		})
	}
	// private forwarding requires both the copied deadline and the current lease.
	expired := header
	expired.LeaseExpiresAt = time.Now().Add(-time.Second)
	if _, ok := registry.candidate(expired, lease, time.Now()); ok {
		t.Fatal("expired private projection selected")
	}
	// a claim from another process cannot be rescued by a current header/lease.
	connection.lease.RelayId = "other-process"
	if _, ok := registry.candidate(header, lease, time.Now()); ok {
		t.Fatal("claim process identity ignored")
	}
}

func TestPrivateClaimRejectsChangedAndMissingResponseIdentity(t *testing.T) {
	ref := tunnel.ServiceForwardingRef(privateLifecycleHeader())
	claimed := relayv1.ServicePublisherConnection{ServiceId: ref.ServiceID, ServiceRunId: ref.ServiceRunID, RunNumber: int64(ref.RunNumber),
		PublisherConnectionId: ref.PublisherConnectionID, ConnectionAssignmentRevision: int64(ref.ConnectionAssignmentRevision), RelayServiceId: ref.RelayServiceID}
	if err := validatePrivateClaim(ref, claimed); err != nil {
		t.Fatal(err)
	}
	for i := range reflect.TypeOf(claimed).NumField() {
		field := reflect.TypeOf(claimed).Field(i).Name
		for _, missing := range []bool{false, true} {
			name := "substitute/"
			if missing {
				name = "missing/"
			}
			t.Run(name+field, func(t *testing.T) {
				changed := claimed
				value := reflect.ValueOf(&changed).Elem().Field(i)
				if missing {
					value.SetZero()
				} else if value.Kind() == reflect.String {
					value.SetString(value.String() + "other")
				} else {
					value.SetInt(value.Int() + 1)
				}
				if err := validatePrivateClaim(ref, changed); err == nil {
					t.Fatal("changed control identity accepted")
				}
			})
		}
	}
}

func privateLifecycleFixture(t *testing.T) (*serviceConnection, *tunnel.Session, *ServiceRegistry, tunnelv1.ServiceForwardingHeader) {
	t.Helper()
	header := privateLifecycleHeader()
	ref := tunnel.ServiceForwardingRef(header)
	publisher, relay := privateRelayPair(t, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version,
		Role: tunnelv1.Publisher, Credential: "private-publisher", ServiceConnection: &ref})
	c := &serviceConnection{ref: ref, paths: newStreamLifetime(relay)}
	registry := NewServiceRegistry()
	if err := registry.insert(c); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	return c, publisher, registry, header
}

func openPrivateLifecycle(ctx context.Context, c *serviceConnection, h tunnelv1.ServiceForwardingHeader) (net.Conn, error) {
	if err := c.paths.beginOpen(); err != nil {
		return nil, err
	}
	stream, err := c.paths.session.OpenServiceForwardingStream(ctx, h)
	return c.paths.finishOpen(stream, err)
}

func TestPrivateLifecycleCloseAndForcedDrainInterruptPendingOpen(t *testing.T) {
	for _, drain := range []bool{false, true} {
		name := "close"
		if drain {
			name = "forced-drain"
		}
		t.Run(name, func(t *testing.T) {
			c, publisher, registry, header := privateLifecycleFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			opened := relayWorker(t, func() { _ = c.paths.Close() }, func() error {
				stream, err := openPrivateLifecycle(ctx, c, header)
				if stream != nil {
					_ = stream.Close()
				}
				return err
			})
			incoming, err := publisher.AcceptServiceForwardingStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer incoming.Stream().Close()
			if n, s := registry.Load(); n != 1 || s != 1 {
				t.Fatalf("pending load=%d/%d", n, s)
			}
			if drain {
				drainCtx, stop := context.WithCancel(ctx)
				waiting := &waitingDrainContext{Context: drainCtx, waiting: make(chan struct{})}
				done := relayWorker(t, stop, func() error { return registry.Drain(waiting) })
				relayAwait(t, waiting.waiting)
				if _, err := openPrivateLifecycle(ctx, c, header); !errors.Is(err, ErrDraining) {
					t.Fatalf("draining open=%v", err)
				}
				stop()
				if err := relayAwait(t, done); !errors.Is(err, context.Canceled) {
					t.Fatalf("forced drain=%v", err)
				}
			} else if err := registry.Close(); err != nil {
				t.Fatal(err)
			}
			var timeout net.Error
			if err := relayAwait(t, opened); err == nil || errors.As(err, &timeout) && timeout.Timeout() {
				t.Fatalf("pending open not interrupted: %v", err)
			}
			if _, s := registry.Load(); s != 0 {
				t.Fatal("pending stream leaked")
			}
			if _, err := openPrivateLifecycle(ctx, c, header); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("post-close open=%v", err)
			}
		})
	}
}

func TestPrivateLifecycleDrainKeepsAdmittedStreamAndReleasesOnce(t *testing.T) {
	c, publisher, registry, header := privateLifecycleFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	peer := make(chan *tunnel.IncomingServiceForwardingStream, 1)
	accepted := relayWorker(t, func() { _ = publisher.Close() }, func() error {
		incoming, err := publisher.AcceptServiceForwardingStream(ctx)
		if err != nil {
			return err
		}
		peer <- incoming
		return incoming.Accept()
	})
	stream, err := openPrivateLifecycle(ctx, c, header)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	incoming := relayAwait(t, peer)
	defer incoming.Stream().Close()
	if err := relayAwait(t, accepted); err != nil {
		t.Fatal(err)
	}
	waiting := &waitingDrainContext{Context: ctx, waiting: make(chan struct{})}
	drained := relayWorker(t, func() { _ = c.paths.Close() }, func() error { return registry.Drain(waiting) })
	relayAwait(t, waiting.waiting)
	if _, err := openPrivateLifecycle(ctx, c, header); !errors.Is(err, ErrDraining) {
		t.Fatalf("draining open=%v", err)
	}
	if err := registry.insert(c); err == nil {
		t.Fatal("draining registry accepted assignment")
	}
	if _, err := stream.Write([]byte("live")); err != nil {
		t.Fatal(err)
	}
	var data [4]byte
	if _, err := io.ReadFull(incoming.Stream(), data[:]); err != nil || string(data[:]) != "live" {
		t.Fatalf("drain interrupted stream: %q %v", data, err)
	}
	select {
	case err := <-drained:
		t.Fatalf("early drain=%v", err)
	default:
	}
	var group sync.WaitGroup
	for range 16 {
		group.Go(func() { _ = stream.Close() })
	}
	group.Wait()
	if err := relayAwait(t, drained); err != nil {
		t.Fatal(err)
	}
	if _, s := registry.Load(); s != 0 {
		t.Fatal("stream accounting retained")
	}
}

func TestPrivateLifecycleDrainRejectsLatePendingAcknowledgement(t *testing.T) {
	c, publisher, registry, header := privateLifecycleFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	opened := relayWorker(t, func() { _ = c.paths.Close() }, func() error {
		stream, err := openPrivateLifecycle(ctx, c, header)
		if stream != nil {
			_ = stream.Close()
		}
		return err
	})
	incoming, err := publisher.AcceptServiceForwardingStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer incoming.Stream().Close()
	waiting := &waitingDrainContext{Context: ctx, waiting: make(chan struct{})}
	drained := relayWorker(t, func() { _ = c.paths.Close() }, func() error { return registry.Drain(waiting) })
	relayAwait(t, waiting.waiting)
	select {
	case err := <-drained:
		t.Fatalf("drain skipped pending acknowledgement: %v", err)
	default:
	}
	if err := incoming.Accept(); err != nil {
		t.Fatal(err)
	}
	if err := relayAwait(t, opened); !errors.Is(err, ErrDraining) {
		t.Fatalf("late acknowledgement escaped drain: %v", err)
	}
	if err := relayAwait(t, drained); err != nil {
		t.Fatal(err)
	}
	if _, streams := registry.Load(); streams != 0 {
		t.Fatal("late acknowledgement retained stream capacity")
	}
}

type countedCloseConn struct {
	net.Conn
	closes atomic.Int64
}

func (c *countedCloseConn) Close() error { c.closes.Add(1); return c.Conn.Close() }

func TestTrackedStreamConcurrentCloseReleasesExactlyOnce(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	base := &countedCloseConn{Conn: left}
	var released atomic.Int64
	stream := &trackedConn{Conn: base, release: func() { released.Add(1) }}
	var group sync.WaitGroup
	for range 32 {
		group.Go(func() { _ = stream.Close() })
	}
	group.Wait()
	if base.closes.Load() != 1 || released.Load() != 1 {
		t.Fatalf("close/release=%d/%d", base.closes.Load(), released.Load())
	}
}

type pendingCleanupConn struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
}

func (c *pendingCleanupConn) Close() error {
	close(c.entered)
	<-c.release
	return c.Conn.Close()
}

func TestStreamLifetimePendingCleanupRemainsReserved(t *testing.T) {
	for _, closing := range []bool{false, true} {
		name := "drain"
		if closing {
			name = "close"
		}
		t.Run(name, func(t *testing.T) {
			c, _, _, _ := privateLifecycleFixture(t)
			if err := c.paths.beginOpen(); err != nil {
				t.Fatal(err)
			}
			left, right := net.Pipe()
			t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
			connection := &pendingCleanupConn{Conn: left, entered: make(chan struct{}), release: make(chan struct{})}
			unblock := sync.OnceFunc(func() { close(connection.release) })
			t.Cleanup(unblock)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			waiting := &waitingDrainContext{Context: ctx, waiting: make(chan struct{})}
			var joined <-chan error
			wantOpenErr := ErrDraining
			if closing {
				joined = relayWorker(t, unblock, c.paths.Close)
				relayAwait(t, c.paths.session.Done())
				wantOpenErr = net.ErrClosed
			} else {
				joined = relayWorker(t, unblock, func() error { return c.paths.Drain(waiting) })
				relayAwait(t, waiting.waiting)
			}
			finished := relayWorker(t, unblock, func() error {
				_, err := c.paths.finishOpen(connection, nil)
				return err
			})
			relayAwait(t, connection.entered)
			c.paths.mu.Lock()
			opening, streams := c.paths.opening, len(c.paths.streams)
			c.paths.mu.Unlock()
			if opening != 1 || streams != 0 {
				t.Fatalf("pending cleanup lost its reservation: opening=%d streams=%d", opening, streams)
			}
			select {
			case err := <-joined:
				t.Fatalf("%s finished before rejected-stream cleanup: %v", name, err)
			default:
			}
			unblock()
			if err := relayAwait(t, finished); !errors.Is(err, wantOpenErr) {
				t.Fatalf("rejected open=%v, want %v", err, wantOpenErr)
			}
			if err := relayAwait(t, joined); err != nil {
				t.Fatal(err)
			}
			c.paths.mu.Lock()
			opening, streams = c.paths.opening, len(c.paths.streams)
			c.paths.mu.Unlock()
			if opening != 0 || streams != 0 {
				t.Fatal("completed cleanup retained its reservation")
			}
		})
	}
}
