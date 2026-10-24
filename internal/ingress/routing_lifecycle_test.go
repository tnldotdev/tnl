package ingress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func trafficRoutingEvent(now time.Time, revision int64, tombstone bool) ingressv1.IngressRoutingTableEvent {
	entry := forwardingTestEntry(now, "relay.example:443")
	entry.CanonicalHostname = "traffic.example"
	entry.PolicyRevision, entry.IpPolicy = 1, ingressv1.AllowAll
	event := ingressv1.IngressRoutingTableEvent{RoutingTableRevision: revision, Kind: ingressv1.PublicUrlUpsert,
		PublicUrlId: entry.PublicUrlId, PublishRunNumber: entry.PublishRunNumber, CanonicalHostname: entry.CanonicalHostname,
		EntryRevision: revision, Entry: entry, PublicUrlExpiresAt: &entry.PublicUrlExpiresAt, CreatedAt: now}
	if tombstone {
		event.Kind, event.PublicUrlExpiresAt, event.Entry.PublisherConnections = ingressv1.PublicUrlTombstone, nil, nil
	}
	return event
}

func TestTrafficTotalsSurviveSameRunTombstoneRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var table RoutingTable
		event := trafficRoutingEvent(time.Now(), 1, false)
		if err := table.ApplySnapshot(ingressv1.IngressRoutingTableSnapshot{ThroughRevision: 1, Entries: []ingressv1.IngressRoutingTableEvent{event}}); err != nil {
			t.Fatal(err)
		}
		a := trafficFixture(t)
		a.terminalRuns = table.TerminalTrafficRuns
		key := trafficKey{url: event.PublicUrlId, id: event.Entry.PublishRunId, run: uint64(event.PublishRunNumber)}
		limits := a.config.Default
		limits.TotalConnections, limits.TotalUploadBytes, limits.TotalDownloadBytes = 1, 4, 4
		release, reason := a.acquire(key, limits)
		if release == nil {
			t.Fatal(reason)
		}
		for _, upload := range []bool{true, false} {
			if err := a.bytes(t.Context(), key, upload, 4, true); err != nil {
				t.Fatal(err)
			}
		}
		release()
		tombstone := trafficRoutingEvent(time.Now(), 2, true)
		if err := table.ApplyPage(1, ingressv1.IngressRoutingTablePage{ThroughRevision: 2, NextRevision: 2, Events: []ingressv1.IngressRoutingTableEvent{tombstone}}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(31 * time.Second)
		a.prune(time.Now())
		// resnapshotting during the outage is not evidence that this run ended.
		if err := table.ApplySnapshot(ingressv1.IngressRoutingTableSnapshot{ThroughRevision: 2}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(31 * time.Second)
		a.prune(time.Now())
		recovered := trafficRoutingEvent(time.Now(), 3, false)
		if err := table.ApplyPage(2, ingressv1.IngressRoutingTablePage{ThroughRevision: 3, NextRevision: 3, Events: []ingressv1.IngressRoutingTableEvent{recovered}}); err != nil {
			t.Fatal(err)
		}
		if r, reason := a.acquire(key, limits); r != nil || reason != "public_url_connection_total" {
			if r != nil {
				r()
			}
			t.Fatalf("recovery reset exhausted connection total: %s", reason)
		}
		for _, upload := range []bool{true, false} {
			if err := a.bytes(t.Context(), key, upload, 1, true); err == nil {
				t.Fatal("recovery reset exhausted byte total")
			}
		}
	})
}

func TestPendingPromotionAcceptsCurrentFullRelay(t *testing.T) {
	s, _, header, route := pendingAdmissionFixture(t)
	f := newTestForwarder(t, newForwardingTestMaterial(t))
	entry := forwardingTestEntry(time.Now(), "relay.internal:9445")
	entry.IpPolicy = ingressv1.AllowAll
	zero := int64(0)
	entry.PublisherConnections[0].AvailableStreams = &zero
	full, err := f.PublicURL(entry)
	if err != nil {
		t.Fatal(err)
	}
	*route = full
	if len(route.Backends) != 0 {
		t.Fatal("full relay eligible for a new stream")
	}
	if result := s.PromotePendingAdmission(t.Context(), header); result.Type != tunnelv1.StreamAccepted {
		t.Fatalf("current last-slot visitor rejected: %+v", result)
	}
}

type stalledServiceForwarder struct {
	alternate  ServiceForwarder
	stallProxy bool
}

func (f stalledServiceForwarder) OpenPrivate(ctx context.Context, relay ingressv1.ServiceRelay, header tunnelv1.ServiceForwardingHeader, events *tunnel.ReturnEvents) (net.Conn, error) {
	if relay.ConnectionSlot == 0 {
		if f.stallProxy {
			connection, peer := net.Pipe()
			context.AfterFunc(ctx, func() { _ = peer.Close() })
			return connection, nil
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.alternate.OpenPrivate(ctx, relay, header, events)
}

func TestConnectorStalledRelayLeavesAlternateBudget(t *testing.T) {
	for _, proxy := range []bool{false, true} {
		t.Run(fmt.Sprintf("proxy=%t", proxy), func(t *testing.T) {
			p, control, forwarder, roots, _, _ := privateTestSetup(t)
			p.config.PendingTimeout = 600 * time.Millisecond
			p.config.Forwarder = stalledServiceForwarder{alternate: forwarder, stallProxy: proxy}
			transport, stop := privateTestConnect(t, p, control, roots)
			defer stop()
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			stream, err := transport.OpenStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			_ = stream.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := tunnelv1.WriteConnectorVisitorOpening(stream, privateEntry(control), nil); err != nil {
				t.Fatal(err)
			}
			if _, err := stream.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			var reply [4]byte
			if _, err := io.ReadFull(stream, reply[:]); err != nil || string(reply[:]) != "pong" {
				t.Fatalf("alternate forwarding: %q %v", reply, err)
			}
		})
	}
}

func TestDirectVisitorStalledRelayLeavesAlternateBudget(t *testing.T) {
	for _, proxy := range []bool{false, true} {
		t.Run(fmt.Sprintf("proxy=%t", proxy), func(t *testing.T) {
			p, control, forwarder, _, _, _ := privateTestSetup(t)
			updateNativePolicy(t, p, control, func(update *visitorlease.Update) { update.View.Public, update.View.Port = true, 20000 })
			p.config.PendingTimeout = 600 * time.Millisecond
			p.config.Forwarder = stalledServiceForwarder{alternate: forwarder, stallProxy: proxy}
			connection, visitor := net.Pipe()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- p.AcceptDirect(ctx, connection, netip.MustParseAddrPort("192.0.2.4:42000"), netip.MustParseAddrPort("203.0.113.8:20000"))
			}()
			t.Cleanup(func() {
				cancel()
				_ = visitor.Close()
				_ = connection.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("direct visitor did not join")
				}
			})
			_ = visitor.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := visitor.Write([]byte("ping")); err != nil {
				t.Fatalf("alternate direct setup: %v", err)
			}
			var reply [4]byte
			if _, err := io.ReadFull(visitor, reply[:]); err != nil || string(reply[:]) != "pong" {
				t.Fatalf("alternate direct forwarding: %q %v", reply, err)
			}
		})
	}
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client.(*net.TCPConn), server.(*net.TCPConn)
}

func TestPendingDirectMySQLServerFirstHalfClose(t *testing.T) {
	visitor, ingress := tcpPair(t)
	upstream, mysql := tcpPair(t)
	pending := &pendingDirectConn{Conn: ingress, ctx: t.Context(), promoted: make(chan struct{})}
	pending.upload.Store(64 << 10)
	pending.download.Store(128 << 10)
	done := make(chan error, 1)
	go func() { _, err := streamcopy.Copy(pending, upstream); done <- err }()
	t.Cleanup(func() { _ = ingress.Close(); _ = upstream.Close(); <-done })
	// a MySQL ERR packet may precede any client byte. its EOF must reach the
	// visitor immediately, rather than waiting for pending authorization expiry.
	packet := []byte{3, 0, 0, 0, 0xff, 0x10, 0x04}
	if _, err := mysql.Write(packet); err != nil {
		t.Fatal(err)
	}
	if err := mysql.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = visitor.SetReadDeadline(time.Now().Add(time.Second))
	got := make([]byte, len(packet))
	if _, err := io.ReadFull(visitor, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(packet) {
		t.Fatalf("MySQL error packet changed: %x", got)
	}
	var b [1]byte
	if _, err := visitor.Read(b[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("server-first EOF hidden by pending wrapper: %v", err)
	}
}

func TestTrafficTerminalRetirementIsBoundedAndExact(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := trafficFixture(t)
		var table RoutingTable
		a.terminalRuns = table.TerminalTrafficRuns
		event := trafficRoutingEvent(time.Now(), 1, false)
		key := trafficKey{url: event.PublicUrlId, id: event.Entry.PublishRunId, run: uint64(event.PublishRunNumber)}
		limits := a.config.Default
		limits.TotalConnections = 1
		release, _ := a.acquire(key, limits)
		defer release()
		// fill the finite table with unknown runs. no absence or age can make
		// those totals safe to discard, including after a fresh snapshot.
		sibling := trafficKey{url: key.url, id: "sibling", run: key.run + 1}
		a.runs[sibling] = &runTraffic{limits: limits}
		for n := 2; n < maxTrafficKeys; n++ {
			a.runs[trafficKey{url: fmt.Sprint(n), id: "unknown", run: 1}] = &runTraffic{limits: limits}
		}
		if r, reason := a.acquire(trafficKey{url: "new", id: "new", run: 1}, limits); r != nil || reason != "traffic_keys" {
			t.Fatal("table did not fail closed", reason)
		}
		if err := table.ApplySnapshot(ingressv1.IngressRoutingTableSnapshot{ThroughRevision: 1, Entries: []ingressv1.IngressRoutingTableEvent{event}}); err != nil {
			t.Fatal(err)
		}
		closed := trafficRoutingEvent(time.Now(), 2, true)
		proof := true
		closed.Entry.PublishRunClosed = &proof
		if err := table.ApplyPage(1, ingressv1.IngressRoutingTablePage{ThroughRevision: 2, NextRevision: 2, Events: []ingressv1.IngressRoutingTableEvent{closed}}); err != nil {
			t.Fatal(err)
		}
		// the routing table owns its proof, and active copies keep their budget.
		proof = false
		time.Sleep(31 * time.Second)
		a.prune(time.Now())
		if len(a.runs) != maxTrafficKeys {
			t.Fatal("retired active or unknown run")
		}
		release()
		time.Sleep(31 * time.Second)
		if r, reason := a.acquire(trafficKey{url: "new", id: "new", run: 1}, limits); r == nil {
			t.Fatal("terminal proof did not free a bounded slot", reason)
		} else {
			r()
		}
		if len(a.runs) != maxTrafficKeys {
			t.Fatalf("traffic keys=%d", len(a.runs))
		}
		if _, exists := a.runs[key]; exists {
			t.Fatal("closed run retained totals after its last copy joined")
		}
		if _, exists := a.runs[sibling]; !exists {
			t.Fatal("closed run retired a pool sibling's totals")
		}
	})
}

func TestTerminalRoutingProofCannotReviveSameRun(t *testing.T) {
	var table RoutingTable
	first := trafficRoutingEvent(time.Now(), 1, false)
	if err := table.ApplySnapshot(ingressv1.IngressRoutingTableSnapshot{ThroughRevision: 1, Entries: []ingressv1.IngressRoutingTableEvent{first}}); err != nil {
		t.Fatal(err)
	}
	closed := trafficRoutingEvent(time.Now(), 2, true)
	proof := true
	closed.Entry.PublishRunClosed = &proof
	if err := table.ApplyPage(1, ingressv1.IngressRoutingTablePage{ThroughRevision: 2, NextRevision: 2, Events: []ingressv1.IngressRoutingTableEvent{closed}}); err != nil {
		t.Fatal(err)
	}
	revived := trafficRoutingEvent(time.Now(), 3, false)
	if err := table.ApplyPage(2, ingressv1.IngressRoutingTablePage{ThroughRevision: 3, NextRevision: 3, Events: []ingressv1.IngressRoutingTableEvent{revived}}); !errors.Is(err, ErrRoutingTableEvent) {
		t.Fatalf("terminal run revived after totals could retire: %v", err)
	}
}
