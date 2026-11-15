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

	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type stalledServiceForwarder struct {
	alternate  ServiceForwarder
	stallProxy bool
}

func (f stalledServiceForwarder) OpenService(ctx context.Context, relay ingressv1.ServiceRelay, header tunnelv1.ServiceForwardingHeader, reserveCapacity func(context.Context) error) (net.Conn, error) {
	if relay.ConnectionSlot == 0 {
		if f.stallProxy {
			connection, peer := net.Pipe()
			context.AfterFunc(ctx, func() { _ = peer.Close() })
			return connection, nil
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.alternate.OpenService(ctx, relay, header, reserveCapacity)
}

func TestPublicServiceVisitorStalledRelayLeavesAlternateBudget(t *testing.T) {
	for _, proxy := range []bool{false, true} {
		t.Run(fmt.Sprintf("proxy=%t", proxy), func(t *testing.T) {
			p, _, forwarder, _ := publicServiceTestSetup(t)
			p.config.OpenTimeout = 600 * time.Millisecond
			p.config.Forwarder = stalledServiceForwarder{alternate: forwarder, stallProxy: proxy}
			connection, visitor := net.Pipe()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- p.AcceptPublic(ctx, connection, netip.MustParseAddrPort("192.0.2.4:42000"), netip.MustParseAddrPort("203.0.113.8:20000"), "", nil)
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
	p, c, _, _ := publicServiceTestSetup(t)
	admission, reason := p.admitPendingService()
	if admission == nil {
		t.Fatal(reason)
	}
	defer admission.close()
	key := trafficKey{service: c.service, id: c.run, run: 1}
	if reason := admission.selectRun(key, p.config.Traffic.Default, netip.MustParseAddr("192.0.2.4"), false); reason != "" {
		t.Fatal(reason)
	}
	pending := &budgetConn{Conn: ingress, beforeWrite: func(size int) error {
		return admission.beforeWrite(t.Context(), false, size)
	}}
	outbound := &budgetConn{Conn: upstream, beforeWrite: func(size int) error {
		return admission.beforeWrite(t.Context(), true, size)
	}}
	done := make(chan error, 1)
	go func() { _, err := streamcopy.Copy(pending, outbound); done <- err }()
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
		key := trafficKey{service: "service", id: "run", run: 1}
		limits := a.config.Default
		limits.TotalConnections = 1
		release, reason := a.acquire(key, limits)
		if release == nil {
			t.Fatal(reason)
		}
		sibling := trafficKey{service: key.service, id: "sibling", run: key.run + 1}
		a.runs[sibling] = &runTraffic{limits: limits}
		for n := 2; n < maxTrafficKeys; n++ {
			a.runs[trafficKey{service: fmt.Sprint(n), id: "unknown", run: 1}] = &runTraffic{limits: limits}
		}
		if r, reason := a.acquire(trafficKey{service: "new", id: "new", run: 1}, limits); r != nil || reason != "traffic_keys" {
			t.Fatal("table did not fail closed", reason)
		}
		time.Sleep(31 * time.Second)
		a.prune(time.Now())
		terminal := []ingressv1.ServiceRunReference{{ServiceId: key.service, ServiceRunId: key.id, RunNumber: int64(key.run)}}
		a.retireTerminal(terminal)
		if len(a.runs) != maxTrafficKeys {
			t.Fatal("retired active or unknown run")
		}
		release()
		time.Sleep(31 * time.Second)
		a.retireTerminal(terminal)
		if r, reason := a.acquire(trafficKey{service: "new", id: "new", run: 1}, limits); r == nil {
			t.Fatal("terminal proof did not free a bounded slot", reason)
		} else {
			r()
		}
		if _, exists := a.runs[key]; exists {
			t.Fatal("closed run retained totals after its last copy joined")
		}
		if _, exists := a.runs[sibling]; !exists {
			t.Fatal("closed run retired a sibling's totals")
		}
	})
}
