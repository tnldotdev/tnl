package publisher

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"

	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// the visitor sends ClientHello but stops reading the publisher's TLS response.
type stalledPublicTLS struct {
	net.Conn
	reading chan struct{}
	release chan struct{}
}

func (c *stalledPublicTLS) Read(p []byte) (int, error) {
	close(c.reading)
	<-c.release
	return 0, net.ErrClosed
}

func TestPublicCapacitySlowSourcesLeaveRoomForOtherVisitors(t *testing.T) {
	for _, sources := range []int{1, 2} {
		t.Run(fmt.Sprint(sources), func(t *testing.T) {
			f := newPublicCapacityFixture(t, 32, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
			for n := range sources {
				for slot := range PendingSetupsPerSource {
					source := netip.AddrFrom4([4]byte{192, 0, 2, byte(n + 1)})
					stream, err := f.openFrom(slot%2, false, source)
					if err != nil {
						t.Fatal("open stalled visitor", err)
					}
					if _, err := stream.Write(f.metadataFor(stream)); err != nil {
						t.Fatal(err)
					}
					stalled := &stalledPublicTLS{Conn: stream, reading: make(chan struct{}), release: make(chan struct{})}
					done := make(chan error, 1)
					t.Cleanup(func() {
						close(stalled.release)
						_ = stream.Close()
						_ = awaitPublisherTest(t, done)
					})
					go func() { done <- tls.Client(stalled, &tls.Config{ServerName: "route.example"}).HandshakeContext(f.ctx) }()
					awaitPublisherTest(t, stalled.reading)
				}
			}
			f.wait(sources*PendingSetupsPerSource, 0)
			for relay := range 2 {
				stream, err := f.openFrom(relay, false, netip.MustParseAddr("198.51.100.1"))
				if err != nil {
					t.Fatal("slow sources blocked another source before TLS", err)
				}
				response, err := f.request(stream, "/healthy")
				if err != nil {
					t.Fatal("slow sources blocked another source's request", err)
				}
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				if response.StatusCode != 204 {
					t.Fatal("healthy visitor denied", response.StatusCode)
				}
			}
		})
	}
}

func TestPublicCapacitySourceLimitAcrossRelaysAllowsBrowserBurst(t *testing.T) {
	for _, addresses := range [][2]string{
		{"192.0.2.1", "::ffff:192.0.2.1"},
		{"2001:db8::1", "2001:db8::ffff"},
	} {
		t.Run(addresses[0], func(t *testing.T) {
			f := newPublicCapacityFixture(t, 32, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
			var clients []*tls.Conn
			for n := range PendingSetupsPerSource {
				stream, err := f.openFrom(n%2, false, netip.MustParseAddr(addresses[n%2]))
				if err != nil {
					t.Fatal(err)
				}
				client, err := f.secure(stream)
				if err != nil {
					t.Fatal("browser burst rejected", err)
				}
				clients = append(clients, client)
			}
			f.wait(PendingSetupsPerSource, 0)
			for relay := range 2 {
				stream, err := f.openFrom(relay, false, netip.MustParseAddr(addresses[relay]))
				if err != nil {
					t.Fatal("source overflow spent relay capacity", err)
				}
				if _, err := f.secure(stream); err == nil {
					t.Fatal("source overflow passed TLS through relay", relay)
				}
				f.wait(PendingSetupsPerSource, 0)
			}
			// authorization releases pending source capacity, even while these
			// keep-alive connections retain their authorized run capacity.
			for _, client := range clients {
				response, err := capacityRequest(client, "/burst", false)
				if err != nil || response.StatusCode != 204 {
					t.Fatal("browser request rejected", err)
				}
				_ = response.Body.Close()
			}
			f.wait(0, PendingSetupsPerSource)
			stream, err := f.openFrom(1, false, netip.MustParseAddr(addresses[0]))
			if err != nil {
				t.Fatal(err)
			}
			response, err := f.request(stream, "/next")
			if err != nil || response.StatusCode != 204 {
				t.Fatal("authorized connections retained source setup capacity", err)
			}
			_ = response.Body.Close()
		})
	}
}

func TestPublicCapacitySourceRequiresVerifiedMetadata(t *testing.T) {
	route, err := newTestPublicURLServer(t, PublicURLServerConfig{Hostname: "route.example", Handler: http.NotFoundHandler()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	for n := range PendingSetupsPerSource + 1 {
		connection, peer := net.Pipe()
		a, err := reserveTestPublicSetup(route, connection)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { a.retire(); _ = peer.Close() })
		header, metadata := sourceMetadataFixture(t, route)
		if n == 0 {
			changed := metadata
			changed.Source = netip.MustParseAddrPort("198.51.100.1:1234")
			if err := a.authenticateSource(header, changed); !errors.Is(err, visitortoken.ErrVisitorSource) {
				t.Fatal("rewritten source accepted", err)
			}
			if len(route.pendingSources) != 0 || a.source.IsValid() {
				t.Fatal("unverified metadata spent source capacity")
			}
		}
		err = a.authenticateSource(header, metadata)
		if n < PendingSetupsPerSource {
			if err != nil {
				t.Fatal(err)
			}
		} else {
			var denied *tunnel.ProtocolError
			if !errors.As(err, &denied) || denied.Code != tunnelv1.CapacityExceeded {
				t.Fatal("source overflow lost its capacity classification", err)
			}
		}
	}
}

func TestPublicCapacitySourceRetirementSurvivesRelayReconnect(t *testing.T) {
	f := newPublicCapacityFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	source := netip.MustParseAddr("192.0.2.1")
	var held []retiringPublicVisitor
	for n := range PendingSetupsPerSource {
		visitor := openRetiringPublicVisitor(t, f, source)
		visitor.cancel()
		awaitPublisherTest(t, visitor.stream.entered)
		held = append(held, visitor)
		f.wait(n+1, 0)
	}
	f.refs[0].PublisherConnectionID = "reconnected"
	f.refs[0].ConnectionAssignmentRevision++
	f.connect(0)
	for relay := range 2 {
		stream, err := f.openFrom(relay, false, source)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.secure(stream); err == nil {
			t.Fatal("reconnect borrowed source capacity before physical cleanup", relay)
		}
		f.wait(PendingSetupsPerSource, 0)
	}
	held[0].stream.release()
	awaitPublisherTest(t, held[0].admission.done)
	stream, err := f.openFrom(1, false, source)
	if err != nil {
		t.Fatal(err)
	}
	response, err := f.request(stream, "/after-cleanup")
	if err != nil || response.StatusCode != 204 {
		t.Fatal("joined source capacity was not reusable", err)
	}
	_ = response.Body.Close()
	for _, visitor := range held {
		visitor.stream.release()
		awaitPublisherTest(t, visitor.admission.done)
	}
	f.wait(0, 0)
	f.route.mu.Lock()
	defer f.route.mu.Unlock()
	if len(f.route.pendingSources) != 0 {
		t.Fatal("retirement retained source keys")
	}
}
