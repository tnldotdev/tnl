package ingress

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestPublicForwardingRequiresExactConnectedRelayProcess(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*ingressv1.IngressRoutingPublisherConnection)
	}{
		{"relay_process", func(c *ingressv1.IngressRoutingPublisherConnection) { c.RelayId = "sibling_in_same_service" }},
		{"relay_run", func(c *ingressv1.IngressRoutingPublisherConnection) { c.RelayRunId = "previous_process_run" }},
		{"relay_lease", func(c *ingressv1.IngressRoutingPublisherConnection) { c.RelayLeaseRevision-- }},
		{"publisher_connection", func(c *ingressv1.IngressRoutingPublisherConnection) {
			c.PublisherConnectionId = "previous_publisher_connection"
		}},
		{"assignment", func(c *ingressv1.IngressRoutingPublisherConnection) { c.ConnectionAssignmentRevision-- }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newAdmissionTransportFixture(t)
			entry := f.entry
			entry.PublisherConnections = append([]ingressv1.IngressRoutingPublisherConnection(nil), entry.PublisherConnections...)
			test.change(&entry.PublisherConnections[0])
			// the address and WebPKI hostname still reach the real connected
			// relay. a shared relay-service certificate is not a process claim.
			stale := mustOnlyBackend(t, newTestForwarder(t, f.material), entry).(forwardingBackend)
			proxy := publicForwardingProxy(t)
			_, err := stale.Start(ingressContext(t), "visitor_stale", false, proxy, []byte("hello"))
			assertAdmissionCode(t, err, tunnelv1.StaleConnectionAssignment)

			// the rejection must precede publisher work. the next accepted
			// stream must be this current opening, not the rejected visitor.
			done := ingressWorker(t, func() { _ = f.publisher.Close() }, func() error {
				incoming, err := f.publisher.AcceptVisitorStream(ingressContext(t))
				if err != nil {
					return err
				}
				defer incoming.Stream.Close()
				if incoming.Header.VisitorConnectionID != "visitor_current" {
					_ = incoming.Reject(tunnelv1.InvalidMessage)
					return fmt.Errorf("rejected process reached publisher: %s", incoming.Header.VisitorConnectionID)
				}
				if err := incoming.Accept(); err != nil {
					return err
				}
				want := append(bytes.Clone(proxy), []byte("hello")...)
				got := make([]byte, len(want))
				if _, err := io.ReadFull(incoming.Stream, got); err != nil {
					return err
				}
				if !bytes.Equal(got, want) {
					return fmt.Errorf("current opening bytes=%x; want %x", got, want)
				}
				return nil
			})
			// a copied deadline can be old while the exact process has renewed.
			f.entry.PublisherConnections[0].LeaseExpiresAt = time.Now().Add(-time.Second)
			current := mustOnlyBackend(t, f.forwarder, f.entry).(forwardingBackend)
			stream, err := current.Start(ingressContext(t), "visitor_current", false, proxy, []byte("hello"))
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			if err := ingressAwait(t, done); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPublicForwardingRealRelayRejectionRespectsRetryBoundary(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		t.Run(fmt.Sprintf("confirmed=%t", confirmed), func(t *testing.T) {
			f := newAdmissionTransportFixture(t)
			backend := mustOnlyBackend(t, f.forwarder, f.entry).(forwardingBackend)
			proxy := publicForwardingProxy(t)
			if confirmed {
				// confirm through the real relay and publisher acceptance path,
				// not by changing the forwarder's private confirmation state.
				done := ingressWorker(t, func() { _ = f.publisher.Close() }, func() error {
					incoming, err := f.publisher.AcceptVisitorStream(ingressContext(t))
					if err != nil {
						return err
					}
					defer incoming.Stream.Close()
					if err := incoming.Accept(); err != nil {
						return err
					}
					_, err = io.CopyN(io.Discard, incoming.Stream, int64(len(proxy)+1))
					return err
				})
				stream, err := backend.Start(ingressContext(t), "visitor_confirm", false, proxy, []byte("x"))
				if err != nil {
					t.Fatal(err)
				}
				if err := ingressAwait(t, done); err != nil {
					t.Fatal(err)
				}
				_ = stream.Close()
			}
			backend.header.ConnectionAssignmentRevision--
			fallback := newTLSBackend(t)
			_, address := startIngress(t, publicURLConfig(backend, fallback))
			client := ingressClient(t, address, "route.example", "")
			err := client.Handshake()
			if confirmed {
				if err == nil || fallback.opens.Load() != 0 {
					t.Fatalf("replayed committed ClientHello after return-side rejection: handshake=%v fallback_opens=%d", err, fallback.opens.Load())
				}
				return
			}
			if err != nil {
				t.Fatalf("pre-byte relay rejection did not fall back: %v", err)
			}
			exchangePing(t, client)
			if result := ingressAwait(t, fallback.result); result.err != nil || result.request != "ping" || fallback.opens.Load() != 1 {
				t.Fatalf("pre-byte fallback: %+v opens=%d", result, fallback.opens.Load())
			}
		})
	}
}

func publicForwardingProxy(t *testing.T) []byte {
	t.Helper()
	header, err := proxyproto.Encode(proxyproto.Header{
		Source: netip.MustParseAddrPort("192.0.2.1:40000"), Destination: netip.MustParseAddrPort("203.0.113.1:443"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return header
}
