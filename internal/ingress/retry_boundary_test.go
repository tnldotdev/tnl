package ingress

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/relay"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIngressCorrelatesPreHTTPRelayTimeout(t *testing.T) {
	ingressReports, relayReports := make(chan error, 2), make(chan error, 2)
	f := newAdmissionTransportFixture(t, func(err error) { relayReports <- err })
	config := serviceIngressConfig(t, nil)
	control := config.Control.(*httpsServiceControl)
	control.services["route.example"] = httpsService{service: f.header.ServiceID, run: f.header.ServiceRunID}
	control.relays = []ingressv1.ServiceRelay{f.relay}
	config.Forwarder = f.forwarder
	config.OpenTimeout = 750 * time.Millisecond
	config.OnError = func(err error) { ingressReports <- err }
	_, address := startIngress(t, config)
	client := ingressClient(t, address, "route.example", "192.0.2.4:42000", "http/1.1", "tnl-probe-"+strings.Repeat("00", 16))
	handshake := ingressWorker(t, func() { _ = client.Close() }, client.Handshake)
	incoming, err := f.publisher.AcceptServiceForwardingStream(ingressContext(t))
	if err != nil {
		t.Fatal(err)
	}
	defer incoming.Stream().Close()
	// the publisher saw the opening but sends no acknowledgment before the
	// ingress deadline. do not send an HTTP request or fabricate a request id.
	if err := ingressAwait(t, handshake); err == nil {
		t.Fatal("withheld relay acknowledgment did not fail TLS")
	}
	header := incoming.Header
	_ = incoming.Stream().Close()
	err = ingressAwait(t, ingressReports)
	var got *VisitorError
	if !errors.As(err, &got) {
		t.Fatal("missing visitor diagnostics", err)
	}
	wantHello := sha256.Sum256(make([]byte, 16))
	service, run, visitor, _ := got.ForwardingScope()
	attempts := got.RelayAttempts()
	if got.ClientHelloID() != [16]byte(wantHello[:16]) || service != header.ServiceID || run != header.ServiceRunID || visitor != header.VisitorConnectionID ||
		len(attempts) != 1 || attempts[0].RelayRunID != header.RelayRunID || attempts[0].PublisherConnectionID != header.PublisherConnectionID ||
		attempts[0].Step != "wait_for_ack" || attempts[0].Committed || !errors.Is(attempts[0].Err, context.DeadlineExceeded) {
		t.Fatal("report lost pre-HTTP correlation or opening attribution", got, attempts)
	}
	var relayed *relay.ForwardingError
	var opening *tunnel.OpeningError
	if err := ingressAwait(t, relayReports); !errors.As(err, &relayed) || !errors.As(relayed.ForwardingOperation(), &opening) || opening.Step != "wait_for_ack" {
		t.Fatal("relay lost its publisher opening phase", err)
	}
	_, relayRun, publisher := relayed.RelayScope()
	_, _, relayVisitor, _ := relayed.ForwardingScope()
	if relayVisitor != visitor || relayRun != header.RelayRunID || publisher != header.PublisherConnectionID {
		t.Fatal("publisher, relay and ingress reported different identities")
	}
}

func TestIngressRetryBoundary(t *testing.T) {
	for _, committed := range []int{0, 1} {
		t.Run(fmt.Sprintf("visitor_bytes=%d", committed), func(t *testing.T) {
			first := newServiceFailureRelay(t, committed)
			fallback := newServiceTLSRelay(t)
			_, address := startIngress(t, serviceIngressConfig(t, first.open, fallback.open))
			client := ingressClient(t, address, "route.example", "192.0.2.4:42000")
			err := client.Handshake()
			if committed != 0 {
				if err == nil {
					t.Fatal("partial ClientHello backend completed TLS")
				}
				if fallback.opens.Load() != 0 {
					t.Fatal("retried after visitor byte commit")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				exchangePing(t, client)
				result := ingressAwait(t, fallback.result)
				if result.err != nil || result.request != "ping" || result.visitorConnectionID != first.visitorConnectionID() {
					t.Fatalf("fallback = %+v", result)
				}
				if fallback.opens.Load() != 1 {
					t.Fatal("fallback not opened exactly once")
				}
			}
			if first.opens.Load() != 1 || !opaqueid.Valid(first.visitorConnectionID(), opaqueid.VisitorConnectionPrefix) {
				t.Fatalf("first opens=%d, ID=%q", first.opens.Load(), first.visitorConnectionID())
			}
		})
	}
}

func TestIngressAlternatesInitialRelayPerVisitor(t *testing.T) {
	first, second := newServiceTLSRelay(t), newServiceTLSRelay(t)
	_, address := startIngress(t, serviceIngressConfig(t, first.open, second.open))
	for _, backend := range []*serviceTLSRelay{first, second} {
		client := ingressClient(t, address, "route.example", "192.0.2.4:42000")
		if err := client.Handshake(); err != nil {
			t.Fatal(err)
		}
		exchangePing(t, client)
		if result := ingressAwait(t, backend.result); result.err != nil || result.request != "ping" {
			t.Fatalf("backend result = %+v", result)
		}
	}
	if first.opens.Load() != 1 || second.opens.Load() != 1 {
		t.Fatalf("selected first=%d second=%d, want one each", first.opens.Load(), second.opens.Load())
	}
}

func TestIngressRotatedRelayDoesNotRetryCommittedByte(t *testing.T) {
	first := newServiceTLSRelay(t)
	second := newServiceFailureRelay(t, 1)
	_, address := startIngress(t, serviceIngressConfig(t, first.open, second.open))
	client := ingressClient(t, address, "route.example", "192.0.2.4:42000")
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	exchangePing(t, client)
	if result := ingressAwait(t, first.result); result.err != nil {
		t.Fatal(result.err)
	}
	client = ingressClient(t, address, "route.example", "192.0.2.4:42000")
	if err := client.Handshake(); err == nil {
		t.Fatal("partial ClientHello completed TLS")
	}
	if first.opens.Load() != 1 || second.opens.Load() != 1 {
		t.Fatalf("retried committed visitor bytes: first=%d second=%d", first.opens.Load(), second.opens.Load())
	}
}

func TestIngressStalledAttemptLeavesFallbackBudget(t *testing.T) {
	for _, stage := range []string{"open", "proxy_write", "hello_write"} {
		t.Run(stage, func(t *testing.T) {
			first := waitingServiceRelay(nil)
			if stage != "open" {
				a, b := net.Pipe()
				ownIngressConn(t, a)
				ownIngressConn(t, b)
				first = func(context.Context, tunnelv1.ServiceForwardingHeader, func(context.Context) error) (net.Conn, error) {
					return a, nil // peer never reads the PROXY header.
				}
				if stage == "hello_write" {
					ctx, cancel := context.WithCancel(t.Context())
					ingressWorker(t, func() { cancel(); _ = b.Close() }, func() error {
						if _, _, err := proxyproto.Decode(b); err != nil {
							return err
						}
						<-ctx.Done()
						return nil
					})
				}
			}
			fallback := newServiceTLSRelay(t)
			config := serviceIngressConfig(t, first, fallback.open)
			config.OpenTimeout = 2 * time.Second
			_, address := startIngress(t, config)
			client := ingressClient(t, address, "route.example", "192.0.2.4:42000")
			if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			if err := client.Handshake(); err != nil {
				t.Fatal(err)
			}
			if elapsed := time.Since(started); elapsed > 900*time.Millisecond {
				t.Fatalf("fallback took %s; first relay attempt exceeded its budget", elapsed)
			}
			exchangePing(t, client)
			if result := ingressAwait(t, fallback.result); result.err != nil {
				t.Fatal(result.err)
			}
		})
	}
}

func TestForcedDrainCancelsPendingOpen(t *testing.T) {
	entered := make(chan struct{})
	config := serviceIngressConfig(t, waitingServiceRelay(entered))
	config.OpenTimeout = 2 * time.Second
	server, address := startIngress(t, config)
	client := ingressClient(t, address, "route.example", "192.0.2.4:42000")
	handshake := ingressWorker(t, func() { _ = client.Close() }, client.Handshake)
	ingressAwait(t, entered)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := server.Drain(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	ingressAwait(t, handshake)
	joined := make(chan struct{})
	go func() { server.active.Wait(); close(joined) }()
	t.Cleanup(func() { ingressAwait(t, joined) })
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("forced drain retained a pending backend open")
	}
}

func TestIngressBothBackendsUnavailable(t *testing.T) {
	first, second := make(chan struct{}), make(chan struct{})
	config := serviceIngressConfig(t, waitingServiceRelay(first), waitingServiceRelay(second))
	config.OpenTimeout = 200 * time.Millisecond
	_, address := startIngress(t, config)
	client := ingressClient(t, address, "route.example", "192.0.2.4:42000")
	_ = client.SetDeadline(time.Now().Add(time.Second))
	started := time.Now()
	if err := client.Handshake(); err == nil {
		t.Fatal("unavailable relays completed TLS")
	}
	if time.Since(started) > 750*time.Millisecond {
		t.Fatal("opening exceeded the configured overall budget")
	}
	ingressAwait(t, first)
	ingressAwait(t, second)
}

type failAfterProxyConn struct {
	net.Conn
	visitorBytes, writes int
}

func (c *failAfterProxyConn) Write(p []byte) (int, error) {
	c.writes++
	if c.writes == 1 {
		return c.Conn.Write(p)
	}
	return min(c.visitorBytes, len(p)), errors.New("ClientHello write failed")
}
