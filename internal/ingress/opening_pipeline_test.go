package ingress

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/ingress/clienthello"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func maximumOpeningClientHello() []byte {
	vector := func(p []byte) []byte { return append(binary.BigEndian.AppendUint16(nil, uint16(len(p))), p...) }
	name := append([]byte{0}, vector([]byte("route.example"))...)
	sni := vector(name)
	extensions := append([]byte{0, 0}, vector(sni)...)
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0)
	// four records use twenty bytes outside the handshake; the padding extension
	// reaches the inspector's exact wire limit without exceeding a record limit.
	padding := clienthello.MaxClientHelloBytes - 20 - 4 - len(body) - 2 - len(extensions) - 4
	extensions = append(extensions, 0, 21)
	extensions = append(extensions, vector(make([]byte, padding))...)
	body = append(body, vector(extensions)...)
	handshake := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	var records []byte
	for len(handshake) > 0 {
		n := min(len(handshake), 16<<10)
		records = append(records, 22, 3, 1)
		records = append(records, vector(handshake[:n])...)
		handshake = handshake[n:]
	}
	return records
}

func TestPublicOpeningMaximumClientHelloAndForwardedBytes(t *testing.T) {
	var f *serviceTransportFixture
	config := serviceIngressConfig(t, func(ctx context.Context, header tunnelv1.ServiceForwardingHeader) (net.Conn, error) {
		return f.open(ctx, header)
	})
	p := config.PublicServices
	control := p.config.Control.(*httpsServiceControl)
	relay := control.relays[0]
	ref := tunnelv1.ServicePublisherConnectionRef{
		ServiceID: control.service, ServiceRunID: control.run, RunNumber: 1,
		PublisherConnectionID: relay.PublisherConnectionId, ConnectionSlot: uint8(relay.ConnectionSlot),
		ConnectionAssignmentRevision: uint64(relay.ConnectionAssignmentRevision), RelayServiceID: relay.RelayServiceId,
	}
	f = newServiceTransportFixture(t, ref, relay)
	control.relays[0] = f.relay
	metrics := &testMetrics{visitorOutcomes: make(chan string, 2)}
	config.Metrics, p.config.Metrics = metrics, metrics
	server, address := startIngress(t, config)
	hello := maximumOpeningClientHello()
	if len(hello) != clienthello.MaxClientHelloBytes {
		t.Fatal("fixture did not reach ClientHello limit", len(hello))
	}
	worker := ingressWorker(t, func() { _ = f.publisher.Close() }, func() error {
		visitors := make(map[string]bool)
		for range 2 {
			incoming, err := f.publisher.AcceptServiceForwardingStream(ingressContext(t))
			if err != nil {
				return err
			}
			if incoming.Header.Validate() != nil || tunnel.ServiceForwardingRef(incoming.Header) != ref ||
				incoming.Header.PublicService == nil || incoming.Header.PublicService.DestinationPort != 443 ||
				incoming.Header.SourceIP != "192.0.2.4" || visitors[incoming.Header.VisitorConnectionID] {
				return errors.New("maximum ClientHello changed the service run or visitor identity")
			}
			visitors[incoming.Header.VisitorConnectionID] = true
			stream := incoming.Stream()
			// no metadata or visitor bytes may arrive before publisher acceptance.
			if err := stream.SetReadDeadline(time.Now()); err != nil {
				return err
			}
			var beforeAcceptance [1]byte
			n, err := stream.Read(beforeAcceptance[:])
			var timeout net.Error
			if n != 0 || !errors.As(err, &timeout) || !timeout.Timeout() {
				return fmt.Errorf("service stream received bytes before acknowledgment: n=%d error=%v", n, err)
			}
			if err := stream.SetReadDeadline(time.Time{}); err != nil {
				return err
			}
			if err := incoming.Accept(); err != nil {
				return err
			}
			if err := stream.SetDeadline(time.Now().Add(fixtureTimeout)); err != nil {
				return err
			}
			header, reader, err := proxyproto.Decode(stream)
			if err != nil {
				return err
			}
			if header.Source != netip.MustParseAddrPort("192.0.2.4:42000") || header.Destination != netip.MustParseAddrPort("203.0.113.10:443") {
				return errors.New("PROXY addresses changed")
			}
			got, err := io.ReadAll(reader)
			if err != nil {
				return err
			}
			if !bytes.Equal(got, hello) {
				return fmt.Errorf("maximum ClientHello lost bytes: %d", len(got))
			}
			if _, err := stream.Write([]byte("ok")); err != nil {
				return err
			}
			if err := stream.CloseWrite(); err != nil {
				return err
			}
			_ = stream.Close()
		}
		return nil
	})
	for index := range 2 {
		connection, err := net.DialTimeout("tcp", address, fixtureTimeout)
		if err != nil {
			t.Fatal(err)
		}
		ownIngressConn(t, connection)
		_ = connection.SetDeadline(time.Now().Add(fixtureTimeout))
		metadata, err := proxyproto.Encode(proxyproto.Header{
			Source: netip.MustParseAddrPort("192.0.2.4:42000"), Destination: netip.MustParseAddrPort("203.0.113.10:443"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := writeAll(connection, metadata); err != nil {
			t.Fatal(err)
		}
		if _, err := connection.Write(hello); err != nil {
			t.Fatal(err)
		}
		if err := connection.(*net.TCPConn).CloseWrite(); err != nil {
			t.Fatal(err)
		}
		response, err := io.ReadAll(connection)
		if err != nil || string(response) != "ok" {
			t.Fatalf("maximum ClientHello response: %q, %v", response, err)
		}
		if outcome := ingressAwait(t, metrics.visitorOutcomes); outcome != "forwarded" {
			t.Fatal("maximum ClientHello forwarding failed", outcome)
		}
		metrics.forwardedMu.Lock()
		upload, download := metrics.forwardedBytes["visitor_to_publisher"], metrics.forwardedBytes["publisher_to_visitor"]
		metrics.forwardedMu.Unlock()
		if upload != int64((index+1)*len(hello)) || download != int64((index+1)*2) {
			t.Fatalf("forwarding lost or duplicated prefix: upload=%d download=%d", upload, download)
		}
	}
	if err := ingressAwait(t, worker); err != nil {
		t.Fatal(err)
	}
	if f.relayServer.accepted.Load() != 1 || f.publisherServer.accepted.Load() != 1 {
		t.Fatalf("sequential visitors did not reuse both service sessions: ingress=%d publisher=%d", f.relayServer.accepted.Load(), f.publisherServer.accepted.Load())
	}
	if err := server.Drain(ingressContext(t)); err != nil {
		t.Fatal("maximum ClientHello server did not join", err)
	}
	if err := f.close(); err != nil {
		t.Fatal("maximum ClientHello transport did not join", err)
	}
}

type overflowFailureConnector struct {
	relayConnector
	failure error
}

func (c overflowFailureConnector) Connect(ctx context.Context, target relayTarget) (muxsession.Session, error) {
	session, err := c.relayConnector.Connect(ctx, target)
	if err != nil {
		return nil, err
	}
	return overflowFailureSession{Session: session, failure: c.failure}, nil
}

type overflowFailureSession struct {
	muxsession.Session
	failure error
}

func (s overflowFailureSession) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	return &overflowFailureStream{Stream: stream, failure: s.failure}, nil
}

type overflowFailureStream struct {
	muxsession.Stream
	failure error
	opening bool
	prefix  int
}

func (s *overflowFailureStream) Write(p []byte) (int, error) {
	if s.opening {
		n, err := s.Stream.Write(p[:1])
		return n, errors.Join(s.failure, err)
	}
	if s.prefix > 0 {
		s.prefix -= len(p)
		s.opening = s.prefix == 0
		return s.Stream.Write(p)
	}
	// the real control handshake is not a public opening.
	_, service, initial, err := tunnelv1.ReadForwardingOpening(bytes.NewReader(p))
	if err == nil && service == nil {
		s.prefix = tunnelv1.MaxInitialBytes - len(initial)
	}
	return s.Stream.Write(p)
}

func TestPublicOpeningOverflowFailureKeepsCommitAndSession(t *testing.T) {
	material := newForwardingTestMaterial(t)
	server := startForwardingTestServer(t, material, func(ctx context.Context, transport muxsession.Session) error {
		session, _, err := tunnel.Accept(ctx, transport, func(context.Context, tunnelv1.Message) error { return nil })
		if err != nil {
			return err
		}
		defer session.Close()
		for {
			incoming, err := session.AcceptInternalForwardingStream(ctx)
			if err != nil {
				return nil
			}
			if err := incoming.Accept(); err != nil {
				return err
			}
			_, _ = io.Copy(io.Discard, incoming.Stream())
			_ = incoming.Stream().Close()
		}
	})
	f := newTestForwarder(t, material)
	cause := errors.New("overflow write failed")
	f.connector = overflowFailureConnector{relayConnector: f.connector, failure: cause}
	b := mustOnlyBackend(t, f, forwardingTestEntry(time.Now(), server.address())).(forwardingBackend)
	stream, err := b.Start(ingressContext(t), "warm", false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.Close()
	proxy := []byte("proxy")
	stream, err = b.Start(ingressContext(t), "overflow", false, proxy, bytes.Repeat([]byte("v"), tunnelv1.MaxInitialBytes))
	var opening *tunnel.OpeningError
	if stream != nil || !errors.As(err, &opening) || !errors.Is(err, cause) || !opening.Committed || opening.VisitorBytes != int64(tunnelv1.MaxInitialBytes-len(proxy)+1) {
		t.Fatalf("overflow commit lost: %v", err)
	}
	f.mu.Lock()
	current := f.sessions[b.target.key()]
	f.mu.Unlock()
	if current == nil || current.session.Err() != nil || server.accepted.Load() != 1 {
		t.Fatal("overflow failure replaced the borrowed session")
	}
}
