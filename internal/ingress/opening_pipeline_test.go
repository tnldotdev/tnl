package ingress

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
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
	f := newAdmissionTransportFixture(t)
	backends, err := f.forwarder.Backends(f.entry)
	if err != nil {
		t.Fatal(err)
	}
	metrics := &testMetrics{visitorOutcomes: make(chan string, 2)}
	config := publicURLConfig(backends...)
	lookup := config.Lookup
	config.Lookup = func(host string) ([]PublicURL, LookupReason) {
		candidates, reason := lookup(host)
		for index := range candidates {
			candidates[index].AccessMode = "anonymous"
		}
		return candidates, reason
	}
	config.Metrics = metrics
	_, address := startIngress(t, config)
	hello := maximumOpeningClientHello()
	if len(hello) != clienthello.MaxClientHelloBytes {
		t.Fatal("fixture did not reach ClientHello limit", len(hello))
	}
	worker := ingressWorker(t, func() { _ = f.publisher.Close() }, func() error {
		for range 2 {
			incoming, err := f.publisher.AcceptVisitorStream(ingressContext(t))
			if err != nil {
				return err
			}
			if !incoming.Header.ConfirmBeforeBytes {
				return errors.New("wrong assignment confirmation phase")
			}
			if err := incoming.Accept(); err != nil {
				return err
			}
			header, reader, err := proxyproto.Decode(incoming.Stream)
			if err != nil {
				return err
			}
			if !header.Source.Addr().IsLoopback() || !header.Destination.Addr().IsLoopback() {
				return errors.New("PROXY addresses changed")
			}
			got, err := io.ReadAll(reader)
			if err != nil {
				return err
			}
			if !bytes.Equal(got, hello) {
				return fmt.Errorf("maximum ClientHello lost bytes: %d", len(got))
			}
			if _, err := incoming.Stream.Write([]byte("ok")); err != nil {
				return err
			}
			if err := incoming.Stream.CloseWrite(); err != nil {
				return err
			}
			_ = incoming.Stream.Close()
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
