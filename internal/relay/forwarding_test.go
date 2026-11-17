package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	serverhttp "github.com/tnldotdev/tnl/internal/serverhttp"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestForwardingAcceptorCancellationClosesActiveStreams(t *testing.T) {
	testForwardingRejectionMetrics(t, true)
}

func TestForwardingRejectionIsNotSuccessfulOpen(t *testing.T) {
	testForwardingRejectionMetrics(t, false)
}

func TestForwardingAcceptorStalledHeaderDoesNotBlockNextStream(t *testing.T) {
	testForwardingHeaderIsolation(t, "stalled")
}

func TestForwardingAcceptorMalformedHeaderDoesNotCloseSession(t *testing.T) {
	testForwardingHeaderIsolation(t, "malformed")
}

func TestForwardingAcceptorRejectsLegacyOpeningWithoutClosingSession(t *testing.T) {
	testForwardingHeaderIsolation(t, "legacy")
}

func testForwardingHeaderIsolation(t *testing.T, variant string) {
	t.Helper()
	secrets, err := serverhttp.NewBearerSecrets(strings.Repeat("s", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	acceptor, err := NewForwardingAcceptor(ForwardingAcceptorConfig{
		ServiceRegistry: NewServiceRegistry(), CurrentLease: func() relayv1.RelayLease { return relayv1.RelayLease{} },
		ClusterSecrets: secrets, StreamCapacity: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	controlServer, controlClient := net.Pipe()
	stalledServer, stalledClient := net.Pipe()
	healthyServer, healthyClient := net.Pipe()
	for _, connection := range []net.Conn{
		controlServer, controlClient, stalledServer, stalledClient, healthyServer, healthyClient,
	} {
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		t.Cleanup(func() { _ = connection.Close() })
	}
	transport := newForwardingTestSession(
		&forwardingTestStream{Conn: controlServer},
		&forwardingTestStream{Conn: stalledServer},
		&forwardingTestStream{Conn: healthyServer},
	)
	t.Cleanup(func() { _ = transport.Close() })
	ctx, cancel := context.WithCancel(t.Context())
	result := relayWorker(t, func() { cancel(); _ = transport.Close() }, func() error {
		return acceptor.Accept(ctx, transport)
	})
	controlResult := relayWorker(t, func() { _ = controlClient.Close() }, func() error {
		if err := tunnelv1.WriteControl(controlClient, tunnelv1.Message{
			Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version,
			Role: tunnelv1.Ingress, Credential: strings.Repeat("s", 32),
		}); err != nil {
			return err
		}
		_, err := tunnelv1.ReadControl(controlClient)
		return err
	})
	if err := relayAwait(t, controlResult); err != nil {
		t.Fatal(err)
	}
	if variant != "stalled" {
		var writeErr error
		if variant == "legacy" {
			legacy := []byte(`{"protocol_version":1,"kind":"internal_forward","public_url_id":"url_0123456789abcdefghijkl","publish_run_id":"pr_0123456789abcdefghijkl"}`)
			_, writeErr = stalledClient.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(legacy))), legacy...))
		} else {
			// a zero-length frame fails header validation on this stream only.
			_, writeErr = stalledClient.Write([]byte{0, 0, 0, 0})
		}
		if writeErr != nil {
			t.Fatal(writeErr)
		}
		response, err := tunnelv1.ReadReturnFrame(stalledClient)
		if err != nil || response.Kind != tunnelv1.ReturnRejected || response.Code != tunnelv1.InvalidMessage {
			t.Fatalf("malformed stream response = %+v, %v", response, err)
		}
	}
	// a stalled or malformed first stream must not prevent the next stream from
	// receiving a relay response before the first stream's setup deadline.
	_ = healthyClient.SetDeadline(time.Now().Add(time.Second))
	if _, err := tunnelv1.WriteServiceOpening(healthyClient, privateLifecycleHeader()); err != nil {
		t.Fatal(err)
	}
	response, err := tunnelv1.ReadReturnFrame(healthyClient)
	if err != nil || response.Kind != tunnelv1.ReturnRejected || response.Code != tunnelv1.StaleConnectionAssignment {
		t.Fatalf("healthy stream response = %+v, %v", response, err)
	}
	cancel()
	if err := relayAwait(t, result); err != nil {
		t.Fatal(err)
	}
}

func testForwardingRejectionMetrics(t *testing.T, cancelRejection bool) {
	t.Helper()
	metrics := observability.New("relay")
	observer := &forwardingMetricObserver{Metrics: metrics, done: make(chan struct{})}
	secrets, err := serverhttp.NewBearerSecrets(strings.Repeat("s", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	acceptor, err := NewForwardingAcceptor(ForwardingAcceptorConfig{
		ServiceRegistry: NewServiceRegistry(), CurrentLease: func() relayv1.RelayLease { return relayv1.RelayLease{} },
		ClusterSecrets: secrets, StreamCapacity: 1, Observer: observer,
	})
	if err != nil {
		t.Fatal(err)
	}

	controlServer, controlClient := net.Pipe()
	t.Cleanup(func() { _ = controlServer.Close(); _ = controlClient.Close() })
	forwardServer, forwardClient := net.Pipe()
	t.Cleanup(func() { _ = forwardServer.Close(); _ = forwardClient.Close() })
	for _, c := range []net.Conn{controlServer, controlClient, forwardServer, forwardClient} {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	}
	t.Cleanup(func() {
		_ = controlClient.Close()
		_ = forwardClient.Close()
	})
	writeStarted := make(chan struct{})
	transport := newForwardingTestSession(
		&forwardingTestStream{Conn: controlServer},
		&forwardingTestStream{Conn: forwardServer, writeStarted: writeStarted},
	)
	t.Cleanup(func() { _ = transport.Close() })

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	result := relayWorker(t, func() { cancel(); _ = transport.Close() }, func() error { return acceptor.Accept(ctx, transport) })

	controlResult := relayWorker(t, func() { _ = controlClient.Close() }, func() error {
		if err := tunnelv1.WriteControl(controlClient, tunnelv1.Message{
			Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version,
			Role: tunnelv1.Ingress, Credential: strings.Repeat("s", 32),
		}); err != nil {
			return err
		}
		_, err := tunnelv1.ReadControl(controlClient)
		return err
	})
	if err := relayAwait(t, controlResult); err != nil {
		t.Fatal(err)
	}

	headerResult := relayWorker(t, func() { _ = forwardClient.Close() }, func() error {
		_, err := tunnelv1.WriteServiceOpening(forwardClient, privateLifecycleHeader())
		return err
	})
	if err := relayAwait(t, headerResult); err != nil {
		t.Fatal(err)
	}
	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("forwarding rejection did not start")
	}

	if !cancelRejection {
		response, err := tunnelv1.ReadReturnFrame(forwardClient)
		if err != nil || response.Kind != tunnelv1.ReturnRejected || response.Code != tunnelv1.StaleConnectionAssignment {
			t.Fatalf("rejection response=%+v err=%v", response, err)
		}
		relayAwait(t, observer.done)
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("forwarding acceptor did not close its session before waiting for active streams")
	}
	assertRelayOperation(t, metrics, "RelayOpenVisitorStream", "success", 0)
	if cancelRejection {
		assertRelayOperation(t, metrics, "RelayOpenVisitorStream", "canceled", 1)
	} else {
		assertRelayOperation(t, metrics, "RelayOpenVisitorStream", "rejected", 1)
		assertRelayOperation(t, metrics, "RelayOpenVisitorStream", "error", 0)
	}
}

type forwardingMetricObserver struct {
	*observability.Metrics
	done chan struct{}
}

func (o *forwardingMetricObserver) ObserveOperationContext(ctx context.Context, operation observability.ServerOperation, err error, elapsed time.Duration) {
	o.Metrics.ObserveOperationContext(ctx, operation, err, elapsed)
	close(o.done)
}

type forwardingTestSession struct {
	incoming chan muxsession.Stream
	done     chan struct{}
	streams  []muxsession.Stream
	once     sync.Once
}

func newForwardingTestSession(streams ...muxsession.Stream) *forwardingTestSession {
	incoming := make(chan muxsession.Stream, len(streams))
	for _, stream := range streams {
		incoming <- stream
	}
	return &forwardingTestSession{incoming: incoming, done: make(chan struct{}), streams: streams}
}

func (s *forwardingTestSession) OpenStream(context.Context) (muxsession.Stream, error) {
	return nil, errors.ErrUnsupported
}

func (s *forwardingTestSession) AcceptStream(ctx context.Context) (muxsession.Stream, error) {
	select {
	case stream := <-s.incoming:
		return stream, nil
	case <-s.done:
		return nil, muxsession.ErrClosed
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
}

func (s *forwardingTestSession) Close() error {
	s.once.Do(func() {
		close(s.done)
		for _, stream := range s.streams {
			_ = stream.Close()
		}
	})
	return nil
}

func (s *forwardingTestSession) Done() <-chan struct{} { return s.done }

func (s *forwardingTestSession) Err() error {
	select {
	case <-s.done:
		return muxsession.ErrClosed
	default:
		return nil
	}
}

type forwardingTestStream struct {
	net.Conn
	writeStarted chan struct{}
	once         sync.Once
}

func (s *forwardingTestStream) Write(data []byte) (int, error) {
	if s.writeStarted != nil {
		s.once.Do(func() { close(s.writeStarted) })
	}
	return s.Conn.Write(data)
}

func (s *forwardingTestStream) CloseWrite() error { return errors.ErrUnsupported }

func (s *forwardingTestStream) Reset(uint32) error { return s.Close() }
