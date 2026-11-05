package daemon

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type connectorOuter struct {
	session muxsession.Session
	address string
	ready   <-chan struct{}
}
type recordedConnectorConnector struct {
	muxsession.Connector
	opened    chan connectorOuter
	blocked   atomic.Bool
	loseReply atomic.Int32
	lost      atomic.Int32
}

func (c *recordedConnectorConnector) Connect(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
	if c.blocked.Load() {
		return nil, &tunnel.ProtocolError{Code: tunnelv1.Unavailable}
	}
	session, err := c.Connector.Connect(ctx, endpoint)
	if err == nil {
		observed := &observedConnectorOuter{Session: session, ready: make(chan struct{}), loseReply: c.loseReply.Swap(0), lost: &c.lost}
		session = observed
		if datagrams, ok := observed.Session.(muxsession.DatagramSession); ok {
			session = &observedConnectorDatagrams{observedConnectorOuter: observed, DatagramSession: datagrams}
		}
		select {
		case c.opened <- connectorOuter{session, endpoint.Address, observed.ready}:
		case <-ctx.Done():
			_ = session.Close()
			return nil, context.Cause(ctx)
		}
	}
	return session, err
}

// observe a publisher probe reply on the replacement carrier, not just an outer
// handshake. the production receiver still authenticates the actual frame.
type observedConnectorOuter struct {
	muxsession.Session
	opened    atomic.Int32
	ready     chan struct{}
	once      sync.Once
	loseReply int32
	lost      *atomic.Int32
}

func (s *observedConnectorOuter) observe(wire []byte) {
	if len(wire) <= tunnelv1.PeerDeliveryHeaderBytes+tunnelv1.PeerDeliveryTagBytes {
		return
	}
	packet, err := tunnelv1.ParsePeerPacket(wire[tunnelv1.PeerDeliveryHeaderBytes : len(wire)-tunnelv1.PeerDeliveryTagBytes])
	if err == nil && packet.Kind == tunnelv1.PeerProbeReply && packet.Sender == 1 {
		s.once.Do(func() { close(s.ready) })
	}
}
func (s *observedConnectorOuter) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.OpenStream(ctx)
	if err == nil && s.opened.Add(1) > 1 {
		return &observedConnectorStream{Stream: stream, owner: s}, nil
	}
	if err == nil && s.loseReply != 0 {
		return &lostConnectorReply{Stream: stream, owner: s}, nil
	}
	return stream, err
}

type lostConnectorReply struct {
	muxsession.Stream
	owner   *observedConnectorOuter
	pending []byte
}

func (s *lostConnectorReply) Read(b []byte) (int, error) {
	n, err := s.Stream.Read(b)
	s.pending = append(s.pending, b[:n]...)
	for len(s.pending) >= 4 {
		size := int(binary.BigEndian.Uint32(s.pending[:4]))
		if size > tunnelv1.MaxControlBytes {
			return 0, io.ErrUnexpectedEOF
		}
		if len(s.pending) < 4+size {
			break
		}
		var message tunnelv1.Message
		decodeErr := json.Unmarshal(s.pending[4:4+size], &message)
		s.pending = s.pending[4+size:]
		if decodeErr == nil && (s.owner.loseReply == 1 && message.Type == tunnelv1.HelloAccepted || s.owner.loseReply == 2 && message.Type == tunnelv1.ConnectorLegActivated) {
			s.owner.lost.Add(1)
			_ = s.owner.Session.Close()
			return 0, io.ErrUnexpectedEOF
		}
	}
	return n, err
}

type observedConnectorDatagrams struct {
	*observedConnectorOuter
	muxsession.DatagramSession
}

func (s *observedConnectorDatagrams) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	b, err := s.DatagramSession.ReceiveDatagram(ctx)
	if err == nil {
		s.observe(b)
	}
	return b, err
}

type observedConnectorStream struct {
	muxsession.Stream
	owner   *observedConnectorOuter
	pending []byte
}

func (s *observedConnectorStream) Read(b []byte) (int, error) {
	n, err := s.Stream.Read(b)
	s.pending = append(s.pending, b[:n]...)
	for len(s.pending) >= 2 {
		size := int(binary.BigEndian.Uint16(s.pending[:2]))
		if size > tunnelv1.MaxPeerDeliveryBytes {
			s.pending = nil
			break
		}
		if len(s.pending) < 2+size {
			break
		}
		s.owner.observe(s.pending[2 : 2+size])
		s.pending = s.pending[2+size:]
	}
	return n, err
}

func TestIntegrationConnectorCarrierSwitchRetainsApplicationAndTarget(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, standalone := range []bool{false, true} {
		for _, tcp := range []bool{false, true} {
			for _, lostReply := range []int32{0, 1, 2} {
				if standalone && lostReply != 0 {
					continue
				}
				t.Run(fmt.Sprintf("standalone=%t/tcp=%t/lost-reply=%d", standalone, tcp, lostReply), func(t *testing.T) {
					f := newServiceRuntimeFixture(t, standalone, nil)
					f.publisherTCPOnly = tcp
					target := startPrivateEchoTarget(t)
					key, _ := opaqueid.New(opaqueid.IdempotencyPrefix)
					service, err := f.identity.routes.CreateService(t.Context(), f.identity.teamID, "native", key)
					if err != nil {
						t.Fatal(err)
					}
					startPrivateHTTPPublisher(t, f, service, target.address)
					person, err := f.identity.authority.IdentityContext(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					control, err := connectorstream.NewControl(f.identity.routes, f.identity.state, person.Identity.Id)
					if err != nil {
						t.Fatal(err)
					}
					quic, tls := f.connectors()
					selected := quic
					if tcp {
						selected = tls
					}
					recorded := &recordedConnectorConnector{Connector: selected, opened: make(chan connectorOuter, 8)}
					config := connectorstream.Config{Control: control, IdentityID: person.Identity.Id, RelayQUIC: recorded, RelayTCP: privateDisabledConnector()}
					if tcp {
						config.RelayQUIC, config.RelayTCP = privateDisabledConnector(), recorded
					}
					listener, stopConnector := startRuntimeConnector(t, f, service, config)
					defer stopConnector()
					var carriers [2]connectorOuter
					for i := range carriers {
						select {
						case carriers[i] = <-recorded.opened:
						case <-time.After(time.Second):
							t.Fatal("readiness omitted a carrier")
						}
					}
					var firstAddress string
					if err := f.inspect.QueryRowContext(t.Context(), `SELECT slots->0->>'relay_address' FROM control.connector_peer_pairs WHERE service_id=$1`, service.Id).Scan(&firstAddress); err != nil {
						t.Fatal(err)
					}
					connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
					if err != nil {
						t.Fatal(err)
					}
					defer connection.Close()
					exchange := func(message string) {
						t.Helper()
						_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
						if _, err := io.WriteString(connection, message); err != nil {
							t.Fatal(err)
						}
						got := make([]byte, len(message))
						if _, err := io.ReadFull(connection, got); err != nil || string(got) != message {
							t.Fatal("carrier switch interrupted application", err)
						}
					}
					exchange("before-switch\n")
					recorded.loseReply.Store(lostReply)
					closed := false
					for _, carrier := range carriers {
						if carrier.address == firstAddress {
							_ = carrier.session.Close()
							closed = true
							break
						}
					}
					if !closed {
						t.Fatal("active relay carrier was not found")
					}
					exchange("after-switch\n")
					deadline := time.NewTimer(8 * time.Second)
					defer deadline.Stop()
					for {
						var repaired connectorOuter
						select {
						case repaired = <-recorded.opened:
						case <-deadline.C:
							t.Fatal("lost leg did not reconnect")
						}
						if repaired.address != firstAddress {
							t.Fatal("replaced healthy sibling")
						}
						ready := false
						select {
						case <-repaired.ready:
							ready = true
						case <-repaired.session.Done():
						case <-deadline.C:
							t.Fatal("repaired leg did not prove a publisher round trip")
						}
						if ready {
							break
						}
					}
					if lostReply != 0 && recorded.lost.Load() != 1 {
						t.Fatal("did not lose the committed reply")
					}
					// prevent a second repair from hiding failure of the first one.
					recorded.blocked.Store(true)
					for _, carrier := range carriers {
						if carrier.address != firstAddress {
							_ = carrier.session.Close()
						}
					}
					exchange("after-sibling-loss\n")
					target.mu.Lock()
					defer target.mu.Unlock()
					if target.received["before-switch\n"] != 1 || target.received["after-switch\n"] != 1 || target.received["after-sibling-loss\n"] != 1 || target.receivedOn["before-switch\n"] != target.receivedOn["after-switch\n"] || target.receivedOn["before-switch\n"] != target.receivedOn["after-sibling-loss\n"] {
						t.Fatal("switch reopened target or replayed bytes")
					}
				})
			}
		}
	}
}

// revocation can reach either the control worker or the publisher first.
// neither transport failure nor an arbitrary protocol error is an expected stop.
func revokedConnectorOwnerStop(err error) bool {
	var rejected *tunnel.ProtocolError
	return defaultConnectorRevocationDenied(err) || errors.Is(err, connectorstream.ErrServiceConnection) ||
		errors.As(err, &rejected) && rejected != nil && rejected.Code == tunnelv1.Unauthenticated
}

func TestRevokedConnectorOwnerStopClassification(t *testing.T) {
	for _, test := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{fmt.Errorf("control: %w", clientcontrol.ErrNotFound), true},
		{fmt.Errorf("owner: %w", connectorstream.ErrServiceConnection), true},
		{fmt.Errorf("publisher: %w", &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}), true},
		{context.DeadlineExceeded, false},
		{io.ErrUnexpectedEOF, false},
		{&tunnel.ProtocolError{Code: tunnelv1.Unavailable}, false},
	} {
		if got := revokedConnectorOwnerStop(test.err); got != test.want {
			t.Fatalf("revoked owner stop %v = %t, want %t", test.err, got, test.want)
		}
	}
}

func startRuntimeConnector(t *testing.T, f *privateSeparatedFixture, service controlv1.Service, config connectorstream.Config, expectedStop ...func(error) bool) (net.Listener, func()) {
	t.Helper()
	listener := serviceRuntimeListener(t)
	ctx, cancel := context.WithCancel(t.Context())
	ready, done := make(chan struct{}), make(chan error, 1)
	config.ServiceID, config.Protocol, config.TrustRevision, config.Endpoint = service.Id, string(service.Protocol), service.TrustRevision, service.Endpoint
	config.ServiceTLS, config.TransportTLS = f.visitorRoots, f.roots
	config.Ready = func() error { close(ready); return nil }
	go func() { done <- connectorstream.Serve(ctx, listener, config) }()
	// callers defer this join before testing cancels their publishers' contexts.
	// cleanup remains a fallback for a failed startup, not the lifetime owner.
	stop := sync.OnceFunc(func() {
		cancel()
		select {
		case err := <-done:
			expected := false
			for _, allowed := range expectedStop {
				expected = expected || allowed(err)
			}
			if err != nil && !expected {
				t.Errorf("connector cleanup: %v", err)
			}
		case <-time.After(8 * time.Second):
			t.Error("connector did not join")
		}
	})
	t.Cleanup(stop)
	select {
	case <-ready:
	case err := <-done:
		done <- err
		t.Fatal("connector startup", err)
	case <-time.After(35 * time.Second):
		t.Fatal("connector never became ready")
	}
	return listener, stop
}
