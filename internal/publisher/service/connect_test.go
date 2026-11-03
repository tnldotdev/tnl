package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestPrivateConnectOptionsKeepRelayTrustSeparate(t *testing.T) {
	_, roots := privateTransportTLS(t)
	roots.MinVersion = tls.VersionTLS12
	options, err := (RunConfig{TransportTLS: roots}).connectionOptions()
	if err != nil {
		t.Fatal(err)
	}
	udp := options.QUIC.(muxsession.QUICConnector)
	tcp := options.TCP.(muxsession.TLSYamuxConnector)
	if udp.TLSConfig == roots || udp.TLSConfig != tcp.TLSConfig || udp.TLSConfig.RootCAs != roots.RootCAs ||
		udp.TLSConfig.MinVersion < tls.VersionTLS13 || roots.MinVersion != tls.VersionTLS12 ||
		udp.TLSConfig.InsecureSkipVerify || !udp.Config.Config.EnableDatagrams || options.PreferTCP {
		t.Fatal("relay composition changed trust, mutated caller TLS, or disabled peer datagrams")
	}
	defaults, err := (RunConfig{}).connectionOptions()
	if err != nil || defaults.QUIC.(muxsession.QUICConnector).TLSConfig.RootCAs != nil ||
		defaults.TCP.(muxsession.TLSYamuxConnector).TLSConfig.MinVersion < tls.VersionTLS13 {
		t.Fatal("default relay connectors did not retain system roots and TLS 1.3", err)
	}
	config, control := lifecycleFixture(t)
	config.TransportTLS = &tls.Config{InsecureSkipVerify: true}
	if err := Publish(t.Context(), config); !errors.Is(err, ErrPrivateStream) || control.prepares != 0 {
		t.Fatal("insecure relay trust reached run preparation", err)
	}
}

func TestPrivateConnectSlotPreferenceAndFallback(t *testing.T) {
	for _, test := range []struct {
		name      string
		preferTCP bool
		failFirst bool
		datagrams bool
		want      tunnel.Transport
	}{
		{"quic-first", false, false, true, tunnel.TransportQUIC},
		{"tcp-first", true, false, true, tunnel.TransportTLSTCP},
		{"quic-failure", false, true, true, tunnel.TransportTLSTCP},
		{"tcp-failure", true, true, true, tunnel.TransportQUIC},
		{"quic-without-datagrams", false, false, false, tunnel.TransportTLSTCP},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, bound, _, _ := privateFixture(t, "127.0.0.1:1")
			relay := newPrivateSlotRelay(t, bound, test.datagrams, nil)
			options := relay.options(t, relay.roots)
			options.PreferTCP = test.preferTCP
			if test.failFirst {
				failed := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
					return nil, net.ErrClosed
				})
				if test.preferTCP {
					options.TCP = failed
				} else {
					options.QUIC = failed
				}
			}
			claimed, err := bound.ConnectSlot(t.Context(), 0, options)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = claimed.Close() })
			if claimed.Transport() != test.want || bound.packetSlots[0] != claimed || claimed.dispatcher == nil || claimed.packets == nil {
				t.Fatal("wrong transport or missing dispatcher/packet owner", claimed.Transport())
			}
			if !test.datagrams {
				awaitPrivateSlot(t, relay.closed[0])
				if relay.hellos[0].Load() != 0 {
					t.Fatal("QUIC without negotiated datagrams consumed a single-use hello")
				}
			} else if !test.failFirst {
				loser := 1
				if test.preferTCP {
					loser = 0
				}
				if relay.calls[loser].Load() != 0 {
					t.Fatal("fallback started before the preferred transport was accepted")
				}
			}
			_ = claimed.Close()
			if bound.packetSlots[0] != nil {
				t.Fatal("closed claim retained its packet slot")
			}
			awaitPrivateSlot(t, claimed.packets.Done())
			winner := 0
			if test.want == tunnel.TransportTLSTCP {
				winner = 1
			}
			awaitPrivateSlot(t, relay.closed[winner])
		})
	}
}

func TestPrivateConnectSlotRejectsUnverifiedRelayTLS(t *testing.T) {
	for _, name := range []string{"untrusted-ca", "wrong-hostname"} {
		t.Run(name, func(t *testing.T) {
			_, bound, _, _ := privateFixture(t, "127.0.0.1:1")
			relay := newPrivateSlotRelay(t, bound, true, nil)
			roots := relay.roots
			if name == "untrusted-ca" {
				roots = &tls.Config{RootCAs: x509.NewCertPool()}
			} else {
				bound.connections[0].TlsServerName = "wrong.relay.test"
			}
			claimed, err := bound.ConnectSlot(t.Context(), 0, relay.options(t, roots))
			var invalid *tls.CertificateVerificationError
			if claimed != nil || !errors.As(err, &invalid) || bound.packetSlots[0] != nil {
				t.Fatal("unverified relay was claimed or lost its TLS cause", err)
			}
			if relay.hellos[0].Load() != 0 || relay.hellos[1].Load() != 0 {
				t.Fatal("unverified TLS sent publisher credentials")
			}
		})
	}
}

func TestPrivateConnectSlotRequiresExplicitTransports(t *testing.T) {
	_, bound, _, _ := privateFixture(t, "127.0.0.1:1")
	unused := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
		t.Error("incomplete options started a transport")
		return nil, net.ErrClosed
	})
	for _, options := range []ConnectOptions{{}, {QUIC: unused}, {TCP: unused}} {
		if claimed, err := bound.ConnectSlot(t.Context(), 0, options); claimed != nil || !errors.Is(err, ErrPrivateStream) {
			t.Fatal("incomplete options supplied an implicit transport", err)
		}
	}
}

func TestPrivateConnectSlotOwnsOneDispatcherAndJoinsOnClose(t *testing.T) {
	_, bound, _, _ := privateFixture(t, "127.0.0.1:1")
	relay := newPrivateSlotRelay(t, bound, true, nil)
	options := relay.options(t, relay.roots)
	options.PreferTCP = true
	tcp := options.TCP
	var tracked *privateSlotAccepts
	options.TCP = muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
		outer, err := tcp.Connect(ctx, endpoint)
		if err != nil {
			return nil, err
		}
		tracked = &privateSlotAccepts{Session: outer, started: make(chan struct{})}
		return tracked, nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	claimed, err := bound.ConnectSlot(ctx, 0, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = claimed.Close() })
	served := make(chan struct{})
	go func() { defer close(served); _ = claimed.Serve(ctx) }()
	awaitPrivateSlot(t, tracked.started)
	if tracked.calls.Load() != 1 || tracked.active.Load() != 1 {
		t.Fatal("packet owner and forwarding server competed with the dispatcher")
	}
	_ = claimed.Close()
	if tracked.active.Load() != 0 || bound.packetSlots[0] != nil {
		t.Fatal("claim close returned before the dispatcher joined or retained its packet slot")
	}
	awaitPrivateSlot(t, claimed.packets.Done())
	awaitPrivateSlot(t, served)
}

type privateSlotAccepts struct {
	muxsession.Session
	started chan struct{}
	calls   atomic.Int32
	active  atomic.Int32
}

func (s *privateSlotAccepts) AcceptStream(ctx context.Context) (muxsession.Stream, error) {
	s.active.Add(1)
	defer s.active.Add(-1)
	if s.calls.Add(1) == 1 {
		close(s.started)
	}
	return s.Session.AcceptStream(ctx)
}

func TestPrivateConnectSlotWaitsForClaimAndClosesLosingTransport(t *testing.T) {
	_, bound, _, _ := privateFixture(t, "127.0.0.1:1")
	quicHello := make(chan struct{})
	relay := newPrivateSlotRelay(t, bound, true, func(ctx context.Context, transport tunnel.Transport, outer muxsession.Session) error {
		if transport == tunnel.TransportQUIC {
			close(quicHello)
			select {
			case <-outer.Done():
				return muxsession.ErrClosed
			case <-ctx.Done():
				return context.Cause(ctx)
			}
		}
		select {
		case <-quicHello:
			return nil
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	})
	claimed, err := bound.ConnectSlot(t.Context(), 0, relay.options(t, relay.roots))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = claimed.Close() })
	if claimed.Transport() != tunnel.TransportTLSTCP {
		t.Fatal("TLS handshake won before hello acceptance", claimed.Transport())
	}
	awaitPrivateSlot(t, relay.closed[0])
}

func TestPrivateConnectSlotRejectsAssignmentChangedDuringHello(t *testing.T) {
	for _, invalidate := range []bool{false, true} {
		t.Run(map[bool]string{false: "replaced", true: "closed"}[invalidate], func(t *testing.T) {
			_, bound, _, _ := privateFixture(t, "127.0.0.1:1")
			relay := newPrivateSlotRelay(t, bound, true, func(context.Context, tunnel.Transport, muxsession.Session) error {
				if invalidate {
					bound.Invalidate()
					return nil
				}
				next := bound.connections
				next[0].PublisherConnectionId, _ = opaqueid.New(opaqueid.PublisherConnectionPrefix)
				next[0].ConnectionAssignmentRevision++
				return bound.ApplyHeartbeat(controlv1.ServiceRunState{ServiceId: bound.prepared.Preparation.ServiceId, ServiceRunId: bound.prepared.Preparation.ServiceRunId,
					RunNumber: bound.prepared.Preparation.RunNumber, State: "ready", PublisherExpiresAt: time.Now().Add(time.Minute), PublisherConnections: next[:]})
			})
			options := relay.options(t, relay.roots)
			// only the gated hello may replace this assignment in this proof.
			options.TCP = muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
				return nil, net.ErrClosed
			})
			claimed, err := bound.ConnectSlot(t.Context(), 0, options)
			if claimed != nil || !errors.Is(err, ErrPrivateStream) || bound.packetSlots[0] != nil {
				t.Fatal("stale accepted hello installed a dispatcher/packet slot", err)
			}
			awaitPrivateSlot(t, relay.closed[0])
		})
	}
}

type privateSlotRelay struct {
	address string
	roots   *tls.Config
	calls   [2]atomic.Int32
	hellos  [2]atomic.Int32
	closed  [2]chan struct{}
}

// both transports redirect only the dial address; the assigned server name and
// normal TLS verification stay intact, as in the real topology fixtures.
func (r *privateSlotRelay) options(t *testing.T, roots *tls.Config) ConnectOptions {
	t.Helper()
	options, err := (RunConfig{TransportTLS: roots}).connectionOptions()
	if err != nil {
		t.Fatal(err)
	}
	redirect := func(slot int, connector muxsession.Connector) muxsession.Connector {
		return muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
			r.calls[slot].Add(1)
			if endpoint.Address != "assigned.relay.test:443" {
				return nil, ErrPrivateStream
			}
			endpoint.Address = r.address
			return connector.Connect(ctx, endpoint)
		})
	}
	options.QUIC, options.TCP = redirect(0, options.QUIC), redirect(1, options.TCP)
	return options
}

func newPrivateSlotRelay(t *testing.T, bound *Bound, datagrams bool, authenticate func(context.Context, tunnel.Transport, muxsession.Session) error) *privateSlotRelay {
	t.Helper()
	serverTLS, roots := privateTransportTLS(t)
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcp.Close() })
	udp, err := muxsession.ListenQUIC(tcp.Addr().String(), serverTLS, muxsession.QUICConfig{Config: &quic.Config{EnableDatagrams: datagrams}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	r := &privateSlotRelay{address: tcp.Addr().String(), roots: roots, closed: [2]chan struct{}{make(chan struct{}), make(chan struct{})}}
	bound.connections[0].RelayAddress, bound.connections[0].TlsServerName = "assigned.relay.test:443", "relay.test"
	ref, credential := bound.prepared.connectionRef(bound.connections[0]), bound.connections[0].PublisherConnectionCredential
	ctx, cancel := context.WithCancel(t.Context())
	var workers sync.WaitGroup
	for slot := range 2 {
		workers.Go(func() {
			defer close(r.closed[slot])
			var outer muxsession.Session
			var err error
			transport := tunnel.TransportQUIC
			if slot == 0 {
				outer, err = udp.Accept(ctx)
			} else {
				transport = tunnel.TransportTLSTCP
				var network net.Conn
				network, err = tcp.Accept()
				if err == nil {
					outer, err = muxsession.AcceptTLSYamux(ctx, network, serverTLS, muxsession.TLSYamuxConfig{})
				}
			}
			if err != nil {
				return
			}
			defer outer.Close()
			if state := outer.(muxsession.AcceptedPeer).TLSConnectionState(); state.Version < tls.VersionTLS13 {
				t.Error("relay transport negotiated TLS below 1.3")
			}
			session, _, err := tunnel.Accept(ctx, outer, func(ctx context.Context, hello tunnelv1.Message) error {
				r.hellos[slot].Add(1)
				if hello.ServiceConnection == nil || *hello.ServiceConnection != ref || hello.Credential != credential {
					return ErrPrivateStream
				}
				if authenticate != nil {
					return authenticate(ctx, transport, outer)
				}
				return nil
			})
			if err != nil {
				return
			}
			defer session.Close()
			select {
			case <-outer.Done():
			case <-ctx.Done():
			}
		})
	}
	t.Cleanup(func() {
		cancel()
		_ = tcp.Close()
		_ = udp.Close()
		workers.Wait()
	})
	return r
}

func awaitPrivateSlot(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("publisher transport did not close and join")
	}
}
