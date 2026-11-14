package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/testutil/transporttest"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type publicConnectorPublisherControl struct {
	ref          tunnelv1.PublisherConnectionRef
	lease        relayv1.RelayLease
	registry     *Registry
	ready        chan *PublisherConnection
	disconnected chan error
	packets      bool
}

func (c *publicConnectorPublisherControl) ClaimPublisherConnection(_ context.Context, ref tunnelv1.PublisherConnectionRef, id, credential string) (relayv1.ClaimedPublisherConnection, error) {
	if ref != c.ref || id == "" || credential != "assigned-public-publisher" {
		return relayv1.ClaimedPublisherConnection{}, errors.New("unexpected publisher claim")
	}
	return relayv1.ClaimedPublisherConnection{PublicUrlId: ref.PublicURLID, PublishRunId: ref.PublishRunID, PublishRunNumber: int64(ref.PublishRunNumber),
		PublisherConnectionId: ref.PublisherConnectionID, ConnectionSlot: int(ref.ConnectionSlot),
		ConnectionAssignmentRevision: int64(ref.ConnectionAssignmentRevision), RelayServiceId: ref.RelayServiceID,
		RelayId: c.lease.RelayId, RelayRunId: c.lease.RelayRunId, RelayLeaseRevision: c.lease.RelayLeaseRevision}, nil
}

func (c *publicConnectorPublisherControl) MarkPublisherConnectionReady(_ context.Context, claim relayv1.ClaimedPublisherConnection) (relayv1.ClaimedPublisherConnection, error) {
	c.registry.mu.Lock()
	connection := c.registry.connections[claim.PublisherConnectionId]
	c.registry.mu.Unlock()
	if connection == nil || (connection.packets != nil) != c.packets {
		return claim, errors.New("public publisher readiness has unexpected packet ownership")
	}
	c.ready <- connection
	return claim, nil
}

func (c *publicConnectorPublisherControl) DisconnectPublisherConnection(_ context.Context, claim relayv1.ClaimedPublisherConnection, _ bool) (relayv1.ClaimedPublisherConnection, error) {
	c.registry.mu.Lock()
	remaining := c.registry.connections[claim.PublisherConnectionId]
	c.registry.mu.Unlock()
	var err error
	if remaining != nil {
		err = errors.New("public publisher disconnected before local retirement")
	}
	c.disconnected <- err
	return claim, err
}

func TestPublicURLPublisherAcceptorOwnsConnectorPackets(t *testing.T) {
	for _, test := range []struct {
		name      string
		transport tunnel.Transport
		packets   bool
	}{
		{"quic packets", tunnel.TransportQUIC, true},
		{"quic ingress only", tunnel.TransportQUIC, false},
		{"tls yamux packets", tunnel.TransportTLSTCP, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			receiver := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			t.Cleanup(receiver.Close)
			serverTLS := receiver.TLS.Clone()
			roots := x509.NewCertPool()
			roots.AddCert(receiver.Certificate())
			clientTLS := &tls.Config{RootCAs: roots}
			registry := NewRegistry()
			t.Cleanup(func() { _ = registry.Close() })
			lease := relayv1.RelayLease{RelayServiceId: "relay-a", RelayId: "relay-process", RelayRunId: "run-a",
				RelayLeaseRevision: 1, LeaseExpiresAt: time.Now().Add(time.Minute)}
			ref := tunnelv1.PublisherConnectionRef{PublicURLID: "url_1234567890123456789012", PublishRunID: "pr_1234567890123456789012",
				PublishRunNumber: 2, PublisherConnectionID: "pc_1234567890123456789012", ConnectionAssignmentRevision: 1, RelayServiceID: lease.RelayServiceId}
			control := &publicConnectorPublisherControl{ref: ref, lease: lease, registry: registry,
				ready: make(chan *PublisherConnection, 1), disconnected: make(chan error, 1), packets: test.packets}
			connector := &ConnectorAcceptor{PublicPublishers: registry}
			acceptor, err := NewPublisherAcceptor(PublisherAcceptorConfig{Control: control, Registry: registry,
				Connector: func(id string) (*ConnectorAcceptor, bool) { return connector, id == lease.RelayServiceId }})
			if err != nil {
				t.Fatal(err)
			}
			completed := make(chan error, 1)
			address := traceMuxServer(t, t.Context(), test.transport, serverTLS, func(ctx context.Context, outer muxsession.Session) error {
				err := acceptor.Accept(ctx, outer)
				completed <- err
				return err
			})
			var dialer muxsession.Connector = muxsession.TLSYamuxConnector{TLSConfig: clientTLS}
			if test.transport == tunnel.TransportQUIC {
				dialer = muxsession.QUICConnector{TLSConfig: clientTLS, Dialer: transporttest.QUICTransport(t),
					Config: muxsession.QUICConfig{Config: &quic.Config{EnableDatagrams: test.packets}}}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			outer, err := dialer.Connect(ctx, muxsession.Endpoint{Address: address, ServerName: "127.0.0.1"})
			if err != nil {
				t.Fatal(err)
			}
			defer outer.Close()
			publisher, err := tunnel.Dial(ctx, outer, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version,
				Role: tunnelv1.Publisher, Credential: "assigned-public-publisher", PublisherConnection: &ref})
			if err != nil {
				t.Fatal(err)
			}
			defer publisher.Close()
			var connection *PublisherConnection
			select {
			case connection = <-control.ready:
			case err := <-completed:
				t.Fatal("public publisher admission ended before readiness", err)
			case <-ctx.Done():
				t.Fatal("public publisher admission did not reach readiness", context.Cause(ctx))
			}
			packets, current := connector.publisherPackets(connectorClaim{public: ref}, lease)
			if current != test.packets || packets != connection.packets {
				t.Fatal("connector packet selection did not match negotiated transport")
			}
			delivered := relayWorker(t, func() { _ = publisher.Close() }, func() error {
				incoming, err := publisher.AcceptVisitorStream(ctx)
				if err != nil {
					return err
				}
				defer incoming.Stream.Close()
				if incoming.Header.PublicURLID != ref.PublicURLID || incoming.Header.PublishRunID != ref.PublishRunID {
					return errors.New("ingress stream lost its public URL publication")
				}
				if err := incoming.Accept(); err != nil {
					return err
				}
				var payload [7]byte
				if _, err := io.ReadFull(incoming.Stream, payload[:]); err != nil {
					return err
				}
				if string(payload[:]) != "ingress" {
					return errors.New("ingress payload changed")
				}
				return nil
			})
			stream, err := connection.OpenVisitor(ctx, "vc_1234567890123456789012", false, true, []byte("ingress"), tunnel.ReturnEvents{})
			if err != nil {
				t.Fatal("public publisher could not carry ingress beside packet ownership", err)
			}
			_ = stream.Close()
			if err := relayAwait(t, delivered); err != nil {
				t.Fatal("public publisher lost ingress traffic", err)
			}
			_ = publisher.Close()
			if err := relayAwait(t, control.disconnected); err != nil {
				t.Fatal(err)
			}
			if connection.packets != nil {
				select {
				case <-connection.packets.Done():
				default:
					t.Fatal("publisher disconnect returned before its packet owner joined")
				}
			}
			if connections, streams := registry.Load(); connections != 0 || streams != 0 {
				t.Fatal("retired public publisher retained local resources")
			}
		})
	}
}

func newPublicURLConnectorBindingFixture(t *testing.T) (*connectorBindingFixture, *PublisherConnection, *Registry) {
	t.Helper()
	f := newConnectorBindingFixture(t)
	f.proof.ServiceID, f.proof.ServiceRunID, f.proof.RunNumber = "", "", 0
	f.proof.PublicURLID, f.proof.PublishRunID, f.proof.PublishRunNumber = "url_1234567890123456789012", "pr_1234567890123456789012", 3
	proof := f.proof
	ref := tunnelv1.PublisherConnectionRef{PublicURLID: proof.PublicURLID, PublishRunID: proof.PublishRunID, PublishRunNumber: uint64(proof.PublishRunNumber),
		PublisherConnectionID: proof.PublisherConnectionID, ConnectionSlot: uint8(proof.ConnectionSlot),
		ConnectionAssignmentRevision: uint64(proof.AssignmentRevision), RelayServiceID: proof.RelayServiceID}
	_, session := privateRelayPair(t, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version,
		Role: tunnelv1.Publisher, Credential: "public-url-publisher", PublisherConnection: &ref})
	connection, err := NewPublisherConnection(ref, relayv1.ClaimedPublisherConnection{
		PublicUrlId: ref.PublicURLID, PublishRunId: ref.PublishRunID, PublishRunNumber: int64(ref.PublishRunNumber),
		PublisherConnectionId: ref.PublisherConnectionID, ConnectionSlot: int(ref.ConnectionSlot),
		ConnectionAssignmentRevision: int64(ref.ConnectionAssignmentRevision), RelayServiceId: ref.RelayServiceID,
		RelayId: proof.RelayID, RelayRunId: proof.RelayRunID, RelayLeaseRevision: int64(proof.RelayLeaseRevision),
	}, session)
	if err != nil {
		t.Fatal(err)
	}
	connection.packets = f.publisher
	registry := NewRegistry()
	if err := registry.Insert(connection); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	f.acceptor.PublicPublishers = registry
	// retain the same connection ID in the service fixture as a decoy. public
	// selection must never fall back to it when the public assignment is stale.
	return f, connection, registry
}

func TestPublicURLConnectorRelaySelectionKeepsExactFamilyAndAssignment(t *testing.T) {
	f, connection, registry := newPublicURLConnectorBindingFixture(t)
	d, _ := f.candidate(t, 1, "192.0.2.1:12345")
	lease := f.acceptor.CurrentLease()
	if d.claim.ref != (tunnelv1.ServicePublisherConnectionRef{}) || d.claim.public != connection.ref {
		t.Fatal("public URL control reply became a service publisher reference")
	}
	if packets, current := f.acceptor.publisherPackets(d.claim, lease); !current || packets != f.publisher {
		t.Fatal("exact public URL publisher was not selected")
	}
	for name, edit := range map[string]func(*connectorClaim){
		"public URL":    func(c *connectorClaim) { c.public.PublicURLID = "url_abcdefghijklmnopqrstuv" },
		"publish run":   func(c *connectorClaim) { c.public.PublishRunID = "pr_abcdefghijklmnopqrstuv" },
		"run number":    func(c *connectorClaim) { c.public.PublishRunNumber++ },
		"connection":    func(c *connectorClaim) { c.public.PublisherConnectionID = "pc_abcdefghijklmnopqrstuv" },
		"slot":          func(c *connectorClaim) { c.public.ConnectionSlot = 1 },
		"assignment":    func(c *connectorClaim) { c.public.ConnectionAssignmentRevision++ },
		"relay service": func(c *connectorClaim) { c.public.RelayServiceID = "other-relay" },
		"mixed family":  func(c *connectorClaim) { c.ref = f.connection.ref },
	} {
		t.Run(name, func(t *testing.T) {
			changed := d.claim
			edit(&changed)
			if packets, current := f.acceptor.publisherPackets(changed, lease); current || packets != nil {
				t.Fatal("changed publication selected a publisher")
			}
		})
	}
	for name, edit := range map[string]func(*relayv1.RelayLease){
		"process":  func(l *relayv1.RelayLease) { l.RelayRunId = "restarted" },
		"lease":    func(l *relayv1.RelayLease) { l.RelayLeaseRevision++ },
		"relay":    func(l *relayv1.RelayLease) { l.RelayId = "other" },
		"draining": func(l *relayv1.RelayLease) { l.Draining = true },
		"expired":  func(l *relayv1.RelayLease) { l.LeaseExpiresAt = time.Now() },
	} {
		t.Run(name, func(t *testing.T) {
			changed := lease
			edit(&changed)
			if packets, current := f.acceptor.publisherPackets(d.claim, changed); current || packets != nil {
				t.Fatal("changed relay claim selected a public URL publisher")
			}
		})
	}
	registry.mu.Lock()
	delete(registry.connections, connection.ref.PublisherConnectionID)
	registry.mu.Unlock()
	if packets, current := f.acceptor.publisherPackets(d.claim, lease); current || packets != nil {
		t.Fatal("missing public assignment fell back to the service registry")
	}
	// restore ownership so the fixture's registry cleanup joins its packet owner.
	registry.mu.Lock()
	registry.connections[connection.ref.PublisherConnectionID] = connection
	registry.mu.Unlock()
}

func TestPublicURLConnectorRelayBridgeReusesHandoffAndRebindLifecycle(t *testing.T) {
	f, _, _ := newPublicURLConnectorBindingFixture(t)
	first, _ := f.candidate(t, 1, "192.0.2.1:12345")
	old, err := f.activate(t, first, tunnelv1.ConnectorHandoffID{})
	if err != nil {
		t.Fatal(err)
	}
	if !first.admit(tunnelv1.PeerPacket{Kind: tunnelv1.PeerData}) {
		t.Fatal("active public URL binding did not admit delivery")
	}
	next, _ := f.candidate(t, 2, "192.0.2.2:12345")
	initial := tunnelv1.ConnectorHandoffID{9}
	binding, err := f.activate(t, next, initial)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-old.done:
	default:
		t.Fatal("public URL successor installed before predecessor joined")
	}
	if old == binding || old.publisher == binding.publisher || old.claim.key == binding.claim.key ||
		first.ctx.Err() == nil || next.admit(tunnelv1.PeerPacket{Kind: tunnelv1.PeerData}) {
		t.Fatal("public URL rebind inherited old delivery or active admission")
	}
	bound, registration := binding.until, binding.publisher
	next.cancel()
	binding.detach(next)
	retry, _ := f.candidate(t, 2, "192.0.2.2:12345")
	recovered, err := f.activate(t, retry, initial)
	if err != nil || recovered != binding || recovered.publisher != registration || recovered.until != bound {
		t.Fatal("uncertain public URL activation changed owner or extended authority", err)
	}
	late, _ := f.candidate(t, 1, "192.0.2.1:12345")
	if _, err := f.activate(t, late, tunnelv1.ConnectorHandoffID{}); err == nil {
		t.Fatal("late public URL generation revived an old bridge")
	}
}

func TestPublicURLConnectorRelayCapacityIsPerPublicationRun(t *testing.T) {
	f, _, _ := newPublicURLConnectorBindingFixture(t)
	var releases []func()
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	for index := range maxConnectorSessionsPerRun {
		proof := f.proof
		proof.PairID = fmt.Sprintf("cpp_%022d", index)
		release, err := f.acceptor.reserve(proof)
		if err != nil {
			t.Fatal("public URL run was limited before its share", err)
		}
		releases = append(releases, release)
	}
	extra := f.proof
	extra.PairID = "cpp_abcdefghijklmnopqrstuv"
	_, err := f.acceptor.reserve(extra)
	var capacity *tunnel.ProtocolError
	if !errors.As(err, &capacity) || capacity.Code != tunnelv1.CapacityExceeded {
		t.Fatal("one public URL run exceeded its relay share", err)
	}
	sibling := extra
	sibling.PublishRunID = "pr_abcdefghijklmnopqrstuv"
	release, err := f.acceptor.reserve(sibling)
	if err != nil {
		t.Fatal("different public URL runs shared the empty service-run capacity key", err)
	}
	release()
	service := extra
	service.PublicURLID, service.PublishRunID, service.PublishRunNumber = "", "", 0
	service.ServiceID, service.ServiceRunID, service.RunNumber = f.connection.ref.ServiceID, f.connection.ref.ServiceRunID, 1
	release, err = f.acceptor.reserve(service)
	if err != nil {
		t.Fatal("public URL capacity blocked a saved service run", err)
	}
	release()
	releases[0]()
	release, err = f.acceptor.reserve(extra)
	if err != nil {
		t.Fatal("released public URL capacity was not reusable", err)
	}
	release()
}

func TestPublicURLPublisherPacketOwnerJoinsBridgeOnDrainOrClose(t *testing.T) {
	for _, drain := range []bool{false, true} {
		t.Run(fmt.Sprintf("drain=%t", drain), func(t *testing.T) {
			f, connection, _ := newPublicURLConnectorBindingFixture(t)
			d, _ := f.candidate(t, 1, "192.0.2.1:12345")
			bridge, err := f.activate(t, d, tunnelv1.ConnectorHandoffID{})
			if err != nil {
				t.Fatal(err)
			}
			if drain {
				err = connection.Drain(t.Context())
			} else {
				err = connection.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-bridge.done:
			default:
				t.Fatal("public URL publisher cleanup returned before its bridge joined")
			}
			if packets, current := f.acceptor.publisherPackets(d.claim, f.acceptor.CurrentLease()); current || packets != nil {
				t.Fatal("drained public URL publisher still accepted connector delivery")
			}
		})
	}
}

func TestPublicURLPublisherRetirementFencesAdmissionBeforePacketJoin(t *testing.T) {
	for _, drain := range []bool{false, true} {
		t.Run(fmt.Sprintf("drain=%t", drain), func(t *testing.T) {
			f, connection, _ := newPublicURLConnectorBindingFixture(t)
			joined := make(chan struct{})
			release := sync.OnceFunc(func() { close(joined) })
			defer release()
			f.publisher.mu.Lock()
			f.publisher.bridges[[16]byte{99}] = &connectorBridge{done: joined}
			f.publisher.mu.Unlock()
			retired := relayWorker(t, release, func() error {
				if drain {
					return connection.Drain(t.Context())
				}
				return connection.Close()
			})
			relayAwait(t, f.publisher.Done())
			if err := connection.beginOpen(); !errors.Is(err, ErrDraining) {
				if err == nil {
					_, _ = connection.finishOpen(nil, errors.New("unexpected opening"))
				}
				t.Fatal("publisher admitted ingress while joining connector packets", err)
			}
			claim := connectorClaim{public: connection.ref}
			if _, current := f.acceptor.publisherPackets(claim, f.acceptor.CurrentLease()); current {
				t.Fatal("publisher admitted connector delivery while joining packets")
			}
			select {
			case err := <-retired:
				t.Fatal("publisher retirement returned before packet join", err)
			default:
			}
			release()
			if err := relayAwait(t, retired); err != nil {
				t.Fatal(err)
			}
		})
	}
}
