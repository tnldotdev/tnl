package ingress

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/relay"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type admissionTransportFixture struct {
	forwarder       *Forwarder
	publisher       *tunnel.Session
	wire            muxsession.Session
	relay           ingressv1.ServiceRelay
	header          tunnelv1.ServiceForwardingHeader
	server          *forwardingTestServer
	publisherServer *forwardingTestServer
	lease           atomic.Pointer[relayv1.RelayLease]
	released        chan struct{}
}

type admissionRelayControl struct {
	relay.ControlClient
	lease relayv1.RelayLease
	ref   tunnelv1.ServicePublisherConnectionRef
}

func (c admissionRelayControl) RegisterRelay(context.Context, relayv1.RelayRegistration) (relayv1.RelayLease, error) {
	return c.lease, nil
}

func (c admissionRelayControl) ClaimServicePublisherConnection(_ context.Context, id string, request relayv1.ServicePublisherConnectionClaim) (relayv1.ServicePublisherConnection, error) {
	if id != c.ref.PublisherConnectionID || request.ServiceId != c.ref.ServiceID || request.ServiceRunId != c.ref.ServiceRunID ||
		request.RunNumber != int64(c.ref.RunNumber) || request.ConnectionAssignmentRevision != int64(c.ref.ConnectionAssignmentRevision) ||
		request.Credential != "publisher-secret" || request.ObservedSourceIp != "127.0.0.1" ||
		request.RelayId != c.lease.RelayId || request.RelayRunId != c.lease.RelayRunId || request.RelayLeaseRevision != c.lease.RelayLeaseRevision {
		return relayv1.ServicePublisherConnection{}, errors.New("publisher claim changed its accepted source or assignment")
	}
	return c.connection(), nil
}

func (c admissionRelayControl) connection() relayv1.ServicePublisherConnection {
	return relayv1.ServicePublisherConnection{ServiceId: c.ref.ServiceID, ServiceRunId: c.ref.ServiceRunID, RunNumber: int64(c.ref.RunNumber),
		PublisherConnectionId: c.ref.PublisherConnectionID, ConnectionAssignmentRevision: int64(c.ref.ConnectionAssignmentRevision), RelayServiceId: c.ref.RelayServiceID}
}

func (c admissionRelayControl) ReadyServicePublisherConnection(context.Context, string, relayv1.ServicePublisherConnectionTransition) (relayv1.ServicePublisherConnection, error) {
	return c.connection(), nil
}

func (c admissionRelayControl) DisconnectServicePublisherConnection(context.Context, string, relayv1.ServicePublisherConnectionTransition) error {
	return nil
}

// both hops use the real service-only relay acceptors and verified TLS/yamux.
// control supplies one exact claim; no legacy publisher or forwarding adapter runs.
func newAdmissionTransportFixture(t *testing.T) *admissionTransportFixture {
	t.Helper()
	material := newForwardingTestMaterial(t)
	now := time.Now().UTC()
	id := func(prefix string) string { return prefix + strings.Repeat("a", 22) }
	ref := tunnelv1.ServicePublisherConnectionRef{ServiceID: id("svc_"), ServiceRunID: id("srun_"), RunNumber: 2,
		PublisherConnectionID: id("pc_"), ConnectionAssignmentRevision: 3, RelayServiceID: "relay-service"}
	lease := relayv1.RelayLease{RelayServiceId: ref.RelayServiceID, RelayId: "relay", RelayRunId: id("rr_"), RelayLeaseRevision: 4,
		ProtocolVersion: 1, RelayAddress: "relay.test:443", TlsServerName: material.serverName, InternalRelayAddress: "127.0.0.1:9445",
		InternalNetworks: []string{}, ConnectionCapacity: 4, StreamCapacity: 4,
		RegisteredAt: now, RenewedAt: now, LeaseExpiresAt: now.Add(time.Minute)}
	backend := admissionRelayControl{lease: lease, ref: ref}
	leased := make(chan struct{}, 1)
	controller, err := relay.NewController(relay.ControllerConfig{Client: backend,
		Registration: relayv1.RelayRegistration{RelayServiceId: lease.RelayServiceId, RelayId: lease.RelayId, RelayRunId: lease.RelayRunId,
			ProtocolVersion: 1, RelayAddress: lease.RelayAddress, TlsServerName: lease.TlsServerName, InternalRelayAddress: lease.InternalRelayAddress,
			InternalNetworks: []string{}, ConnectionCapacity: 4, StreamCapacity: 4},
		RenewalInterval: time.Hour, RetryInterval: time.Hour, LeaseChanged: func(relayv1.RelayLease, relayv1.RelayLease) { leased <- struct{}{} },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	ingressWorker(t, cancel, func() error { return controller.Run(ctx) })
	ingressAwait(t, leased)
	registry := relay.NewServiceRegistry()
	t.Cleanup(func() { _ = registry.Close() })
	ready := make(chan struct{}, 1)
	acceptor, err := relay.NewPublisherAcceptor(relay.PublisherAcceptorConfig{
		Select: func(service string) (relay.ServicePublisherTarget, bool) {
			return relay.ServicePublisherTarget{Control: controller, Registry: registry}, service == ref.RelayServiceID
		},
		ReadyConnectionsDelta: func(delta int) {
			if delta == 1 {
				ready <- struct{}{}
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	publisherServer := startForwardingTestServer(t, material, acceptor.Accept)
	transport, err := (muxsession.TLSYamuxConnector{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: material.roots}}).Connect(
		ingressContext(t), muxsession.Endpoint{Address: publisherServer.address(), ServerName: material.serverName})
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := tunnel.Dial(ingressContext(t), transport, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version,
		Role: tunnelv1.Publisher, Credential: "publisher-secret", ServiceConnection: &ref})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { publisherServer.cancel(); _ = publisher.Close() })
	ingressAwait(t, ready)
	f := &admissionTransportFixture{publisher: publisher, publisherServer: publisherServer, wire: transport, released: make(chan struct{}, 16)}
	f.lease.Store(&lease)
	forwarding, err := relay.NewForwardingAcceptor(relay.ForwardingAcceptorConfig{ServiceRegistry: registry,
		CurrentLease: func() relayv1.RelayLease { return *f.lease.Load() }, ClusterSecrets: forwardingTestSecrets(t), StreamCapacity: 1,
		StreamsDelta: func(delta int) {
			if delta == -1 {
				f.released <- struct{}{}
			}
		}})
	if err != nil {
		t.Fatal(err)
	}
	f.server = startForwardingTestServer(t, material, forwarding.Accept)
	f.relay = ingressv1.ServiceRelay{PublisherConnectionId: ref.PublisherConnectionID, ConnectionSlot: int(ref.ConnectionSlot),
		ConnectionAssignmentRevision: int64(ref.ConnectionAssignmentRevision), RelayServiceId: ref.RelayServiceID,
		RelayId: lease.RelayId, RelayRunId: lease.RelayRunId, RelayLeaseRevision: lease.RelayLeaseRevision,
		LeaseExpiresAt: lease.LeaseExpiresAt, InternalRelayAddress: f.server.address(), TlsServerName: material.serverName}
	f.header = tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{
		ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ServiceForwardingStream, ServiceID: ref.ServiceID, ServiceRunID: ref.ServiceRunID,
		RunNumber: ref.RunNumber, PublisherConnectionID: ref.PublisherConnectionID, ConnectionAssignmentRevision: ref.ConnectionAssignmentRevision,
		VisitorConnectionID: id("vc_"), SourceIP: "192.0.2.7", ExpiresAt: lease.LeaseExpiresAt,
		PublicService: &tunnelv1.PublicServiceAdmission{IngressID: "ingress", IngressRunID: id("ir_"), IngressLeaseRevision: 1, DestinationPort: 443},
	}, ConnectionSlot: ref.ConnectionSlot, RelayServiceID: lease.RelayServiceId, RelayID: lease.RelayId,
		RelayRunID: lease.RelayRunId, RelayLeaseRevision: uint64(lease.RelayLeaseRevision), LeaseExpiresAt: lease.LeaseExpiresAt}
	f.forwarder = newTestForwarder(t, material)
	return f
}

func (f *admissionTransportFixture) closePublisher() {
	// stop the publisher owner before closing its carrier, so planned fixture
	// cleanup cannot be recorded as an unexpected publisher-session failure.
	f.publisherServer.cancel()
	_ = f.publisher.Close()
}

func assertAdmissionCode(t *testing.T, err error, want tunnelv1.ErrorCode) {
	t.Helper()
	var protocol *tunnel.ProtocolError
	if !errors.As(err, &protocol) || protocol.Code != want {
		t.Fatalf("admission=%v want=%s", err, want)
	}
	var opening *tunnel.OpeningError
	if !errors.As(err, &opening) || opening.VisitorBytes != 0 {
		t.Fatal("rejected setup crossed the visitor-byte retry boundary", err)
	}
}

func TestServiceForwardingBindsIdentityBeforeVisitorBytes(t *testing.T) {
	f := newAdmissionTransportFixture(t)
	for _, field := range []string{"ServiceID", "ServiceRunID", "RunNumber", "PublisherConnectionID", "ConnectionSlot", "ConnectionAssignmentRevision", "RelayServiceID", "RelayID", "RelayRunID", "RelayLeaseRevision"} {
		t.Run(field, func(t *testing.T) {
			header := f.header
			value := reflect.ValueOf(&header).Elem().FieldByName(field)
			if value.Kind() == reflect.String {
				text := value.String()
				value.SetString(text[:len(text)-1] + "b")
			} else {
				value.SetUint(value.Uint() + 1)
			}
			connection, err := f.forwarder.OpenPrivate(ingressContext(t), f.relay, header)
			if connection != nil || err == nil {
				t.Fatal("changed forwarding identity was admitted")
			}
			switch field {
			case "ServiceID", "ServiceRunID", "RunNumber":
				// service identity is checked against the relay's claimed run.
				assertAdmissionCode(t, err, tunnelv1.StaleConnectionAssignment)
				ingressAwait(t, f.released)
			default:
				// assignment and process identity must match ingress's selection
				// before it opens a stream or writes any visitor bytes.
				if !errors.Is(err, ErrServiceAdmission) {
					t.Fatal("mismatched relay projection reached forwarding", err)
				}
			}
		})
	}
	if f.server.accepted.Load() != 1 {
		t.Fatal("semantic setup rejection replaced the shared ingress session")
	}
}

func TestServiceForwardingLeaseAndCapacityRejectionBeforeAcknowledgment(t *testing.T) {
	for _, boundary := range []string{"lease", "capacity", "cancellation"} {
		t.Run(boundary, func(t *testing.T) {
			f := newAdmissionTransportFixture(t)
			ctx, cancel := context.WithCancel(ingressContext(t))
			defer cancel()
			type result struct {
				connection net.Conn
				err        error
			}
			opened := make(chan result, 1)
			go func() {
				connection, err := f.forwarder.OpenPrivate(ctx, f.relay, f.header)
				opened <- result{connection, err}
			}()
			incoming, err := f.publisher.AcceptServiceForwardingStream(ingressContext(t))
			if err != nil {
				t.Fatal(err)
			}
			defer incoming.Stream().Close()
			if boundary == "capacity" {
				header := f.header
				header.VisitorConnectionID = "vc_" + strings.Repeat("b", 22)
				connection, err := f.forwarder.OpenPrivate(ingressContext(t), f.relay, header)
				if connection != nil {
					connection.Close()
					t.Fatal("capacity was not reserved while publisher acknowledgment was pending")
				}
				assertAdmissionCode(t, err, tunnelv1.CapacityExceeded)
			}
			if boundary == "lease" {
				lease := *f.lease.Load()
				lease.RelayRunId += "-restarted"
				f.lease.Store(&lease)
			}
			if boundary == "cancellation" {
				cancel()
			} else if err := incoming.Accept(); err != nil {
				t.Fatal(err)
			}
			got := ingressAwait(t, opened)
			if boundary == "capacity" {
				if got.err != nil || got.connection == nil {
					t.Fatal("healthy pending opening was changed by sibling capacity rejection", got.err)
				}
				got.connection.Close()
			} else {
				if got.connection != nil || got.err == nil {
					t.Fatal("canceled or lease-stale setup was accepted")
				}
				if boundary == "lease" {
					assertAdmissionCode(t, got.err, tunnelv1.StaleConnectionAssignment)
				}
			}
		})
	}
}

func TestServiceForwardingAcknowledgmentIsIdempotentAndKeepsDataOnce(t *testing.T) {
	f := newAdmissionTransportFixture(t)
	worker := ingressWorker(t, f.closePublisher, func() error {
		incoming, err := f.publisher.AcceptServiceForwardingStream(ingressContext(t))
		if err != nil {
			return err
		}
		defer incoming.Stream().Close()
		if !reflect.DeepEqual(incoming.Header, f.header) {
			return errors.New("canonical forwarding rewrote service, source, or lease facts")
		}
		if err := incoming.Accept(); err != nil {
			return err
		}
		if err := incoming.Accept(); err != nil {
			return err
		}
		_, err = incoming.Stream().Write([]byte("encrypted"))
		if err != nil {
			return err
		}
		return incoming.CloseWrite(ingressContext(t))
	})
	connection, err := f.forwarder.OpenPrivate(ingressContext(t), f.relay, f.header)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(fixtureTimeout)); err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(connection)
	if err != nil || string(payload) != "encrypted" {
		t.Fatal("repeated acknowledgment duplicated a decision or visitor bytes", err)
	}
	if err := ingressAwait(t, worker); err != nil {
		t.Fatal(err)
	}
}
