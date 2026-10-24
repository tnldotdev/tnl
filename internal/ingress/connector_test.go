package ingress

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"io"
	"maps"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type privateControlFixture struct {
	outerStarted    chan struct{}
	outerGate       chan struct{}
	sessionClaims   atomic.Int64
	sessionDuration time.Duration
	nextSession     string
	session         string
	service         string
	identity        string
	device          string
	sourceIP        string
	run             string
	revision        int64
	projection      ingressv1.ServiceProjection
	routingReads    atomic.Int64
	permission      visitortoken.Token
	key             ed25519.PrivateKey
	policyUpdate    visitorlease.Update
}

const privateTestSessionCredential = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const privateTestRotatedCredential = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func (f *privateControlFixture) subject() tunnelv1.VisitorSubject {
	return tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: f.identity, DeviceID: f.device}
}

func (f *privateControlFixture) expectedSourceIP() string {
	if f.sourceIP != "" {
		return f.sourceIP
	}
	return "192.0.2.4"
}

func (f *privateControlFixture) ClaimConnectorSession(_ context.Context, id string, body ingressv1.ConnectorSessionClaim) (ingressv1.ConnectorSessionResult, error) {
	f.sessionClaims.Add(1)
	if f.outerStarted != nil {
		select {
		case f.outerStarted <- struct{}{}:
		default:
		}
	}
	if f.outerGate != nil {
		<-f.outerGate
	}
	credentialOK := body.ConnectorSessionId == f.session && body.SessionCredential == privateTestSessionCredential ||
		f.nextSession != "" && body.ConnectorSessionId == f.nextSession && body.SessionCredential == privateTestRotatedCredential
	if id != "ingress-a" || body.ServiceId != f.service || !credentialOK || body.IngressLeaseRevision != 1 || body.ObservedSourceIp != f.expectedSourceIP() {
		return ingressv1.ConnectorSessionResult{}, ErrServiceAdmission
	}
	duration := f.sessionDuration
	if duration == 0 {
		duration = time.Minute
	}
	return ingressv1.ConnectorSessionResult{ConnectorSessionId: body.ConnectorSessionId, ServiceId: f.service, Subject: visitorsubject.Wire(f.subject()), ObservedSourceIp: body.ObservedSourceIp, ExpiresAt: time.Now().Add(duration)}, nil
}
func (f *privateControlFixture) GetServiceSnapshot(_ context.Context, _ string, _ ingressv1.GetServiceSnapshotParams) (ingressv1.ServiceSnapshot, error) {
	f.routingReads.Add(1)
	return ingressv1.ServiceSnapshot{Revision: f.revision, Entries: []ingressv1.ServiceProjection{f.projection}}, nil
}
func (f *privateControlFixture) GetServiceEvents(_ context.Context, _ string, params ingressv1.GetServiceEventsParams) (ingressv1.ServiceSnapshot, error) {
	f.routingReads.Add(1)
	return ingressv1.ServiceSnapshot{Revision: params.After, Entries: []ingressv1.ServiceProjection{}}, nil
}

type privateForwarderFixture struct {
	mu             sync.Mutex
	calls          int
	failFirst      bool
	closeAfterByte bool
	holdAfterReply bool
	relayDone      chan struct{}
	observed       chan tunnelv1.ServiceForwardingHeader
	data           chan []byte
	sourceIP       string
}

func (f *privateForwarderFixture) OpenPrivate(_ context.Context, relay ingressv1.ServiceRelay, h tunnelv1.ServiceForwardingHeader) (net.Conn, error) {
	f.mu.Lock()
	f.calls++
	call := f.calls
	f.mu.Unlock()
	if h.RelayID != relay.RelayId || h.PublisherConnectionID != relay.PublisherConnectionId || h.ConnectionSlot != uint8(relay.ConnectionSlot) || h.ServiceID == "" {
		return nil, ErrServiceAdmission
	}
	if f.failFirst && call == 1 {
		return nil, errors.New("relay unavailable before visitor byte")
	}
	ingress, upstream := net.Pipe()
	go func() {
		defer upstream.Close()
		meta, remaining, err := proxyproto.Decode(upstream)
		wantSource := f.sourceIP
		if wantSource == "" {
			wantSource = "192.0.2.4"
		}
		if err != nil || meta.Source.Addr().String() != wantSource {
			return
		}
		if h.Connector != nil {
			_, initial, err := tunnelv1.ReadConnectorVisitorOpening(remaining)
			if err != nil {
				return
			}
			remaining = tunnel.NewNativeRequestReader(&testReaderConn{Conn: upstream, reader: remaining}, initial, func(tunnelv1.NativeVisitorPermission) error { return nil })
		}
		f.observed <- h
		if f.closeAfterByte {
			var first [1]byte
			_, _ = io.ReadFull(remaining, first[:])
			f.data <- first[:]
			return
		}
		value := make([]byte, 4)
		if _, err = io.ReadFull(remaining, value); err != nil {
			return
		}
		f.data <- value
		_, _ = upstream.Write([]byte("pong"))
		if f.holdAfterReply {
			_, _ = io.Copy(io.Discard, remaining)
			if f.relayDone != nil {
				f.relayDone <- struct{}{}
			}
		}
	}()
	return ingress, nil
}
func (f *privateForwarderFixture) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

func privateTestID(t *testing.T, prefix string) string {
	t.Helper()
	id, err := opaqueid.New(prefix)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func serviceCertificate(t *testing.T, host string) (*tls.Config, *tls.Config) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}}, &tls.Config{RootCAs: roots}
}

func privateTestSetup(t *testing.T) (*Connector, *privateControlFixture, *privateForwarderFixture, *tls.Config, ingressv1.IngressLease, func()) {
	t.Helper()
	service, run, session, identity := privateTestID(t, opaqueid.ServicePrefix), privateTestID(t, opaqueid.ServiceRunPrefix), privateTestID(t, opaqueid.ConnectorSessionPrefix), privateTestID(t, opaqueid.IdentityPrefix)
	lease := ingressv1.IngressLease{IngressId: "ingress-a", IngressRunId: privateTestID(t, opaqueid.IngressRunPrefix), IngressLeaseRevision: 1, LeaseExpiresAt: time.Now().Add(time.Minute)}
	relays := []ingressv1.ServiceRelay{}
	for index := range 2 {
		relays = append(relays, ingressv1.ServiceRelay{PublisherConnectionId: privateTestID(t, opaqueid.PublisherConnectionPrefix), ConnectionSlot: index, ConnectionAssignmentRevision: 1, RelayServiceId: []string{"a", "b"}[index], RelayId: []string{"relay-a", "relay-b"}[index], RelayRunId: privateTestID(t, opaqueid.RelayRunPrefix), RelayLeaseRevision: 1, InternalRelayAddress: "127.0.0.1:443", LeaseExpiresAt: time.Now().Add(time.Minute)})
	}
	control := &privateControlFixture{service: service, run: run, session: session, identity: identity, revision: 1, projection: ingressv1.ServiceProjection{Kind: ingressv1.Upsert, ServiceId: service, ServiceRunId: &run, RunNumber: func() *int64 { n := int64(1); return &n }(), Revision: 1, ExpiresAt: time.Now().Add(time.Minute), ConnectedRelays: &relays}}
	control.device = privateTestID(t, "vdev_")
	forwarder := &privateForwarderFixture{observed: make(chan tunnelv1.ServiceForwardingHeader, 4), data: make(chan []byte, 4)}
	serverTLS, clientTLS := serviceCertificate(t, "ingress.test")
	connector, err := NewConnector(ConnectorConfig{Hostname: "ingress.test", TLSConfig: serverTLS, Control: control, Forwarder: forwarder, Routing: &ServiceRoutingTable{}, CurrentLease: func() ingressv1.IngressLease { return lease }})
	if err != nil {
		t.Fatal(err)
	}
	control.key = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, ed25519.SeedSize))
	public := control.key.Public().(ed25519.PublicKey)
	digest, err := visitortoken.KeyDigest(public)
	if err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: service}
	now := time.Now()
	permission := visitortoken.Permission{Scope: scope, Hostname: "service.example.test", Port: 25443, VisitorPolicyRevision: 1, Subject: visitortoken.Device{IdentityID: identity, DeviceID: control.device, SessionID: privateTestID(t, opaqueid.ControlSessionPrefix), KeySHA256: digest}, ExpiresAt: now.Add(time.Minute)}
	control.permission, err = visitortoken.Sign("https://control.example.test", "test-key", control.key, permission, now)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := visitorlease.New(scope, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(policy.Close)
	allocation := controlv1.StreamCapacityAllocation{Id: privateTestID(t, "salloc_"), Resource: controlv1.VisitorResourceScope{Kind: "service", Id: service}, RunId: run, RunNumber: 1, IngressId: lease.IngressId, IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision, Capacity: 64, ObservedAt: now, ValidUntil: now.Add(10 * time.Second), PublisherObserved: true}
	control.policyUpdate = visitorlease.Update{Snapshot: true, KeyRevision: 1, Enabled: true, Allocations: map[string]controlv1.StreamCapacityAllocation{allocation.Id: allocation}, View: visitortoken.View{Issuer: "https://control.example.test", Scope: scope, Hostname: permission.Hostname, Port: permission.Port, MetadataRevision: 1, VisitorPolicyRevision: 1, ObservedAt: now, ValidUntil: now.Add(10 * time.Second), Keys: map[string]ed25519.PublicKey{"test-key": public}}}
	if err := policy.Apply(policy.Begin(), control.policyUpdate); err != nil {
		t.Fatal(err)
	}
	pool := newStreamReservations(nil)
	t.Cleanup(pool.Close)
	if err := pool.apply(streamAllocation{ID: allocation.Id, ResourceKind: "service", ResourceID: service, RunID: run, RunNumber: 1, IngressID: lease.IngressId, IngressRunID: lease.IngressRunId, IngressLeaseRevision: uint64(lease.IngressLeaseRevision), Capacity: 64, ObservedAt: now, ValidUntil: allocation.ValidUntil}, now); err != nil {
		t.Fatal(err)
	}
	connector.prepared[run] = &preparedVisitorRun{policy: &visitorPolicy{lease: policy}, capacity: &streamCapacity{owner: lease, pool: pool, id: allocation.Id, ready: true}}
	if err := connector.refreshRouting(t.Context(), lease); err != nil {
		t.Fatal(err)
	}
	return connector, control, forwarder, clientTLS, lease, func() {}
}

func updateNativePolicy(t *testing.T, connector *Connector, control *privateControlFixture, change func(*visitorlease.Update)) {
	t.Helper()
	update := control.policyUpdate
	update.Allocations = maps.Clone(update.Allocations)
	now := time.Now()
	update.View.ObservedAt, update.View.ValidUntil = now, now.Add(10*time.Second)
	change(&update)
	lease := connector.prepared[control.run].policy.lease
	if err := lease.Apply(lease.Begin(), update); err != nil {
		t.Fatal(err)
	}
	control.policyUpdate = update
}

func privateTestConnect(t *testing.T, connector *Connector, control *privateControlFixture, clientTLS *tls.Config) (muxsession.Session, func()) {
	return privateTestConnectAs(t, connector, control, clientTLS, control.session, privateTestSessionCredential)
}

func privateTestConnectAs(t *testing.T, connector *Connector, control *privateControlFixture, clientTLS *tls.Config, sessionID, credential string) (muxsession.Session, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err == nil {
			_ = connector.Accept(ctx, conn, netip.MustParseAddrPort("192.0.2.4:42000"), netip.MustParseAddrPort("203.0.113.8:443"))
			_ = conn.Close()
		}
	}()
	client := muxsession.ConnectorMuxTLS{TLSConfig: clientTLS}
	transport, err := client.Connect(ctx, muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "ingress.test"})
	if err != nil {
		cancel()
		_ = listener.Close()
		t.Fatal(err)
	}
	session, err := tunnel.DialConnector(ctx, transport, privateTestHello(control, sessionID, credential))
	if err != nil {
		cancel()
		_ = listener.Close()
		t.Fatal(err)
	}
	return nativeTestSession{Session: session}, func() {
		_ = session.Close()
		cancel()
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("private connector did not stop")
		}
	}
}

type nativeTestSession struct{ muxsession.Session }

func (s nativeTestSession) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	return wrapNativeTestStream(stream), nil
}

type nativeTestStream struct {
	muxsession.Stream
	writer *tunnel.NativeRequestWriter
	opened bool
}

func wrapNativeTestStream(stream muxsession.Stream) muxsession.Stream {
	return &nativeTestStream{Stream: stream, writer: tunnel.NewNativeRequestWriter(stream)}
}

func (s *nativeTestStream) Write(p []byte) (int, error) {
	if !s.opened {
		s.opened = true
		return s.Stream.Write(p)
	}
	return s.writer.Write(p)
}

func (s *nativeTestStream) CloseWrite() error { return s.writer.CloseWrite() }

func privateEntry(control *privateControlFixture, selectedSession ...string) tunnelv1.ConnectorVisitorEntry {
	visitor, err := opaqueid.New(opaqueid.VisitorConnectionPrefix)
	if err != nil {
		panic(err)
	}
	session := control.session
	if len(selectedSession) != 0 {
		session = selectedSession[0]
	}
	message, err := visitortoken.NativeProofMessage(control.permission, session, visitor, 1, nil)
	if err != nil {
		panic(err)
	}
	return tunnelv1.ConnectorVisitorEntry{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ConnectorVisitorStream, ServiceID: control.service, ServiceRunID: control.run, RunNumber: 1,
		VisitorConnectionID: visitor, MetadataRevision: 1, Permission: tunnelv1.NativeVisitorPermission{Token: control.permission.Reveal(), PublicKey: base64.RawURLEncoding.EncodeToString(control.key.Public().(ed25519.PublicKey)), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(control.key, message))}}
}

func TestConnectorOpeningRejectsUnboundPermissionBeforeOnlineAuthority(t *testing.T) {
	for _, name := range []string{"signature", "key", "visitor", "metadata", "token", "initial", "another-session"} {
		t.Run(name, func(t *testing.T) {
			connector, control, forwarder, roots, _, _ := privateTestSetup(t)
			peer, stop := privateTestConnect(t, connector, control, roots)
			defer stop()
			entry := privateEntry(control)
			var initial []byte
			switch name {
			case "signature":
				entry.Permission.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
			case "key":
				entry.Permission.PublicKey = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
			case "visitor":
				entry.VisitorConnectionID = privateTestID(t, opaqueid.VisitorConnectionPrefix)
			case "metadata":
				entry.MetadataRevision++
			case "token":
				entry.Permission.Token = "invalid.signed.permission"
			case "initial":
				initial = []byte("changed opening bytes")
			case "another-session":
				entry = privateEntry(control, privateTestID(t, opaqueid.ConnectorSessionPrefix))
			}
			stream, err := peer.OpenStream(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			if _, err := tunnelv1.WriteConnectorVisitorOpening(stream, entry, initial); err != nil {
				t.Fatal(err)
			}
			_ = stream.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := stream.Read(make([]byte, 1)); err == nil {
				t.Fatal("unbound native permission admitted a stream")
			}
			if control.sessionClaims.Load() != 1 || control.routingReads.Load() != 2 || forwarder.count() != 0 {
				t.Fatal("invalid opening reached online authority or relay")
			}
		})
	}
}

func TestConnectorOpeningForwardsProofBoundInitialBytesExactlyOnce(t *testing.T) {
	connector, control, forwarder, roots, _, _ := privateTestSetup(t)
	peer, stop := privateTestConnect(t, connector, control, roots)
	defer stop()
	entry := privateEntry(control)
	initial := []byte("ping")
	message, err := visitortoken.NativeProofMessage(control.permission, control.session, entry.VisitorConnectionID, entry.MetadataRevision, initial)
	if err != nil {
		t.Fatal(err)
	}
	entry.Permission.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(control.key, message))
	stream, err := peer.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(time.Second))
	if _, err := tunnelv1.WriteConnectorVisitorOpening(stream, entry, initial); err != nil {
		t.Fatal(err)
	}
	var response [4]byte
	if _, err := io.ReadFull(stream, response[:]); err != nil || string(response[:]) != "pong" {
		t.Fatalf("initial bytes were not carried before further client writes: %q %v", response, err)
	}
	select {
	case data := <-forwarder.data:
		if !bytes.Equal(data, initial) || forwarder.count() != 1 {
			t.Fatal("initial visitor bytes changed or replayed")
		}
	case <-time.After(time.Second):
		t.Fatal("initial visitor bytes did not reach the target")
	}
	header := <-forwarder.observed
	if header.VisitorConnectionID != entry.VisitorConnectionID {
		t.Fatal("opening changed the proof-bound visitor")
	}
}

func TestConnectorSNIMapSelectsIndependentMuxHandlers(t *testing.T) {
	first, firstControl, _, firstRoots, _, _ := privateTestSetup(t)
	second, secondControl, _, _, _, _ := privateTestSetup(t)
	secondTLS, secondRoots := serviceCertificate(t, "ingress-b.test")
	configuration := second.config
	prepared := second.prepared
	configuration.Hostname, configuration.TLSConfig = "ingress-b.test", secondTLS
	var err error
	second, err = NewConnector(configuration)
	if err != nil {
		t.Fatal(err)
	}
	second.prepared = prepared
	firstControl.sourceIP, secondControl.sourceIP = "127.0.0.1", "127.0.0.1"
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mapping := map[string]*Connector{"ingress.test": first, "ingress-b.test": second}
	var publicLookups atomic.Int32
	server, err := New(listener, Config{MaxConnections: 16, Connectors: mapping, Lookup: func(string) (PublicURL, LookupReason) { publicLookups.Add(1); return PublicURL{}, LookupNotFound }})
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	// validated configuration must not retain a mutable caller-owned map.
	mapping["ingress.test"] = nil
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = first.Close()
		_ = second.Close()
		_ = server.Drain(ctx)
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("shared private TCP listener: %v", err)
			}
		case <-ctx.Done():
			t.Error("shared private TCP listener did not join")
		}
	})
	for _, candidate := range []struct {
		name    string
		roots   *tls.Config
		control *privateControlFixture
	}{
		{"ingress.test", firstRoots, firstControl}, {"ingress-b.test", secondRoots, secondControl},
	} {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		transport, err := (muxsession.ConnectorMuxTLS{TLSConfig: candidate.roots}).Connect(ctx, muxsession.Endpoint{Address: listener.Addr().String(), ServerName: candidate.name})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		session, err := tunnel.DialConnector(ctx, transport, privateTestHello(candidate.control, candidate.control.session, privateTestSessionCredential))
		cancel()
		if err != nil {
			_ = transport.Close()
			t.Fatalf("private SNI selected the wrong handler: %v", err)
		}
		if session.Accepted.ServiceID != candidate.control.service {
			t.Fatal("private SNI changed the authenticated service scope")
		}
		_ = session.Close()
	}
	if publicLookups.Load() != 0 {
		t.Fatal("private SNI fell through to public URL lookup")
	}
}

func TestConnectorQUICAuthenticatesDeviceAndPreservesSocketSource(t *testing.T) {
	connector, control, forwarder, clientTLS, _, _ := privateTestSetup(t)
	control.sourceIP = "127.0.0.1"
	forwarder.sourceIP = control.sourceIP
	listener, err := muxsession.ListenConnectorQUIC("127.0.0.1:0", connector.TransportTLSConfig(), muxsession.QUICConfig{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		transport, err := listener.Accept(ctx)
		if err != nil {
			done <- err
			return
		}
		done <- connector.AcceptQUIC(ctx, transport)
	}()
	var session *tunnel.ConnectorSession
	t.Cleanup(func() {
		cancel()
		if session != nil {
			_ = session.Close()
		}
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("private QUIC ingress did not stop")
		}
	})
	transport, err := (muxsession.ConnectorQUIC{TLSConfig: clientTLS}).Connect(ctx, muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "ingress.test"})
	if err != nil {
		t.Fatal(err)
	}
	session, err = tunnel.DialConnector(ctx, transport, privateTestHello(control, control.session, privateTestSessionCredential))
	if err != nil {
		t.Fatal(err)
	}
	if session.Accepted.SourceIP != control.sourceIP || session.Accepted.Subject != control.subject() {
		t.Fatal("QUIC session changed the enrolled device or socket source")
	}
	stream, err := session.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stream = wrapNativeTestStream(stream)
	defer stream.Close()
	if err = stream.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = tunnelv1.WriteConnectorVisitorOpening(stream, privateEntry(control), nil); err != nil {
		t.Fatal(err)
	}
	if _, err = stream.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var reply [4]byte
	if _, err = io.ReadFull(stream, reply[:]); err != nil || string(reply[:]) != "pong" {
		t.Fatalf("QUIC visitor stream: %q %v", reply, err)
	}
	header := <-forwarder.observed
	if header.SourceIP != control.sourceIP || header.Connector.Subject != control.subject() {
		t.Fatal("QUIC forwarding changed source or subject")
	}
}

func privateTestHello(control *privateControlFixture, session, credential string) tunnelv1.ConnectorSessionHello {
	return tunnelv1.ConnectorSessionHello{ProtocolVersion: tunnelv1.Version, Kind: "connector_session", ServiceID: control.service, SessionID: session, Credential: credential,
		Subject: control.subject(), Nonce: bytes.Repeat([]byte{1}, 32), Signature: make([]byte, 64)}
}

func TestConnectorAuthenticatesBeforeMuxAndBeforeForwarding(t *testing.T) {
	connector, control, forwarder, tlsConfig, _, _ := privateTestSetup(t)
	forwarder.failFirst = true
	session, stop := privateTestConnect(t, connector, control, tlsConfig)
	defer stop()
	stream, err := session.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	wrong := privateEntry(control)
	wrong.ServiceID = privateTestID(t, opaqueid.ServicePrefix)
	if _, err := tunnelv1.WriteConnectorVisitorOpening(stream, wrong, nil); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	_ = stream.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := stream.Read(one[:]); err == nil {
		t.Fatal("cross-service stream received acceptance")
	}
	if forwarder.count() != 0 {
		t.Fatal("forwarded unauthenticated cross-service visitor")
	}
	stream2, err := session.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer stream2.Close()
	entry := privateEntry(control)
	if _, err := tunnelv1.WriteConnectorVisitorOpening(stream2, entry, nil); err != nil {
		t.Fatal(err)
	}
	_ = stream2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := stream2.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-forwarder.data:
		if string(got) != "ping" {
			t.Fatalf("forwarded bytes=%q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("no forwarded visitor bytes")
	}
	select {
	case header := <-forwarder.observed:
		if header.VisitorConnectionID != entry.VisitorConnectionID || header.SourceIP != "192.0.2.4" || header.Connector.SessionID != control.session || header.Connector.Subject != control.subject() || header.Connector.GrantRevision != 1 {
			t.Fatalf("forwarded binding=%+v", header)
		}
	case <-time.After(time.Second):
		t.Fatal("no relay header")
	}
	if forwarder.count() != 2 {
		t.Fatalf("failover before first visitor byte = %d opens, want 2", forwarder.count())
	}
	if got := control.routingReads.Load(); got != 2 {
		t.Fatalf("visitor triggered routing RPCs: reads=%d, want two startup reads", got)
	}
	if control.sessionClaims.Load() != 1 {
		t.Fatal("prepared visitor contacted online admission")
	}
}

func TestConnectorNeverReplaysAfterVisitorByte(t *testing.T) {
	connector, control, forwarder, tlsConfig, _, _ := privateTestSetup(t)
	forwarder.closeAfterByte = true
	session, stop := privateTestConnect(t, connector, control, tlsConfig)
	defer stop()
	stream, err := session.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := tunnelv1.WriteConnectorVisitorOpening(stream, privateEntry(control), nil); err != nil {
		t.Fatal(err)
	}
	_ = stream.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = stream.Write([]byte("ping"))
	select {
	case <-forwarder.data:
	case <-time.After(time.Second):
		t.Fatal("first visitor byte never reached relay")
	}
	time.Sleep(25 * time.Millisecond)
	if forwarder.count() != 1 {
		t.Fatalf("replayed after first visitor byte: %d relay opens", forwarder.count())
	}
}

func TestConnectorBlocksVisitorStreamsBeforeDeviceAuthentication(t *testing.T) {
	connector, control, forwarder, tlsConfig, _, _ := privateTestSetup(t)
	control.outerStarted = make(chan struct{}, 1)
	control.outerGate = make(chan struct{})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			finished <- err
			return
		}
		finished <- connector.Accept(ctx, conn, netip.MustParseAddrPort("192.0.2.4:42000"), netip.MustParseAddrPort("203.0.113.8:443"))
	}()
	client := muxsession.ConnectorMuxTLS{TLSConfig: tlsConfig}
	type outcome struct {
		session muxsession.Session
		err     error
	}
	connected := make(chan outcome, 1)
	go func() {
		transport, err := client.Connect(ctx, muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "ingress.test"})
		if err != nil {
			connected <- outcome{err: err}
			return
		}
		session, err := tunnel.DialConnector(ctx, transport, privateTestHello(control, control.session, privateTestSessionCredential))
		connected <- outcome{session, err}
	}()
	select {
	case <-control.outerStarted:
	case <-time.After(time.Second):
		t.Fatal("outer credential not checked")
	}
	// the session control stream must authenticate before a visitor is served.
	if forwarder.count() != 0 {
		t.Fatal("visitor reached forwarding before outer authentication")
	}
	close(control.outerGate)
	select {
	case result := <-connected:
		if result.err != nil {
			t.Fatal(result.err)
		}
		_ = result.session.Close()
	case <-time.After(time.Second):
		t.Fatal("authenticated outer mux did not start")
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("private listener did not stop")
	}
}

func TestConnectorRejectsMissingCertificateAndWrongHostname(t *testing.T) {
	connector, _, _, _, _, _ := privateTestSetup(t)
	broken := connector.config
	broken.TLSConfig = nil
	if _, err := NewConnector(broken); err == nil {
		t.Fatal("accepted plaintext private connector")
	}
	broken = connector.config
	broken.Hostname = "service.example.test"
	broken.TLSConfig.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return nil, nil }
	if _, err := NewConnector(broken); err == nil {
		t.Fatal("accepted per-service TLS selection")
	}
}

func TestConnectorRefusesPublicTunnelALPN(t *testing.T) {
	connector, control, forwarder, clientTLS, _, _ := privateTestSetup(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	finished := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			finished <- err
			return
		}
		defer conn.Close()
		finished <- connector.Accept(t.Context(), conn, netip.MustParseAddrPort("192.0.2.4:42000"), netip.MustParseAddrPort("203.0.113.8:443"))
	}()
	ordinary := muxsession.TLSYamuxConnector{TLSConfig: clientTLS}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if session, err := ordinary.Connect(ctx, muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "ingress.test"}); err == nil {
		_ = session.Close()
		t.Fatal("public tunnel ALPN reached private mux")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("unmatched ALPN blocked ingress")
	}
	if control.sessionClaims.Load() != 0 || forwarder.count() != 0 {
		t.Fatal("unmatched ALPN reached private control or relay")
	}
}

func TestConnectorRejectsLeaseLostDuringStreamAuthorization(t *testing.T) {
	connector, control, forwarder, tlsConfig, lease, _ := privateTestSetup(t)
	var lost atomic.Bool
	connector.config.CurrentLease = func() ingressv1.IngressLease {
		current := lease
		if lost.Load() {
			current.Draining = true
		}
		return current
	}
	session, stop := privateTestConnect(t, connector, control, tlsConfig)
	defer stop()
	stream, err := session.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	var opening bytes.Buffer
	if _, err := tunnelv1.WriteConnectorVisitorOpening(&opening, privateEntry(control), nil); err != nil {
		t.Fatal(err)
	}
	raw := stream.(*nativeTestStream).Stream
	if _, err := raw.Write(opening.Bytes()[:opening.Len()-4]); err != nil {
		t.Fatal(err)
	}
	lost.Store(true)
	_, _ = raw.Write(opening.Bytes()[opening.Len()-4:])
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := stream.Read(make([]byte, 1)); err == nil {
		t.Fatal("accepted a visitor on a stale ingress lease")
	}
	if forwarder.count() != 0 {
		t.Fatal("forwarded visitor on stale ingress lease")
	}
}

func TestConnectorRejectsStaleRunProjectionAfterAuthorization(t *testing.T) {
	connector, control, forwarder, tlsConfig, _, _ := privateTestSetup(t)
	other := privateTestID(t, opaqueid.ServiceRunPrefix)
	projection := clonePrivateProjection(control.projection)
	projection.ServiceRunId = &other
	projection.Revision = 2
	if err := connector.config.Routing.ApplySnapshot(ingressv1.ServiceSnapshot{Revision: 2, Entries: []ingressv1.ServiceProjection{projection}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	session, stop := privateTestConnect(t, connector, control, tlsConfig)
	defer stop()
	stream, err := session.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := tunnelv1.WriteConnectorVisitorOpening(stream, privateEntry(control), nil); err != nil {
		t.Fatal(err)
	}
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := stream.Read(make([]byte, 1)); err == nil {
		t.Fatal("accepted stale private run")
	}
	if forwarder.count() != 0 {
		t.Fatal("forwarded stale run before admission")
	}
}

func privateActiveStream(t *testing.T, connector *Connector, control *privateControlFixture, forwarder *privateForwarderFixture, tlsConfig *tls.Config) (muxsession.Session, muxsession.Stream, func()) {
	t.Helper()
	forwarder.holdAfterReply = true
	forwarder.relayDone = make(chan struct{}, 4)
	session, stop := privateTestConnect(t, connector, control, tlsConfig)
	stream, err := session.OpenStream(t.Context())
	if err != nil {
		stop()
		t.Fatal(err)
	}
	if _, err := tunnelv1.WriteConnectorVisitorOpening(stream, privateEntry(control), nil); err != nil {
		stop()
		t.Fatal(err)
	}
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := stream.Write([]byte("ping")); err != nil {
		stop()
		t.Fatal(err)
	}
	var reply [4]byte
	if _, err := io.ReadFull(stream, reply[:]); err != nil || string(reply[:]) != "pong" {
		stop()
		t.Fatalf("active response = %q: %v", reply, err)
	}
	_ = stream.SetReadDeadline(time.Time{})
	return session, stream, func() { _ = stream.Close(); stop() }
}

func TestPrivateLiveVisitorClosesOnExplicitDenial(t *testing.T) {
	connector, control, forwarder, tlsConfig, _, _ := privateTestSetup(t)
	_, stream, stop := privateActiveStream(t, connector, control, forwarder, tlsConfig)
	defer stop()
	updateNativePolicy(t, connector, control, func(update *visitorlease.Update) { update.Enabled = false; update.View.VisitorPolicyRevision++ })
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, err := stream.Read(one[:]); err == nil {
		t.Fatal("revoked visitor kept an active stream")
	}
	select {
	case <-forwarder.relayDone:
	case <-time.After(time.Second):
		t.Fatal("relay copy not joined after denial")
	}
}

func TestPrivateLiveVisitorHardDeadlineOnControlOutage(t *testing.T) {
	connector, control, forwarder, tlsConfig, _, _ := privateTestSetup(t)
	_, stream, stop := privateActiveStream(t, connector, control, forwarder, tlsConfig)
	defer stop()
	updateNativePolicy(t, connector, control, func(update *visitorlease.Update) {
		update.View.ValidUntil = update.View.ObservedAt.Add(125 * time.Millisecond)
	})
	started := time.Now()
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, err := stream.Read(one[:]); err == nil {
		t.Fatal("control outage left visitor stream open")
	}
	if elapsed := time.Since(started); elapsed < 35*time.Millisecond || elapsed > 300*time.Millisecond {
		t.Fatalf("outage stream closed after %v, want bounded grace period", elapsed)
	}
	if control.sessionClaims.Load() != 1 || control.routingReads.Load() != 2 {
		t.Fatal("active native visitor polled control during outage")
	}
	select {
	case <-forwarder.relayDone:
	case <-time.After(time.Second):
		t.Fatal("relay copy not joined at hard deadline")
	}
}

func TestPrivateLiveVisitorCancellationJoinsBlockedFrameReaderAndCopy(t *testing.T) {
	connector, control, forwarder, tlsConfig, _, _ := privateTestSetup(t)
	_, _, stop := privateActiveStream(t, connector, control, forwarder, tlsConfig)
	stop()
	select {
	case <-forwarder.relayDone:
	case <-time.After(time.Second):
		t.Fatal("relay copy survived connector close")
	}
}

func TestPrivateOuterExpiryAllowsOldStreamAndFreshSessionForNewStreams(t *testing.T) {
	connector, control, forwarder, tlsConfig, _, _ := privateTestSetup(t)
	control.sessionDuration = 120 * time.Millisecond
	control.nextSession = privateTestID(t, opaqueid.ConnectorSessionPrefix)
	oldSession, oldStream, stopOld := privateActiveStream(t, connector, control, forwarder, tlsConfig)
	defer stopOld()
	oldHeader := <-forwarder.observed
	time.Sleep(160 * time.Millisecond)
	if _, err := oldStream.Write([]byte("stay")); err != nil {
		t.Fatalf("outer credential expiry killed admitted stream: %v", err)
	}
	_ = oldStream.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	var one [1]byte
	if _, err := oldStream.Read(one[:]); err == nil {
		t.Fatal("unexpected unbound bytes from old stream")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("outer expiry closed the old stream: %v", err)
	}
	_ = oldStream.SetReadDeadline(time.Time{})
	newOnOld, err := oldSession.OpenStream(t.Context())
	if err != nil {
		t.Fatalf("outer mux closed while its admitted stream was active: %v", err)
	}
	defer newOnOld.Close()
	_ = newOnOld.SetDeadline(time.Now().Add(time.Second))
	if _, err := tunnelv1.WriteConnectorVisitorOpening(newOnOld, privateEntry(control), nil); err == nil {
		if _, err := newOnOld.Read(make([]byte, 1)); err == nil {
			t.Fatal("expired session admitted new visitor stream")
		}
	}
	newSession, stopNew := privateTestConnectAs(t, connector, control, tlsConfig, control.nextSession, privateTestRotatedCredential)
	defer stopNew()
	newStream, err := newSession.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer newStream.Close()
	entry := privateEntry(control, control.nextSession)
	if _, err := tunnelv1.WriteConnectorVisitorOpening(newStream, entry, nil); err != nil {
		t.Fatal(err)
	}
	_ = newStream.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := newStream.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var reply [4]byte
	if _, err := io.ReadFull(newStream, reply[:]); err != nil || string(reply[:]) != "pong" {
		t.Fatalf("new session did not serve new visitor: %q: %v", reply, err)
	}
	header := <-forwarder.observed
	if header.Connector.SessionID != control.nextSession || header.VisitorConnectionID == oldHeader.VisitorConnectionID {
		t.Fatal("rotated session reused old visitor")
	}
	if _, err := oldStream.Write([]byte("more")); err != nil {
		t.Fatalf("new session migrated or closed old visitor: %v", err)
	}
	_ = newStream.Close()
	stopNew()
	stopOld()
	connector.mu.Lock()
	sessions, pending, active := connector.sessions, connector.pending, connector.active
	connector.mu.Unlock()
	if sessions != 0 || pending != 0 || active != 0 {
		t.Fatalf("connector workers did not join: sessions=%d pending=%d active=%d", sessions, pending, active)
	}
	for range 2 {
		select {
		case <-forwarder.relayDone:
		case <-time.After(time.Second):
			t.Fatal("relay stream worker did not join")
		}
	}
}

func TestPrivateLiveVisitorOutageEndsAtEarlierAllocationDeadline(t *testing.T) {
	connector, control, forwarder, tlsConfig, _, _ := privateTestSetup(t)
	_, stream, stop := privateActiveStream(t, connector, control, forwarder, tlsConfig)
	defer stop()
	updateNativePolicy(t, connector, control, func(update *visitorlease.Update) {
		for id, allocation := range update.Allocations {
			allocation.ValidUntil = time.Now().Add(135 * time.Millisecond)
			update.Allocations[id] = allocation
		}
	})
	started := time.Now()
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, err := stream.Read(one[:]); err == nil {
		t.Fatal("visitor survived allocation hard deadline during outage")
	}
	if elapsed := time.Since(started); elapsed > 190*time.Millisecond {
		t.Fatalf("grant hard deadline ignored for %v", elapsed)
	}
	select {
	case <-forwarder.relayDone:
	case <-time.After(time.Second):
		t.Fatal("stream worker survived grant expiry")
	}
}

func TestPrivateLiveVisitorOutageHonorsInitialAllocationDeadline(t *testing.T) {
	connector, control, forwarder, tlsConfig, _, _ := privateTestSetup(t)
	updateNativePolicy(t, connector, control, func(update *visitorlease.Update) {
		for id, allocation := range update.Allocations {
			allocation.ValidUntil = time.Now().Add(175 * time.Millisecond)
			update.Allocations[id] = allocation
		}
	})
	_, stream, stop := privateActiveStream(t, connector, control, forwarder, tlsConfig)
	defer stop()
	started := time.Now()
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, err := stream.Read(one[:]); err == nil {
		t.Fatal("initial grant expiry did not end stream during outage")
	}
	if elapsed := time.Since(started); elapsed > 230*time.Millisecond {
		t.Fatalf("ignored initial valid_until for %v", elapsed)
	}
	select {
	case <-forwarder.relayDone:
	case <-time.After(time.Second):
		t.Fatal("relay copy remained after initial deadline")
	}
	if control.sessionClaims.Load() != 1 || control.routingReads.Load() != 2 {
		t.Fatal("native allocation expiry polled control")
	}
}

func TestPrivateLiveVisitorDefaultsRefreshShortInitialLease(t *testing.T) {
	connector, control, forwarder, tlsConfig, _, _ := privateTestSetup(t)
	initialDeadline := time.Now().Add(250 * time.Millisecond)
	updateNativePolicy(t, connector, control, func(update *visitorlease.Update) { update.View.ValidUntil = initialDeadline })
	_, stream, stop := privateActiveStream(t, connector, control, forwarder, tlsConfig)
	defer stop()
	time.Sleep(100 * time.Millisecond)
	updateNativePolicy(t, connector, control, func(update *visitorlease.Update) {
		update.View.ValidUntil = update.View.ObservedAt.Add(2 * time.Second)
	})
	_ = stream.SetReadDeadline(initialDeadline.Add(100 * time.Millisecond))
	if _, err := stream.Read(make([]byte, 1)); err == nil {
		t.Fatal("unexpected bytes")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("background policy refresh did not preserve the original stream: %v", err)
	}
}

func TestPrivateRoutingRejectsOldAssignmentAndLease(t *testing.T) {
	_, control, _, _, lease, _ := privateTestSetup(t)
	table := new(ServiceRoutingTable)
	now := time.Now()
	if err := table.ApplySnapshot(ingressv1.ServiceSnapshot{Revision: 1, Entries: []ingressv1.ServiceProjection{control.projection}}, now); err != nil {
		t.Fatal(err)
	}
	changed := clonePrivateProjection(control.projection)
	changed.Revision = 2
	(*changed.ConnectedRelays)[0].ConnectionAssignmentRevision = 2
	(*changed.ConnectedRelays)[0].PublisherConnectionId = privateTestID(t, opaqueid.PublisherConnectionPrefix)
	if err := table.ApplyEvents(1, ingressv1.ServiceSnapshot{Revision: 2, Entries: []ingressv1.ServiceProjection{changed}}, now); err != nil {
		t.Fatal(err)
	}
	if err := table.ApplyEvents(2, ingressv1.ServiceSnapshot{Revision: 3, Entries: []ingressv1.ServiceProjection{control.projection}}, now); !errors.Is(err, ErrPrivateRoutingStale) {
		t.Fatalf("accepted old assignment revision: %v", err)
	}
	if _, ok := table.Lookup(control.service, control.run, 1, lease.LeaseExpiresAt.Add(time.Second)); ok {
		t.Fatal("accepted expired projection")
	}
	table.Clear()
	if _, ok := table.Lookup(control.service, control.run, 1, now); ok {
		t.Fatal("accepted projection after lease loss")
	}
}
