package ingress

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type privateControlFixture struct {
	mu                sync.Mutex
	outerStarted      chan struct{}
	outerGate         chan struct{}
	claimStarted      chan struct{}
	allowClaim        chan struct{}
	claims            int
	recheckStarted    chan struct{}
	recheckGate       chan struct{}
	recheckErr        error
	deny              bool
	rechecks          int
	recheckActive     atomic.Int32
	sessionDuration   time.Duration
	nextSession       string
	initialValidUntil time.Time
	recheckValidUntil time.Time
	session           string
	service           string
	identity          string
	device            string
	sourceIP          string
	run               string
	revision          int64
	projection        ingressv1.PrivateServiceProjection
}

const privateTestSessionCredential = "session-secret-for-this-private-test-credential"
const privateTestRotatedCredential = "next-session-secret-for-this-private-test"

func (f *privateControlFixture) expectedSourceIP() string {
	if f.sourceIP != "" {
		return f.sourceIP
	}
	return "192.0.2.4"
}

func (f *privateControlFixture) ClaimPrivateConnectorSession(_ context.Context, id string, body ingressv1.PrivateConnectorSessionClaim) (ingressv1.PrivateConnectorSessionResult, error) {
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
	if id != "ingress-a" || body.PrivateServiceId != f.service || !credentialOK || body.IngressLeaseRevision != 1 || body.ObservedSourceIp != f.expectedSourceIP() {
		return ingressv1.PrivateConnectorSessionResult{}, ErrPrivateAdmission
	}
	duration := f.sessionDuration
	if duration == 0 {
		duration = time.Minute
	}
	return ingressv1.PrivateConnectorSessionResult{ConnectorSessionId: body.ConnectorSessionId, PrivateServiceId: f.service, IdentityId: f.identity, DeviceId: f.device, ObservedSourceIp: body.ObservedSourceIp, ExpiresAt: time.Now().Add(duration)}, nil
}
func (f *privateControlFixture) AuthorizePrivateServiceStream(ctx context.Context, id string, body ingressv1.PrivateServiceStreamClaim) (ingressv1.PrivateServiceStreamResult, error) {
	if body.PrivateServiceId != f.service {
		return ingressv1.PrivateServiceStreamResult{}, ErrPrivateAdmission
	}
	f.mu.Lock()
	f.claims++
	started := f.claimStarted
	gate := f.allowClaim
	f.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return ingressv1.PrivateServiceStreamResult{}, ctx.Err()
		}
	}
	validSession := body.ConnectorSessionId == f.session || f.nextSession != "" && body.ConnectorSessionId == f.nextSession
	if id != "ingress-a" || body.PrivateServiceId != f.service || body.PrivateRunId != f.run || !validSession || body.ObservedSourceIp != f.expectedSourceIP() || !opaqueid.Valid(body.VisitorConnectionId, opaqueid.VisitorConnectionPrefix) {
		return ingressv1.PrivateServiceStreamResult{}, ErrPrivateAdmission
	}
	validUntil := f.initialValidUntil
	if validUntil.IsZero() {
		validUntil = time.Now().Add(2 * time.Minute)
	}
	return ingressv1.PrivateServiceStreamResult{PrivateServiceId: body.PrivateServiceId, PrivateRunId: body.PrivateRunId, ConnectorSessionId: body.ConnectorSessionId, IdentityId: f.identity, DeviceId: f.device, GrantRevision: 1, ObservedSourceIp: body.ObservedSourceIp, VisitorConnectionId: body.VisitorConnectionId, RunNumber: body.RunNumber, ExpiresAt: time.Now().Add(time.Minute), ValidUntil: validUntil}, nil
}

func (f *privateControlFixture) ClosePrivateServiceStream(context.Context, string, string, ingressv1.ClosePrivateServiceStreamJSONRequestBody) error {
	return nil
}

func (f *privateControlFixture) RecheckPrivateServiceVisitor(ctx context.Context, id string, body ingressv1.PrivateServiceVisitorRecheck) (ingressv1.PrivateServiceVisitorRecheckResult, error) {
	f.recheckActive.Add(1)
	defer f.recheckActive.Add(-1)
	f.mu.Lock()
	f.rechecks++
	gate, started, denied, problem := f.recheckGate, f.recheckStarted, f.deny, f.recheckErr
	f.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return ingressv1.PrivateServiceVisitorRecheckResult{}, ctx.Err()
		}
	}
	if id != "ingress-a" || body.PrivateServiceId != f.service || body.PrivateRunId != f.run ||
		(body.ConnectorSessionId != f.session && body.ConnectorSessionId != f.nextSession) || body.IdentityId != f.identity || body.RunNumber != 1 ||
		!opaqueid.Valid(body.VisitorConnectionId, opaqueid.VisitorConnectionPrefix) || body.ObservedSourceIp != f.expectedSourceIP() || body.IngressLeaseRevision != 1 {
		return ingressv1.PrivateServiceVisitorRecheckResult{}, ErrPrivateAdmission
	}
	if problem != nil {
		return ingressv1.PrivateServiceVisitorRecheckResult{}, problem
	}
	validUntil := f.recheckValidUntil
	if validUntil.IsZero() {
		validUntil = time.Now().Add(2 * time.Minute)
	}
	return ingressv1.PrivateServiceVisitorRecheckResult{Allowed: !denied, RecheckAt: time.Now().Add(10 * time.Millisecond), ValidUntil: validUntil}, nil
}
func (f *privateControlFixture) GetPrivateServiceSnapshot(_ context.Context, _ string, _ ingressv1.GetPrivateServiceSnapshotParams) (ingressv1.PrivateServiceSnapshot, error) {
	return ingressv1.PrivateServiceSnapshot{Revision: f.revision, Entries: []ingressv1.PrivateServiceProjection{f.projection}}, nil
}
func (f *privateControlFixture) GetPrivateServiceEvents(_ context.Context, _ string, params ingressv1.GetPrivateServiceEventsParams) (ingressv1.PrivateServiceSnapshot, error) {
	return ingressv1.PrivateServiceSnapshot{Revision: params.After, Entries: []ingressv1.PrivateServiceProjection{}}, nil
}

type privateForwarderFixture struct {
	mu             sync.Mutex
	calls          int
	failFirst      bool
	closeAfterByte bool
	holdAfterReply bool
	relayDone      chan struct{}
	observed       chan tunnelv1.PrivateForwardingHeader
	data           chan []byte
	sourceIP       string
}

func (f *privateForwarderFixture) OpenPrivate(_ context.Context, relay ingressv1.PrivateServiceRelay, h tunnelv1.PrivateForwardingHeader) (net.Conn, error) {
	f.mu.Lock()
	f.calls++
	call := f.calls
	f.mu.Unlock()
	if h.RelayID != relay.RelayId || h.PublisherConnectionID != relay.PublisherConnectionId || h.ConnectionSlot != uint8(relay.ConnectionSlot) || h.PrivateServiceID == "" {
		return nil, ErrPrivateAdmission
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

func privateCertificate(t *testing.T, host string) (*tls.Config, *tls.Config) {
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

func privateTestSetup(t *testing.T) (*PrivateConnector, *privateControlFixture, *privateForwarderFixture, *tls.Config, ingressv1.IngressLease, func()) {
	t.Helper()
	service, run, session, identity := privateTestID(t, opaqueid.PrivateServicePrefix), privateTestID(t, opaqueid.PrivateRunPrefix), privateTestID(t, opaqueid.PrivateConnectorSessionPrefix), privateTestID(t, opaqueid.IdentityPrefix)
	lease := ingressv1.IngressLease{IngressId: "ingress-a", IngressRunId: privateTestID(t, opaqueid.IngressRunPrefix), IngressLeaseRevision: 1, LeaseExpiresAt: time.Now().Add(time.Minute)}
	relays := []ingressv1.PrivateServiceRelay{}
	for index := range 2 {
		relays = append(relays, ingressv1.PrivateServiceRelay{PublisherConnectionId: privateTestID(t, opaqueid.PublisherConnectionPrefix), ConnectionSlot: index, ConnectionAssignmentRevision: 1, RelayServiceId: []string{"a", "b"}[index], RelayId: []string{"relay-a", "relay-b"}[index], RelayRunId: privateTestID(t, opaqueid.RelayRunPrefix), RelayLeaseRevision: 1, InternalRelayAddress: "127.0.0.1:443", LeaseExpiresAt: time.Now().Add(time.Minute)})
	}
	control := &privateControlFixture{service: service, run: run, session: session, identity: identity, revision: 1, projection: ingressv1.PrivateServiceProjection{Kind: ingressv1.Upsert, PrivateServiceId: service, PrivateRunId: &run, RunNumber: func() *int64 { n := int64(1); return &n }(), Revision: 1, ExpiresAt: time.Now().Add(time.Minute), ConnectedRelays: &relays}}
	control.device = privateTestID(t, "vdev_")
	forwarder := &privateForwarderFixture{observed: make(chan tunnelv1.PrivateForwardingHeader, 4), data: make(chan []byte, 4)}
	serverTLS, clientTLS := privateCertificate(t, "ingress.test")
	connector, err := NewPrivateConnector(PrivateConnectorConfig{Hostname: "ingress.test", TLSConfig: serverTLS, Control: control, Forwarder: forwarder, Routing: &PrivateRoutingTable{}, CurrentLease: func() ingressv1.IngressLease { return lease }})
	if err != nil {
		t.Fatal(err)
	}
	return connector, control, forwarder, clientTLS, lease, func() {}
}

func privateTestConnect(t *testing.T, connector *PrivateConnector, control *privateControlFixture, clientTLS *tls.Config) (muxsession.Session, func()) {
	return privateTestConnectAs(t, connector, control, clientTLS, control.session, privateTestSessionCredential)
}

func privateTestConnectAs(t *testing.T, connector *PrivateConnector, control *privateControlFixture, clientTLS *tls.Config, sessionID, credential string) (muxsession.Session, func()) {
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
	client := muxsession.PrivateMuxTLSConnector{TLSConfig: clientTLS}
	transport, err := client.Connect(ctx, muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "ingress.test"})
	if err != nil {
		cancel()
		_ = listener.Close()
		t.Fatal(err)
	}
	session, err := tunnel.DialPrivateConnector(ctx, transport, privateTestHello(control, sessionID, credential))
	if err != nil {
		cancel()
		_ = listener.Close()
		t.Fatal(err)
	}
	return session, func() {
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

func privateEntry(control *privateControlFixture) tunnelv1.PrivateVisitorEntry {
	return tunnelv1.PrivateVisitorEntry{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.PrivateVisitorStream, PrivateServiceID: control.service, PrivateRunID: control.run, RunNumber: 1}
}

func TestPrivateConnectorSNIMapSelectsIndependentMuxHandlers(t *testing.T) {
	first, firstControl, _, firstRoots, _, _ := privateTestSetup(t)
	second, secondControl, _, _, _, _ := privateTestSetup(t)
	secondTLS, secondRoots := privateCertificate(t, "ingress-b.test")
	configuration := second.config
	configuration.Hostname, configuration.TLSConfig = "ingress-b.test", secondTLS
	var err error
	second, err = NewPrivateConnector(configuration)
	if err != nil {
		t.Fatal(err)
	}
	firstControl.sourceIP, secondControl.sourceIP = "127.0.0.1", "127.0.0.1"
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mapping := map[string]*PrivateConnector{"ingress.test": first, "ingress-b.test": second}
	var publicLookups atomic.Int32
	server, err := New(listener, Config{MaxConnections: 16, PrivateConnectors: mapping, Lookup: func(string) (PublicURL, LookupReason) { publicLookups.Add(1); return PublicURL{}, LookupNotFound }})
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
		transport, err := (muxsession.PrivateMuxTLSConnector{TLSConfig: candidate.roots}).Connect(ctx, muxsession.Endpoint{Address: listener.Addr().String(), ServerName: candidate.name})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		session, err := tunnel.DialPrivateConnector(ctx, transport, privateTestHello(candidate.control, candidate.control.session, privateTestSessionCredential))
		cancel()
		if err != nil {
			_ = transport.Close()
			t.Fatalf("private SNI selected the wrong handler: %v", err)
		}
		if session.Accepted.PrivateServiceID != candidate.control.service {
			t.Fatal("private SNI changed the authenticated service scope")
		}
		_ = session.Close()
	}
	if publicLookups.Load() != 0 {
		t.Fatal("private SNI fell through to public URL lookup")
	}
}

func TestPrivateConnectorQUICAuthenticatesDeviceAndPreservesSocketSource(t *testing.T) {
	connector, control, forwarder, clientTLS, _, _ := privateTestSetup(t)
	control.sourceIP = "127.0.0.1"
	forwarder.sourceIP = control.sourceIP
	listener, err := muxsession.ListenPrivateQUIC("127.0.0.1:0", connector.TransportTLSConfig(), muxsession.QUICConfig{})
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
	var session *tunnel.PrivateConnectorSession
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
	transport, err := (muxsession.PrivateQUICConnector{TLSConfig: clientTLS}).Connect(ctx, muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "ingress.test"})
	if err != nil {
		t.Fatal(err)
	}
	session, err = tunnel.DialPrivateConnector(ctx, transport, privateTestHello(control, control.session, privateTestSessionCredential))
	if err != nil {
		t.Fatal(err)
	}
	if session.Accepted.SourceIP != control.sourceIP || session.Accepted.DeviceID != control.device {
		t.Fatal("QUIC session changed the enrolled device or socket source")
	}
	stream, err := session.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if err = stream.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = tunnelv1.WritePrivateVisitorEntry(stream, privateEntry(control)); err != nil {
		t.Fatal(err)
	}
	accepted, err := tunnelv1.ReadPrivateVisitorAccepted(stream)
	if err != nil || accepted.SourceIP != control.sourceIP {
		t.Fatalf("QUIC visitor metadata: %+v %v", accepted, err)
	}
	if _, err = stream.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var reply [4]byte
	if _, err = io.ReadFull(stream, reply[:]); err != nil || string(reply[:]) != "pong" {
		t.Fatalf("QUIC visitor stream: %q %v", reply, err)
	}
}

func privateTestHello(control *privateControlFixture, session, credential string) tunnelv1.PrivateConnectorSessionHello {
	return tunnelv1.PrivateConnectorSessionHello{ProtocolVersion: tunnelv1.Version, Kind: "private_connector_session", PrivateServiceID: control.service, SessionID: session, Credential: credential,
		DeviceID: control.device, IdentityID: control.identity, Nonce: bytes.Repeat([]byte{1}, 32), Signature: make([]byte, 64)}
}

func TestPrivateConnectorAuthenticatesBeforeMuxAndBeforeForwarding(t *testing.T) {
	connector, control, forwarder, tlsConfig, _, _ := privateTestSetup(t)
	forwarder.failFirst = true
	control.claimStarted = make(chan struct{}, 1)
	control.allowClaim = make(chan struct{})
	session, stop := privateTestConnect(t, connector, control, tlsConfig)
	defer stop()
	stream, err := session.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	wrong := privateEntry(control)
	wrong.PrivateServiceID = privateTestID(t, opaqueid.PrivateServicePrefix)
	if err := tunnelv1.WritePrivateVisitorEntry(stream, wrong); err != nil {
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
	if err := tunnelv1.WritePrivateVisitorEntry(stream2, privateEntry(control)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-control.claimStarted:
	case <-time.After(time.Second):
		t.Fatal("stream authorization not reached")
	}
	if forwarder.count() != 0 {
		t.Fatal("forwarded before stream authorization")
	}
	close(control.allowClaim)
	_ = stream2.SetReadDeadline(time.Now().Add(2 * time.Second))
	accepted, err := tunnelv1.ReadPrivateVisitorAccepted(stream2)
	if err != nil || accepted.IdentityID != control.identity || accepted.SourceIP != "192.0.2.4" {
		t.Fatalf("claimed visitor acceptance: %+v, %v", accepted, err)
	}
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
		if header.VisitorConnectionID != accepted.VisitorConnectionID || header.Connector.SessionID != control.session || header.Connector.DeviceID != control.device || header.Connector.GrantRevision != 1 {
			t.Fatalf("forwarded binding=%+v", header)
		}
	case <-time.After(time.Second):
		t.Fatal("no relay header")
	}
	if forwarder.count() != 2 {
		t.Fatalf("failover before first visitor byte = %d opens, want 2", forwarder.count())
	}
}

func TestPrivateConnectorNeverReplaysAfterVisitorByte(t *testing.T) {
	connector, control, forwarder, tlsConfig, _, _ := privateTestSetup(t)
	forwarder.closeAfterByte = true
	session, stop := privateTestConnect(t, connector, control, tlsConfig)
	defer stop()
	stream, err := session.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if err := tunnelv1.WritePrivateVisitorEntry(stream, privateEntry(control)); err != nil {
		t.Fatal(err)
	}
	_ = stream.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := tunnelv1.ReadPrivateVisitorAccepted(stream); err != nil {
		t.Fatal(err)
	}
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

func TestPrivateConnectorBlocksVisitorStreamsBeforeDeviceAuthentication(t *testing.T) {
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
	client := muxsession.PrivateMuxTLSConnector{TLSConfig: tlsConfig}
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
		session, err := tunnel.DialPrivateConnector(ctx, transport, privateTestHello(control, control.session, privateTestSessionCredential))
		connected <- outcome{session, err}
	}()
	select {
	case <-control.outerStarted:
	case <-time.After(time.Second):
		t.Fatal("outer credential not checked")
	}
	// the session control stream must authenticate before a visitor is served.
	if forwarder.count() != 0 || control.claims != 0 {
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

func TestPrivateConnectorRejectsMissingCertificateAndWrongHostname(t *testing.T) {
	connector, _, _, _, _, _ := privateTestSetup(t)
	broken := connector.config
	broken.TLSConfig = nil
	if _, err := NewPrivateConnector(broken); err == nil {
		t.Fatal("accepted plaintext private connector")
	}
	broken = connector.config
	broken.Hostname = "service.example.test"
	broken.TLSConfig.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return nil, nil }
	if _, err := NewPrivateConnector(broken); err == nil {
		t.Fatal("accepted per-service TLS selection")
	}
}

func TestPrivateConnectorRefusesPublicTunnelALPN(t *testing.T) {
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
	if control.claims != 0 || forwarder.count() != 0 {
		t.Fatal("unmatched ALPN reached private control or relay")
	}
}

func TestPrivateConnectorRejectsLeaseLostDuringStreamAuthorization(t *testing.T) {
	connector, control, forwarder, tlsConfig, lease, _ := privateTestSetup(t)
	var lost atomic.Bool
	connector.config.CurrentLease = func() ingressv1.IngressLease {
		current := lease
		if lost.Load() {
			current.Draining = true
		}
		return current
	}
	control.claimStarted, control.allowClaim = make(chan struct{}, 1), make(chan struct{})
	session, stop := privateTestConnect(t, connector, control, tlsConfig)
	defer stop()
	stream, err := session.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if err := tunnelv1.WritePrivateVisitorEntry(stream, privateEntry(control)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-control.claimStarted:
	case <-time.After(time.Second):
		t.Fatal("stream authorization never started")
	}
	lost.Store(true)
	close(control.allowClaim)
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := tunnelv1.ReadPrivateVisitorAccepted(stream); err == nil {
		t.Fatal("accepted a visitor on a stale ingress lease")
	}
	if forwarder.count() != 0 {
		t.Fatal("forwarded visitor on stale ingress lease")
	}
}

func TestPrivateConnectorRejectsStaleRunProjectionAfterAuthorization(t *testing.T) {
	connector, control, forwarder, tlsConfig, _, _ := privateTestSetup(t)
	other := privateTestID(t, opaqueid.PrivateRunPrefix)
	control.projection.PrivateRunId = &other
	session, stop := privateTestConnect(t, connector, control, tlsConfig)
	defer stop()
	stream, err := session.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if err := tunnelv1.WritePrivateVisitorEntry(stream, privateEntry(control)); err != nil {
		t.Fatal(err)
	}
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := tunnelv1.ReadPrivateVisitorAccepted(stream); err == nil {
		t.Fatal("accepted stale private run")
	}
	if forwarder.count() != 0 {
		t.Fatal("forwarded stale run before admission")
	}
}

func privateActiveStream(t *testing.T, connector *PrivateConnector, control *privateControlFixture, forwarder *privateForwarderFixture, tlsConfig *tls.Config) (muxsession.Session, muxsession.Stream, func()) {
	t.Helper()
	forwarder.holdAfterReply = true
	forwarder.relayDone = make(chan struct{}, 4)
	session, stop := privateTestConnect(t, connector, control, tlsConfig)
	stream, err := session.OpenStream(t.Context())
	if err != nil {
		stop()
		t.Fatal(err)
	}
	if err := tunnelv1.WritePrivateVisitorEntry(stream, privateEntry(control)); err != nil {
		stop()
		t.Fatal(err)
	}
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := tunnelv1.ReadPrivateVisitorAccepted(stream); err != nil {
		stop()
		t.Fatal(err)
	}
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
	connector.config.RecheckInterval = 20 * time.Millisecond
	connector.config.RecheckTimeout = 10 * time.Millisecond
	connector.config.HardAuthorizationTTL = 150 * time.Millisecond
	_, stream, stop := privateActiveStream(t, connector, control, forwarder, tlsConfig)
	defer stop()
	control.mu.Lock()
	control.deny = true
	control.mu.Unlock()
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
	if control.recheckActive.Load() != 0 {
		t.Fatal("recheck worker remained active after denial")
	}
}

func TestPrivateLiveVisitorHardDeadlineOnControlOutage(t *testing.T) {
	connector, control, forwarder, tlsConfig, _, _ := privateTestSetup(t)
	connector.config.RecheckInterval = 20 * time.Millisecond
	connector.config.RecheckTimeout = 10 * time.Millisecond
	connector.config.HardAuthorizationTTL = 125 * time.Millisecond
	_, stream, stop := privateActiveStream(t, connector, control, forwarder, tlsConfig)
	defer stop()
	control.mu.Lock()
	control.recheckErr = errors.New("control is unavailable")
	control.mu.Unlock()
	started := time.Now()
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, err := stream.Read(one[:]); err == nil {
		t.Fatal("control outage left visitor stream open")
	}
	if elapsed := time.Since(started); elapsed < 35*time.Millisecond || elapsed > 300*time.Millisecond {
		t.Fatalf("outage stream closed after %v, want bounded grace period", elapsed)
	}
	control.mu.Lock()
	checks := control.rechecks
	control.mu.Unlock()
	if checks < 2 {
		t.Fatalf("outage did not retry live authorization: %d checks", checks)
	}
	select {
	case <-forwarder.relayDone:
	case <-time.After(time.Second):
		t.Fatal("relay copy not joined at hard deadline")
	}
	if control.recheckActive.Load() != 0 {
		t.Fatal("outage left a recheck worker running")
	}
}

func TestPrivateLiveVisitorCancellationJoinsBlockedRecheckAndCopy(t *testing.T) {
	connector, control, forwarder, tlsConfig, _, _ := privateTestSetup(t)
	connector.config.RecheckInterval = 120 * time.Millisecond
	connector.config.RecheckTimeout = 100 * time.Millisecond
	connector.config.HardAuthorizationTTL = 350 * time.Millisecond
	control.recheckStarted = make(chan struct{}, 1)
	control.recheckGate = make(chan struct{})
	_, _, stop := privateActiveStream(t, connector, control, forwarder, tlsConfig)
	select {
	case <-control.recheckStarted:
	case <-time.After(time.Second):
		stop()
		t.Fatal("recheck never started")
	}
	stop()
	if control.recheckActive.Load() != 0 {
		t.Fatal("blocked recheck survived connector close")
	}
	select {
	case <-forwarder.relayDone:
	case <-time.After(time.Second):
		t.Fatal("relay copy survived connector close")
	}
}

func TestPrivateOuterExpiryAllowsOldStreamAndFreshSessionForNewStreams(t *testing.T) {
	connector, control, forwarder, tlsConfig, _, _ := privateTestSetup(t)
	connector.config.RecheckInterval = 20 * time.Millisecond
	connector.config.RecheckTimeout = 10 * time.Millisecond
	connector.config.HardAuthorizationTTL = 250 * time.Millisecond
	control.sessionDuration = 120 * time.Millisecond
	control.nextSession = privateTestID(t, opaqueid.PrivateConnectorSessionPrefix)
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
	if err := tunnelv1.WritePrivateVisitorEntry(newOnOld, privateEntry(control)); err == nil {
		if _, err := tunnelv1.ReadPrivateVisitorAccepted(newOnOld); err == nil {
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
	entry := privateEntry(control)
	if err := tunnelv1.WritePrivateVisitorEntry(newStream, entry); err != nil {
		t.Fatal(err)
	}
	_ = newStream.SetReadDeadline(time.Now().Add(time.Second))
	accepted, err := tunnelv1.ReadPrivateVisitorAccepted(newStream)
	if err != nil || accepted.ConnectorSessionID != control.nextSession || accepted.VisitorConnectionID == oldHeader.VisitorConnectionID {
		t.Fatalf("rotated session reused old visitor: %+v: %v", accepted, err)
	}
	if _, err := newStream.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var reply [4]byte
	if _, err := io.ReadFull(newStream, reply[:]); err != nil || string(reply[:]) != "pong" {
		t.Fatalf("new session did not serve new visitor: %q: %v", reply, err)
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

func TestPrivateLiveVisitorOutageEndsAtEarlierGrantDeadline(t *testing.T) {
	connector, control, forwarder, tlsConfig, _, _ := privateTestSetup(t)
	connector.config.RecheckInterval = 20 * time.Millisecond
	connector.config.RecheckTimeout = 10 * time.Millisecond
	connector.config.HardAuthorizationTTL = 250 * time.Millisecond
	control.recheckStarted = make(chan struct{}, 1)
	control.recheckValidUntil = time.Now().Add(135 * time.Millisecond)
	_, stream, stop := privateActiveStream(t, connector, control, forwarder, tlsConfig)
	defer stop()
	select {
	case <-control.recheckStarted:
	case <-time.After(time.Second):
		t.Fatal("soon-expiring grant was not rechecked")
	}
	control.mu.Lock()
	control.recheckErr = errors.New("control unavailable after last grant check")
	control.mu.Unlock()
	started := time.Now()
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, err := stream.Read(one[:]); err == nil {
		t.Fatal("visitor survived grant hard deadline during outage")
	}
	if elapsed := time.Since(started); elapsed > 190*time.Millisecond {
		t.Fatalf("grant hard deadline ignored for %v", elapsed)
	}
	select {
	case <-forwarder.relayDone:
	case <-time.After(time.Second):
		t.Fatal("stream worker survived grant expiry")
	}
	if control.recheckActive.Load() != 0 {
		t.Fatal("recheck survived grant expiry")
	}
}

func TestPrivateLiveVisitorOutageHonorsInitialClaimDeadline(t *testing.T) {
	connector, control, forwarder, tlsConfig, _, _ := privateTestSetup(t)
	control.initialValidUntil = time.Now().Add(175 * time.Millisecond)
	control.recheckErr = errors.New("control unavailable immediately after stream authorization")
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
	if control.recheckActive.Load() != 0 {
		t.Fatal("initial grant expiry left a recheck running")
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	if control.rechecks < 2 {
		t.Fatalf("default scheduling did not retry before the initial deadline: %d", control.rechecks)
	}
}

func TestPrivateLiveVisitorDefaultsRefreshShortInitialLease(t *testing.T) {
	connector, control, forwarder, tlsConfig, _, _ := privateTestSetup(t)
	control.initialValidUntil = time.Now().Add(250 * time.Millisecond)
	control.recheckStarted = make(chan struct{}, 1)
	_, stream, stop := privateActiveStream(t, connector, control, forwarder, tlsConfig)
	defer stop()
	select {
	case <-control.recheckStarted:
	case <-time.After(time.Second):
		t.Fatal("default interval missed the initial lease deadline")
	}
	_ = stream.SetReadDeadline(control.initialValidUntil.Add(100 * time.Millisecond))
	if _, err := stream.Read(make([]byte, 1)); err == nil {
		t.Fatal("unexpected bytes")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("successful recheck did not preserve the original stream: %v", err)
	}
}

func TestPrivateRoutingRejectsOldAssignmentAndLease(t *testing.T) {
	_, control, _, _, lease, _ := privateTestSetup(t)
	table := new(PrivateRoutingTable)
	now := time.Now()
	if err := table.ApplySnapshot(ingressv1.PrivateServiceSnapshot{Revision: 1, Entries: []ingressv1.PrivateServiceProjection{control.projection}}, now); err != nil {
		t.Fatal(err)
	}
	changed := clonePrivateProjection(control.projection)
	changed.Revision = 2
	(*changed.ConnectedRelays)[0].ConnectionAssignmentRevision = 2
	(*changed.ConnectedRelays)[0].PublisherConnectionId = privateTestID(t, opaqueid.PublisherConnectionPrefix)
	if err := table.ApplyEvents(1, ingressv1.PrivateServiceSnapshot{Revision: 2, Entries: []ingressv1.PrivateServiceProjection{changed}}, now); err != nil {
		t.Fatal(err)
	}
	if err := table.ApplyEvents(2, ingressv1.PrivateServiceSnapshot{Revision: 3, Entries: []ingressv1.PrivateServiceProjection{control.projection}}, now); !errors.Is(err, ErrPrivateRoutingStale) {
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
