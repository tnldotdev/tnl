package service

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type nativeDeliveryFixture struct {
	delivery controlv1.NativePeerPairDelivery
	policy   controlv1.VisitorPolicySnapshot
	calls    int
}

func (f *nativeDeliveryFixture) DeliverNativePeerPair(context.Context, string, string, string, int64, credentials.ServiceRunToken) (controlv1.NativePeerPairDelivery, error) {
	f.calls++
	return f.delivery, nil
}

func (f *nativeDeliveryFixture) ReadPublisherVisitorPolicy(_ context.Context, body controlv1.PublisherVisitorPolicyRequest, _ string) (controlv1.VisitorPolicyUpdate, error) {
	if body.Resource != f.policy.Resource || body.RunId != f.delivery.ServiceRunId || body.RunNumber != f.delivery.RunNumber {
		return controlv1.VisitorPolicyUpdate{}, ErrPrivateStream
	}
	policy := f.policy
	policy.ObservedAt = time.Now()
	policy.ValidUntil = policy.ObservedAt.Add(visitortoken.PolicyLifetime)
	return controlv1.VisitorPolicyUpdate{Policy: policy, AfterRevision: body.AfterRevision, SnapshotRequired: body.AfterRevision == 0}, nil
}

func nativePeerFixture(t *testing.T, target string, lifetime ...time.Duration) (*Bound, *PeerSession, *tls.Config, func(string) tunnelv1.NativePeerVisitorEntry, *nativeDeliveryFixture) {
	t.Helper()
	p, b, _, verification := privateFixture(t, target)
	controlKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	clientKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	digest, _ := visitortoken.KeyDigest(clientKey.Public())
	subject := visitortoken.Device{IdentityID: "ident_" + strings.Repeat("A", 22), SessionID: "cs_" + strings.Repeat("H", 22), DeviceID: "vdev_" + strings.Repeat("B", 22), KeySHA256: digest}
	peerSubject, _ := visitortoken.NativeSubject(subject)
	identity, device := subject.IdentityID, subject.DeviceID
	now := time.Now()
	t.Cleanup(b.Invalidate)
	d := controlv1.NativePeerPairDelivery{PairId: "npp_" + strings.Repeat("C", 22), DeliveryId: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 16)), DeliveryGeneration: 1, Key: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)), ServiceId: p.Preparation.ServiceId, ServiceRunId: p.Preparation.ServiceRunId, RunNumber: p.Preparation.RunNumber, PublisherIdentityId: p.Preparation.PublisherIdentityId, SourceIp: "192.0.2.1", Subject: controlv1.VisitorSubject{Kind: controlv1.VisitorSubjectKind(peerSubject.Kind), IdentityId: &identity, DeviceId: &device}, ObservedAt: now, ExpiresAt: now.Add(time.Minute)}
	if len(lifetime) != 0 {
		d.ExpiresAt = now.Add(lifetime[0])
	}
	for slot, a := range b.connections {
		d.Relays = append(d.Relays, controlv1.NativePeerPairRelay{PublisherConnectionId: a.PublisherConnectionId, AssignmentRevision: a.ConnectionAssignmentRevision, RelayAddress: a.RelayAddress, TlsServerName: a.TlsServerName, RelayLease: controlv1.NativePeerRelayLease{RelayServiceId: a.RelayServiceId, RelayId: "relay-process", RelayRunId: "rr_" + strings.Repeat(string(rune('D'+slot)), 22), RelayLeaseRevision: 1}})
	}
	control := &nativeDeliveryFixture{delivery: d, policy: controlv1.VisitorPolicySnapshot{
		Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKindService, Id: p.Preparation.ServiceId},
		Issuer:   "https://control.example.test", Hostname: p.managedHostname, Port: int(p.servicePort), Enabled: true,
		VisitorPolicyRevision: 1, MetadataRevision: p.metadataRevision, KeyRevision: 1,
		VerificationKeys: []controlv1.VisitorVerificationKey{{Id: "fixture", PublicKey: controlKey.Public().(ed25519.PublicKey)}},
	}}
	if err := b.PrepareNativePolicy(t.Context(), control, "run-token"); err != nil {
		t.Fatal("native policy did not decode current service metadata", err)
	}
	binding, err := PreparePeerBinding(t.Context(), control, d.ServiceId, d.ServiceRunId, d.PairId, d.DeliveryGeneration, "run-token")
	if err != nil {
		t.Fatal(err)
	}
	peer, err := b.BindPeer(t.Context(), binding)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(peer.Close)
	token, err := visitortoken.Sign(control.policy.Issuer, "fixture", controlKey, visitortoken.Permission{Scope: visitorscope.Scope{Kind: visitorscope.Service, ID: p.Preparation.ServiceId}, Hostname: p.managedHostname, Port: p.servicePort, VisitorPolicyRevision: 1, Subject: subject, ExpiresAt: now.Add(time.Minute)}, now)
	if err != nil {
		t.Fatal(err)
	}
	opening := func(label string) tunnelv1.NativePeerVisitorEntry {
		e := tunnelv1.NativePeerVisitorEntry{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.NativePeerVisitorStream, PairID: binding.pairID, DeliveryID: d.DeliveryId, DeliveryGeneration: 1, ServiceID: d.ServiceId, ServiceRunID: d.ServiceRunId, RunNumber: uint64(d.RunNumber), Subject: peerSubject, SourceIP: d.SourceIp, VisitorConnectionID: "vc_" + strings.Repeat(label, 22), MetadataRevision: uint64(p.metadataRevision), Permission: tunnelv1.NativeVisitorPermission{Token: token.Reveal(), PublicKey: base64.RawURLEncoding.EncodeToString(clientKey.Public().(ed25519.PublicKey)), Signature: base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))}}
		message, err := tunnelv1.NativePeerProofMessage(e, nil)
		if err != nil {
			t.Fatal(err)
		}
		e.Permission.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(clientKey, message))
		return e
	}
	return b, peer, verification, opening, control
}

func nativeInnerPair(t *testing.T, ctx context.Context, verification *tls.Config) (muxsession.Session, muxsession.Session) {
	t.Helper()
	// use the fixture's independent root for this inner transport, rather than
	// borrowing visitor or target key material for its client authentication.
	certificate, trust := managedTestCertificate(t, verification.ServerName)
	listener, err := muxsession.ListenQUIC("127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}, muxsession.QUICConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	client, err := (muxsession.QUICConnector{TLSConfig: trust}).Connect(ctx, muxsession.Endpoint{Address: listener.Addr().String(), ServerName: trust.ServerName})
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server
}

func TestNativeServicePeerConsumerForwardsAndRejectsReplayLocally(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	var targets sync.WaitGroup
	var accepted atomic.Int64
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			targets.Go(func() { defer conn.Close(); _, _ = io.Copy(conn, conn) })
		}
	}()
	b, p, verification, opening, control := nativePeerFixture(t, target.Addr().String(), 2*time.Second)
	first, replayed := opening("F"), opening("F")
	client, server := nativeInnerPair(t, ctx, verification)
	served := make(chan error, 1)
	go func() { served <- p.Serve(ctx, server) }()
	open := func(entry tunnelv1.NativePeerVisitorEntry) *tls.Conn {
		raw, err := client.OpenStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tunnelv1.WriteNativePeerVisitorOpening(raw, entry, nil); err != nil {
			t.Fatal(err)
		}
		return tls.Client(tunnel.NewNativeRequestWriter(raw), verification)
	}
	prepared, err := connectorstream.PrepareNativeTCP(ctx, client, connectorstream.Run{ServiceID: first.ServiceID, ServiceRunID: first.ServiceRunID, RunNumber: first.RunNumber, Protocol: "tcp", TrustRevision: int64(first.MetadataRevision), ValidUntil: time.Now().Add(time.Minute), Endpoint: &controlv1.ServiceEndpoint{Hostname: verification.ServerName, Port: int(b.prepared.servicePort)}, ServiceTLS: verification}, first)
	if err != nil {
		t.Fatal("real native preparation rejected", err)
	}
	defer prepared.Close()
	// local arrival only consumes the already signed, open and TLS-verified
	// stream. no source signer, control request or ICE runs on this path.
	local, forward := net.Pipe()
	defer local.Close()
	forwarded := make(chan error, 1)
	go func() { forwarded <- prepared.Forward(ctx, forward) }()
	if _, err := local.Write([]byte("native")); err != nil {
		t.Fatal(err)
	}
	var got [6]byte
	if _, err := io.ReadFull(local, got[:]); err != nil || string(got[:]) != "native" {
		t.Fatal("native target transcript changed", string(got[:]), err)
	}
	old := p.bindingSnapshot()
	b.mu.Lock()
	var original *nativeAdmission
	for a := range p.streams {
		original = a
	}
	if original == nil {
		b.mu.Unlock()
		t.Fatal("no retained native admission after the target replied")
	}
	inner, setupUntil := p.session, original.setupUntil
	b.mu.Unlock()
	renewal := *control
	renewal.delivery.ObservedAt = time.Now()
	renewal.delivery.ExpiresAt = renewal.delivery.ObservedAt.Add(time.Minute)
	binding, err := PreparePeerBinding(ctx, &renewal, old.serviceID, old.runID, old.pairID, old.generation, "run-token")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Renew(binding); err != nil {
		t.Fatal("current authenticated delivery did not renew the retained owner", err)
	}
	// the original fixed context deadline must not close this same inner stream,
	// target socket, capacity charge or replay history after successful renewal.
	timer := time.NewTimer(time.Until(old.until) + 20*time.Millisecond)
	select {
	case <-timer.C:
	case <-ctx.Done():
		timer.Stop()
		t.Fatal(ctx.Err())
	}
	if _, err := local.Write([]byte("retain")); err != nil {
		t.Fatal("renewal closed the retained stream", err)
	}
	if _, err := io.ReadFull(local, got[:]); err != nil || string(got[:]) != "retain" {
		t.Fatal("renewal changed the live target transcript", string(got[:]), err)
	}
	replay := open(replayed)
	if err := replay.HandshakeContext(ctx); err == nil {
		t.Fatal("same visitor entered twice on the retained pair")
	}
	_ = replay.Close()
	b.mu.Lock()
	active, pending := b.reservedStreams, b.nativePending
	_, retained := p.streams[original]
	unchanged := p.session == inner && original.setupUntil.Equal(setupUntil) && len(p.seen) == 1
	b.mu.Unlock()
	if active != 1 || pending != 0 || !retained || !unchanged || accepted.Load() != 1 {
		t.Fatal("renewal changed native stream, target, replay, setup or capacity ownership", active, pending, retained, unchanged, accepted.Load())
	}
	if control.calls != 1 {
		t.Fatal("application arrival fetched delivery", control.calls)
	}
	_ = local.Close()
	_ = prepared.Close()
	<-forwarded
	p.Close()
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	active, pending = b.reservedStreams, b.nativePending
	b.mu.Unlock()
	if active != 0 || pending != 0 {
		t.Fatal("native cleanup released ownership before joining or leaked charges", active, pending)
	}
	_ = target.Close()
	targets.Wait()
}

func TestNativePeerRenewalCannotTransferOrReviveOwnership(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*PeerSession, *PeerBinding)
	}{
		{"pair", func(_ *PeerSession, b *PeerBinding) { b.pairID = "npp_" + strings.Repeat("Z", 22) }},
		{"service", func(_ *PeerSession, b *PeerBinding) { b.serviceID = "svc_" + strings.Repeat("Z", 22) }},
		{"run", func(_ *PeerSession, b *PeerBinding) { b.runID = "srun_" + strings.Repeat("Z", 22) }},
		{"publisher", func(_ *PeerSession, b *PeerBinding) { b.publisherID = "pub_" + strings.Repeat("Z", 22) }},
		{"run number", func(_ *PeerSession, b *PeerBinding) { b.number++ }},
		{"generation", func(_ *PeerSession, b *PeerBinding) { b.generation++ }},
		{"delivery", func(_ *PeerSession, b *PeerBinding) { b.delivery[0]++ }},
		{"key", func(_ *PeerSession, b *PeerBinding) { b.key[0]++ }},
		{"subject", func(_ *PeerSession, b *PeerBinding) { b.subject.DeviceID = "vdev_" + strings.Repeat("Z", 22) }},
		{"source", func(_ *PeerSession, b *PeerBinding) { b.source = netip.MustParseAddr("192.0.2.2") }},
		{"assignment", func(_ *PeerSession, b *PeerBinding) { b.relays[0].AssignmentRevision++ }},
		{"expired delivery", func(_ *PeerSession, b *PeerBinding) { b.until = time.Now().Add(-time.Second) }},
		{"expired owner", func(p *PeerSession, _ *PeerBinding) { p.binding.until = time.Now().Add(-time.Second) }},
		{"retired owner", func(p *PeerSession, _ *PeerBinding) { p.closed = true }},
		{"unregistered owner", func(p *PeerSession, _ *PeerBinding) { delete(p.bound.nativePeers, p.binding.pairID) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			b, p, _, _, _ := nativePeerFixture(t, "127.0.0.1:1")
			b.mu.Lock()
			next := p.binding
			next.until = time.Now().Add(2 * time.Minute)
			test.change(p, &next)
			before := p.binding
			b.mu.Unlock()
			if err := p.Renew(next); !errors.Is(err, ErrPrivateStream) {
				t.Fatal("renewal transferred or revived peer authority", err)
			}
			if p.bindingSnapshot() != before {
				t.Fatal("rejected renewal changed the retained binding")
			}
		})
	}
}

func TestNativeServiceDeniedOpeningCannotResolveOrReadMySQLTarget(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	target, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	b, p, verification, opening, _ := nativePeerFixture(t, target.Addr().String())
	b.prepared.managedProtocol = config.ProtocolMySQL
	resolver := &nativeDeniedResolver{target: target.Addr().String()}
	b.prepared.targetResolver = resolver
	entry := opening("G")
	entry.Permission.Token = "not-a-signed-token"
	client, server := nativeInnerPair(t, ctx, verification)
	served := make(chan error, 1)
	go func() { served <- p.Serve(ctx, server) }()
	raw, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tunnelv1.WriteNativePeerVisitorOpening(raw, entry, nil); err != nil {
		t.Fatal(err)
	}
	_ = raw.SetReadDeadline(time.Now().Add(time.Second))
	var b1 [1]byte
	if _, err = raw.Read(b1[:]); err == nil {
		t.Fatal("denied opening received target bytes")
	}
	_ = target.SetDeadline(time.Now().Add(10 * time.Millisecond))
	if conn, err := target.Accept(); err == nil {
		_ = conn.Close()
		t.Fatal("native denial contacted a MySQL target before admission")
	}
	p.Close()
	<-served
	if resolver.calls.Load() != 0 {
		t.Fatal("native denial entered the target resolver")
	}
}

type nativeDeniedResolver struct {
	target string
	calls  atomic.Int64
}

func (r *nativeDeniedResolver) ResolveTarget(context.Context) (string, *tls.Config, error) {
	r.calls.Add(1)
	return r.target, &tls.Config{MinVersion: tls.VersionTLS12}, nil
}

func TestNativeServicePeerHTTPConsumerJoinsHandlerAndTarget(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "native HTTP") }))
	defer target.Close()
	b, p, verification, opening, _ := nativePeerFixture(t, target.Listener.Addr().String())
	b.prepared.managedProtocol = config.ProtocolHTTP
	var err error
	b.prepared.serviceHTTPRequests, err = publisher.NewServiceHTTPRequestLimits(nil)
	if err != nil {
		t.Fatal(err)
	}
	client, server := nativeInnerPair(t, ctx, verification)
	served := make(chan error, 1)
	go func() { served <- p.Serve(ctx, server) }()
	raw, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tunnelv1.WriteNativePeerVisitorOpening(raw, opening("J"), nil); err != nil {
		t.Fatal(err)
	}
	secured := tls.Client(tunnel.NewNativeRequestWriter(raw), verification)
	defer secured.Close()
	if err := secured.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, "https://127.0.0.1:15432/", nil)
	request.Close = true
	if err := request.Write(secured); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(secured), request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "native HTTP" {
		t.Fatal("native HTTP forwarding changed", response.StatusCode, string(body), err)
	}
	_ = secured.Close()
	p.Close()
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	active, pending := b.reservedStreams, b.nativePending
	b.mu.Unlock()
	if active != 0 || pending != 0 {
		t.Fatal("HTTP handler/target retirement leaked native charges", active, pending)
	}
}

type heldNativeStreamClose struct {
	muxsession.Stream
	entered, release chan struct{}
	once             sync.Once
	err              error
}

func (s *heldNativeStreamClose) Close() error {
	s.once.Do(func() { close(s.entered); <-s.release; s.err = s.Stream.Close() })
	return s.err
}

type heldNativeSessionClose struct {
	muxsession.Session
	entered, release chan struct{}
}

func (s *heldNativeSessionClose) AcceptStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &heldNativeStreamClose{Stream: stream, entered: s.entered, release: s.release}, nil
}

func TestNativeServiceOwnerLossFencesBeforeCloseAndRetainsCUntilJoin(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	targetDone := make(chan struct{})
	go func() {
		defer close(targetDone)
		conn, err := target.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()
	b, p, verification, opening, _ := nativePeerFixture(t, target.Addr().String())
	b.streamCapacity = 1
	client, server := nativeInnerPair(t, ctx, verification)
	entered, release := make(chan struct{}), make(chan struct{})
	releaseClose := sync.OnceFunc(func() { close(release) })
	defer releaseClose()
	served := make(chan error, 1)
	go func() {
		served <- p.Serve(ctx, &heldNativeSessionClose{Session: server, entered: entered, release: release})
	}()
	entry := opening("I")
	raw, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tunnelv1.WriteNativePeerVisitorOpening(raw, entry, nil); err != nil {
		t.Fatal(err)
	}
	secured := tls.Client(tunnel.NewNativeRequestWriter(raw), verification)
	defer secured.Close()
	if err := secured.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := secured.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	var response [1]byte
	if _, err := io.ReadFull(secured, response[:]); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	var admission *nativeAdmission
	for a := range p.streams {
		admission = a
	}
	ref := b.assignments[b.connections[0].PublisherConnectionId]
	b.mu.Unlock()
	if admission == nil {
		t.Fatal("no real admitted stream")
	}
	closed := make(chan struct{})
	go func() { p.Close(); close(closed) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := admission.CheckUse(ctx); err == nil {
		t.Fatal("owner loss admitted new use while physical close was held")
	}
	if release, ok := b.reserveStream(ref); ok {
		release()
		t.Fatal("C was reused before the actual stream cleanup joined")
	}
	select {
	case <-closed:
		t.Fatal("peer close returned before stream cleanup")
	default:
	}
	releaseClose()
	select {
	case <-closed:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	<-served
	<-targetDone
	b.mu.Lock()
	active, pending := b.reservedStreams, b.nativePending
	b.mu.Unlock()
	if active != 0 || pending != 0 {
		t.Fatal("joined retirement leaked C or pending", active, pending)
	}
}

type nativeResolverFunc func(context.Context) (string, *tls.Config, error)

func (f nativeResolverFunc) ResolveTarget(ctx context.Context) (string, *tls.Config, error) {
	return f(ctx)
}

func TestNativeServiceResolutionUsesOriginalSetupDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	target, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	b, p, _, opening, _ := nativePeerFixture(t, target.Addr().String())
	b.streamCapacity = 1
	entered := make(chan context.Context, 1)
	expired, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	b.prepared.targetResolver = nativeResolverFunc(func(resolve context.Context) (string, *tls.Config, error) {
		entered <- resolve
		<-resolve.Done()
		close(expired)
		<-release
		return "", nil, context.Cause(resolve)
	})
	client, server := net.Pipe()
	defer client.Close()
	a, err := p.reserve(ctx, server)
	if err != nil {
		t.Fatal(err)
	}
	// shorten the existing admission budget before starting it; policy and peer
	// authority remain live so neither can hide an unbounded resolver.
	a.setupUntil = time.Now().Add(200 * time.Millisecond)
	done := make(chan error, 1)
	go func() { defer p.workers.Done(); done <- a.forwardPeer() }()
	if _, err := tunnelv1.WriteNativePeerVisitorOpening(client, opening("K"), nil); err != nil {
		t.Fatal(err)
	}
	select {
	case resolve := <-entered:
		if deadline, ok := resolve.Deadline(); !ok || !deadline.Equal(a.setupUntil) {
			t.Fatalf("resolver deadline=%v; want original setup deadline %v", deadline, a.setupUntil)
		}
	case <-ctx.Done():
		t.Fatal("resolver was not entered", ctx.Err())
	}
	next := p.bindingSnapshot()
	next.until = time.Now().Add(2 * time.Minute)
	if err := p.Renew(next); err != nil {
		t.Fatal("peer renewal during entered setup failed", err)
	}
	select {
	case <-expired:
	case <-ctx.Done():
		t.Fatal("resolver outlived setup", ctx.Err())
	}
	if _, err := a.CheckUse(ctx); err == nil {
		t.Fatal("expired setup still permitted use")
	}
	b.mu.Lock()
	ref := b.assignments[b.connections[0].PublisherConnectionId]
	b.mu.Unlock()
	if release, available := b.reserveStream(ref); available {
		release()
		t.Fatal("C was released before the entered resolver joined")
	}
	release <- struct{}{}
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("original resolver expiry was not preserved", err)
		}
	case <-ctx.Done():
		t.Fatal("resolver cleanup did not join", ctx.Err())
	}
	if err := target.SetDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if conn, err := target.Accept(); err == nil {
		conn.Close()
		t.Fatal("expired resolution dialed the target")
	}
	b.mu.Lock()
	active, pending := b.reservedStreams, b.nativePending
	b.mu.Unlock()
	if active != 0 || pending != 0 {
		t.Fatal("joined resolution leaked admission charges", active, pending)
	}
}

type heldNativePreparation struct {
	muxsession.Session
	clearing, release, closing chan struct{}
}

func (s *heldNativePreparation) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	return &heldNativePreparationStream{Stream: stream, owner: s}, nil
}

type heldNativePreparationStream struct {
	muxsession.Stream
	owner *heldNativePreparation
	once  sync.Once
}

func (s *heldNativePreparationStream) SetDeadline(until time.Time) error {
	if until.IsZero() {
		close(s.owner.clearing)
		<-s.owner.release
		return nil
	}
	return s.Stream.SetDeadline(until)
}

func (s *heldNativePreparationStream) Close() error {
	s.once.Do(func() { close(s.owner.closing) })
	return s.Stream.Close()
}

func TestNativePreparationCannotPublishAfterSetupCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	b, p, verification, opening, _ := nativePeerFixture(t, "127.0.0.1:1")
	client, server := nativeInnerPair(t, ctx, verification)
	served := make(chan error, 1)
	go func() { served <- p.Serve(ctx, server) }()
	defer func() { p.Close(); <-served }()
	gate := &heldNativePreparation{Session: client, clearing: make(chan struct{}), release: make(chan struct{}), closing: make(chan struct{})}
	release := sync.OnceFunc(func() { close(gate.release) })
	defer release()
	entry := opening("L")
	done := make(chan error, 1)
	go func() {
		prepared, err := connectorstream.PrepareNativeTCP(ctx, gate, connectorstream.Run{ServiceID: entry.ServiceID, ServiceRunID: entry.ServiceRunID, RunNumber: entry.RunNumber, Protocol: "tcp", TrustRevision: int64(entry.MetadataRevision), ValidUntil: time.Now().Add(time.Minute), Endpoint: &controlv1.ServiceEndpoint{Hostname: verification.ServerName, Port: int(b.prepared.servicePort)}, ServiceTLS: verification}, entry)
		if prepared != nil {
			prepared.Close()
		}
		done <- err
	}()
	select {
	case <-gate.clearing:
	case err := <-done:
		t.Fatal("preparation did not finish visitor TLS", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// TLS has succeeded and the parent is live. let the original setup timeout
	// close the stream before allowing the final deadline clear to return.
	select {
	case <-gate.closing:
	case <-ctx.Done():
		t.Fatal("setup cancellation did not close its stream", ctx.Err())
	}
	if ctx.Err() != nil {
		t.Fatal("parent expiry hid the setup cancellation race")
	}
	release()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("setup cancellation published a closed prepared stream")
		}
	case <-ctx.Done():
		t.Fatal("preparation did not join cancellation", ctx.Err())
	}
}
