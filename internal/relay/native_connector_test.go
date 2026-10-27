package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type nativeClaimFunc func(context.Context, relayv1.RelayLease, netip.Addr, tunnelv1.NativePairLegProof, []byte) (relayv1.NativePeerPairLegClaim, error)

const nativeTestDeliveryID = "AQEBAQEBAQEBAQEBAQEBAQ"

func nativeTestClaim(source netip.Addr, proof tunnelv1.NativePairLegProof) relayv1.NativePeerPairLegClaim {
	key := [32]byte{1}
	now := time.Now()
	return relayv1.NativePeerPairLegClaim{PairId: proof.PairID, DeliveryId: nativeTestDeliveryID, DeliveryGeneration: proof.DeliveryGeneration,
		ConnectionSlot: proof.ConnectionSlot, SourceIp: source.String(), Key: base64.RawURLEncoding.EncodeToString(key[:]), ObservedAt: now, ExpiresAt: now.Add(time.Minute)}
}

type nativeAdmissionObserver struct{ publisher atomic.Int32 }

func (o *nativeAdmissionObserver) ObserveOperation(name string, _ error, _ time.Duration) {
	if name == "RelayAdmitPublisherConnection" {
		o.publisher.Add(1)
	}
}

func (f nativeClaimFunc) ClaimNativePeerPairLegFromAcceptedSocket(ctx context.Context, lease relayv1.RelayLease, source netip.Addr, proof tunnelv1.NativePairLegProof, signed []byte) (relayv1.NativePeerPairLegClaim, error) {
	return f(ctx, lease, source, proof, signed)
}

func nativeAdmissionFixture(t *testing.T, max int, claim NativePeerLegClaimClient) (*PublisherAcceptor, *NativeConnectorAcceptor, tunnelv1.Message) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := base64.RawURLEncoding.EncodeToString(public)
	lease := relayv1.RelayLease{RelayServiceId: "relay-a", RelayId: "node-a", RelayRunId: "run-a", RelayLeaseRevision: 1,
		PeerSigningPublicKey: &key, LeaseExpiresAt: time.Now().Add(time.Minute)}
	owner := &NativeConnectorAcceptor{SourceMode: NativeConnectorDirectSocket, CurrentLease: func() relayv1.RelayLease { return lease },
		SigningKey: private, Claim: claim, MaxSessions: max}
	acceptor, err := NewPublisherAcceptor(PublisherAcceptorConfig{Select: func(string) (PublisherConnectionController, *Registry, bool) {
		return nil, nil, false
	}, Native: owner})
	if err != nil {
		t.Fatal(err)
	}
	proof := tunnelv1.NativePairLegProof{PairID: "npp_1234567890123456789012", DeliveryGeneration: 1,
		ServiceID: "svc_1234567890123456789012", ServiceRunID: "srun_1234567890123456789012", RunNumber: 1,
		PublisherIdentityID: "pub_1234567890123456789012", ConnectionSlot: 0,
		PublisherConnectionID: "pc_1234567890123456789012", AssignmentRevision: 1,
		RelayServiceID: lease.RelayServiceId, RelayID: lease.RelayId, RelayRunID: lease.RelayRunId,
		RelayLeaseRevision: uint64(lease.RelayLeaseRevision), RequestedAt: time.Now(), Nonce: make([]byte, 32), Signature: make([]byte, ed25519.SignatureSize)}
	return acceptor, owner, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.NativeConnector, NativePairLegProof: &proof}
}

// a readable receipt can precede the server's handshake deadline cleanup.
// wait for that cleanup before a test deliberately cancels the serving owner.
type nativeClaimHandshakeSession struct {
	muxsession.Session
	muxsession.AcceptedPeer
	ready chan struct{}
	once  sync.Once
}

func (s *nativeClaimHandshakeSession) AcceptStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return nativeClaimHandshakeStream{Stream: stream, owner: s}, nil
}

type nativeClaimHandshakeStream struct {
	muxsession.Stream
	owner *nativeClaimHandshakeSession
}

func (s nativeClaimHandshakeStream) SetDeadline(at time.Time) error {
	err := s.Stream.SetDeadline(at)
	if at.IsZero() && err == nil {
		s.owner.once.Do(func() { close(s.owner.ready) })
	}
	return err
}

var _ muxsession.AcceptedPeer = (*nativeClaimHandshakeSession)(nil)

// peerNativeHold leaves the acknowledged outer session open so the caller can
// check capacity while another real QUIC or TLS/yamux socket owns a slot.
func peerNativeHold(t *testing.T, kind string, acceptor *PublisherAcceptor, hello tunnelv1.Message, deliveryID ...string) (*tunnel.Session, tunnelv1.NativePairLegAccepted, <-chan error, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)
	root, certificate := testutil.TLSCertificate(t, []string{"relay.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(root) {
		t.Fatal("test root is invalid")
	}
	serverTLS := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
	clientTLS := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	var client muxsession.Session
	var done <-chan error
	endpoint := muxsession.Endpoint{ServerName: "relay.test"}
	handshakeDone := make(chan struct{})
	observe := func(session muxsession.Session) muxsession.Session {
		return &nativeClaimHandshakeSession{Session: session, AcceptedPeer: session.(muxsession.AcceptedPeer), ready: handshakeDone}
	}
	switch kind {
	case "quic":
		listener, err := muxsession.ListenQUIC("127.0.0.1:0", serverTLS, muxsession.QUICConfig{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		endpoint.Address = listener.Addr().String()
		done = relayWorker(t, func() { cancel(); _ = listener.Close() }, func() error {
			accepted, err := listener.Accept(ctx)
			if err != nil {
				return err
			}
			return acceptor.Accept(ctx, observe(accepted))
		})
		client, err = (muxsession.QUICConnector{TLSConfig: clientTLS}).Connect(ctx, endpoint)
		if err != nil {
			t.Fatal(err)
		}
	case "tls_yamux":
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		endpoint.Address = listener.Addr().String()
		done = relayWorker(t, func() { cancel(); _ = listener.Close() }, func() error {
			conn, err := listener.Accept()
			if err != nil {
				return err
			}
			defer conn.Close()
			accepted, err := muxsession.AcceptTLSYamux(ctx, conn, serverTLS, muxsession.TLSYamuxConfig{})
			if err != nil {
				return err
			}
			return acceptor.Accept(ctx, observe(accepted))
		})
		client, err = (muxsession.TLSYamuxConnector{TLSConfig: clientTLS}).Connect(ctx, endpoint)
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unknown socket kind")
	}
	t.Cleanup(func() { _ = client.Close() })
	expected := nativeTestDeliveryID
	if len(deliveryID) != 0 {
		expected = deliveryID[0]
	}
	session, receipt, err := tunnel.DialNative(ctx, client, hello, expected)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-handshakeDone:
	case <-ctx.Done():
		t.Fatal("native claim handshake cleanup did not finish", ctx.Err())
	}
	t.Cleanup(func() { _ = session.Close() })
	return session, receipt, done, cancel
}

func TestNativeConnectorSessionReservations(t *testing.T) {
	var claims atomic.Int32
	claim := nativeClaimFunc(func(_ context.Context, _ relayv1.RelayLease, source netip.Addr, proof tunnelv1.NativePairLegProof, _ []byte) (relayv1.NativePeerPairLegClaim, error) {
		claims.Add(1)
		return nativeTestClaim(source, proof), nil
	})
	acceptor, owner, hello := nativeAdmissionFixture(t, 3, claim)
	observer := new(nativeAdmissionObserver)
	acceptor.observer = observer
	first, _, firstDone, _ := peerNativeHold(t, "quic", acceptor, hello)
	second, _, secondDone, _ := peerNativeHold(t, "tls_yamux", acceptor, hello)
	checkFull := func(name string, message tunnelv1.Message) {
		t.Helper()
		start := time.Now()
		dialErr, acceptErr := peerNativeDial(t, "quic", acceptor, message, nativeTestDeliveryID, false)
		var rejected *tunnel.ProtocolError
		if dialErr == nil || !errors.As(acceptErr, &rejected) || rejected.Code != tunnelv1.CapacityExceeded || time.Since(start) > 3*time.Second {
			t.Fatalf("%s was not promptly rejected: dial=%v accept=%v", name, dialErr, acceptErr)
		}
	}
	checkFull("third session for the same leg", hello)
	if claims.Load() != 2 {
		t.Fatal("per-leg saturation reached control")
	}
	select {
	case <-first.Done():
		t.Fatal("duplicate closed the first owner")
	case <-second.Done():
		t.Fatal("duplicate closed the second owner")
	default:
	}
	otherProof := *hello.NativePairLegProof
	otherProof.PairID = "npp_abcdefghijklmnopqrstuv"
	other := hello
	other.NativePairLegProof = &otherProof
	third, _, thirdDone, thirdCancel := peerNativeHold(t, "quic", acceptor, other)
	checkFull("global saturation on another pair", other)
	if claims.Load() != 3 {
		t.Fatal("global saturation reached control")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := relayAwait(t, firstDone); err != nil {
		t.Fatal(err)
	}
	// releasing one pair does not close or replace a sibling. a new session
	// for the other pair can use the released global reservation.
	fourth, _, fourthDone, fourthCancel := peerNativeHold(t, "tls_yamux", acceptor, other)
	if claims.Load() != 4 {
		t.Fatal("released reservation did not admit the other pair")
	}
	for _, session := range []*tunnel.Session{second, third, fourth} {
		select {
		case <-session.Done():
			t.Fatal("sibling session closed")
		default:
		}
	}
	// cancel without client closes to prove the relay joins held sessions and
	// releases their reservations during shutdown.
	thirdCancel()
	fourthCancel()
	for _, done := range []<-chan error{thirdDone, fourthDone} {
		if err := relayAwait(t, done); err != nil {
			t.Fatal(err)
		}
	}
	_ = second.Close()
	if err := relayAwait(t, secondDone); err != nil {
		t.Fatal(err)
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.sessions != 0 || len(owner.legs) != 0 {
		t.Fatalf("shutdown left native reservations: sessions=%d legs=%d", owner.sessions, len(owner.legs))
	}
	if observer.publisher.Load() != 0 {
		t.Fatal("native outcomes were counted as publisher admissions")
	}
}

func TestNativeConnectorDrainJoinsHeldSession(t *testing.T) {
	var draining atomic.Bool
	claim := nativeClaimFunc(func(_ context.Context, _ relayv1.RelayLease, source netip.Addr, proof tunnelv1.NativePairLegProof, _ []byte) (relayv1.NativePeerPairLegClaim, error) {
		return nativeTestClaim(source, proof), nil
	})
	acceptor, owner, hello := nativeAdmissionFixture(t, 1, claim)
	current := owner.CurrentLease
	owner.CurrentLease = func() relayv1.RelayLease { lease := current(); lease.Draining = draining.Load(); return lease }
	session, _, done, _ := peerNativeHold(t, "quic", acceptor, hello)
	draining.Store(true)
	if err := relayAwait(t, done); err != nil {
		t.Fatal(err)
	}
	relayAwait(t, session.Done())
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.sessions != 0 || len(owner.legs) != 0 {
		t.Fatal("drain left a native reservation")
	}
}

func TestNativeConnectorRejectsMismatchedClaimBeforeReceipt(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*relayv1.NativePeerPairLegClaim)
	}{
		{"delivery ID", func(c *relayv1.NativePeerPairLegClaim) { c.DeliveryId = "malformed" }},
		{"pair", func(c *relayv1.NativePeerPairLegClaim) { c.PairId = "npp_abcdefghijklmnopqrstuv" }},
		{"generation", func(c *relayv1.NativePeerPairLegClaim) { c.DeliveryGeneration++ }},
		{"slot", func(c *relayv1.NativePeerPairLegClaim) { c.ConnectionSlot = 1 }},
		{"source", func(c *relayv1.NativePeerPairLegClaim) { c.SourceIp = "192.0.2.10" }},
		{"expiry", func(c *relayv1.NativePeerPairLegClaim) { c.ExpiresAt = time.Now().Add(-time.Second) }},
		{"missing observation", func(c *relayv1.NativePeerPairLegClaim) { c.ObservedAt = time.Time{} }},
		{"too much authority", func(c *relayv1.NativePeerPairLegClaim) {
			c.ExpiresAt = c.ObservedAt.Add(5*time.Minute + time.Nanosecond)
		}},
		{"malformed key", func(c *relayv1.NativePeerPairLegClaim) { c.Key = "not-a-key" }},
		{"zero key", func(c *relayv1.NativePeerPairLegClaim) {
			c.Key = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			claim := nativeClaimFunc(func(_ context.Context, _ relayv1.RelayLease, source netip.Addr, proof tunnelv1.NativePairLegProof, _ []byte) (relayv1.NativePeerPairLegClaim, error) {
				result := nativeTestClaim(source, proof)
				test.change(&result)
				return result, nil
			})
			acceptor, owner, hello := nativeAdmissionFixture(t, 1, claim)
			dialErr, acceptErr := peerNativeDial(t, "quic", acceptor, hello, nativeTestDeliveryID, false)
			peerNativeAssertDenied(t, dialErr, acceptErr)
			owner.mu.Lock()
			defer owner.mu.Unlock()
			if owner.sessions != 0 || len(owner.legs) != 0 {
				t.Fatal("invalid claim retained a native reservation")
			}
		})
	}
}

type socketIdentityOnly struct{ muxsession.Session }

func (socketIdentityOnly) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
}
func (socketIdentityOnly) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}
func (socketIdentityOnly) TLSConnectionState() tls.ConnectionState { return tls.ConnectionState{} }

func TestNativeConnectorReservesBeforeClaimAndReleasesDenial(t *testing.T) {
	entered, unblock := make(chan struct{}), make(chan struct{})
	var unblockOnce sync.Once
	stop := func() { unblockOnce.Do(func() { close(unblock) }) }
	var calls atomic.Int32
	claim := nativeClaimFunc(func(ctx context.Context, _ relayv1.RelayLease, _ netip.Addr, _ tunnelv1.NativePairLegProof, _ []byte) (relayv1.NativePeerPairLegClaim, error) {
		calls.Add(1)
		close(entered)
		select {
		case <-unblock:
			return relayv1.NativePeerPairLegClaim{}, errors.New("control denied claim")
		case <-ctx.Done():
			return relayv1.NativePeerPairLegClaim{}, ctx.Err()
		}
	})
	_, owner, hello := nativeAdmissionFixture(t, 1, claim)
	var workers sync.WaitGroup
	workers.Add(1)
	done := make(chan error, 1)
	go func() {
		defer workers.Done()
		_, _, err := owner.admit(t.Context(), socketIdentityOnly{}, *hello.NativePairLegProof)
		done <- err
	}()
	t.Cleanup(func() { stop(); workers.Wait() })
	relayAwait(t, entered)
	start := time.Now()
	_, _, err := owner.admit(t.Context(), socketIdentityOnly{}, *hello.NativePairLegProof)
	var rejected *tunnel.ProtocolError
	if !errors.As(err, &rejected) || rejected.Code != tunnelv1.CapacityExceeded || time.Since(start) > time.Second || calls.Load() != 1 {
		t.Fatalf("pending claim did not reserve first: %v, calls=%d", err, calls.Load())
	}
	stop()
	// a control denial must drop the reservation even without an outer session.
	if err := relayAwait(t, done); err == nil {
		t.Fatal("denied control claim succeeded")
	}
	workers.Wait()
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.sessions != 0 || len(owner.legs) != 0 {
		t.Fatalf("denied claim leaked reservation: sessions=%d legs=%d", owner.sessions, len(owner.legs))
	}
}

func TestNativeConnectorDefaultCapacityIsFinite(t *testing.T) {
	owner := new(NativeConnectorAcceptor)
	releases := make([]func(), 0, defaultNativeConnectorSessions)
	for i := range defaultNativeConnectorSessions {
		release, err := owner.reserve(tunnelv1.NativePairLegProof{PairID: fmt.Sprintf("npp_%022d", i), DeliveryGeneration: 1})
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, release)
	}
	if release, err := owner.reserve(tunnelv1.NativePairLegProof{PairID: "npp_abcdefghijklmnopqrstuv", DeliveryGeneration: 1}); err == nil {
		release()
		t.Fatal("default global capacity did not reject the next session")
	}
	for _, release := range releases {
		release()
		release() // a duplicated cleanup cannot release a sibling's slot
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.sessions != 0 || len(owner.legs) != 0 {
		t.Fatal("default reservation cleanup retained sessions")
	}
}
