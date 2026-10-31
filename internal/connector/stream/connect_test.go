package stream

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type connectorFixture struct {
	device                Signer
	run                   Run
	endpoints             [2]muxsession.Endpoint
	localAddress          string
	target                string
	expires               time.Time
	certificate           tls.Certificate
	mu                    sync.Mutex
	sessions              [2][]muxsession.Session
	failed                [2]bool
	opened                atomic.Int64
	application           atomic.Int64
	wrongAdmission        atomic.Bool
	wrongCertificate      atomic.Bool
	badCertificate        tls.Certificate
	finished              chan struct{}
	serveErr              error
	wantStartupError      bool
	config                Config
	assignments           [2]atomic.Int64
	startupOpened         int64
	denied                atomic.Bool
	wrongInnerCertificate atomic.Bool
	ctx                   context.Context
	workers               sync.WaitGroup
	peers                 map[string]*fixtureNativePeer
	activationConflict    [2]atomic.Bool
	rejected              [2]atomic.Int64
	helloNonces           [2][][]byte
	tlsGate               *fixtureTLSGate
}

func connectorID(t *testing.T, prefix string) string {
	t.Helper()
	id, err := opaqueid.New(prefix)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *connectorFixture) ConnectorSigner(context.Context, string) (Signer, error) {
	return f.device, nil
}

func (f *connectorFixture) VisitorPermission(context.Context, string) (controlv1.VisitorTokenResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return controlv1.VisitorTokenResponse{Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKindService, Id: f.run.ServiceID}, Hostname: f.run.Endpoint.Hostname, Port: f.run.Endpoint.Port, VisitorToken: "signed-fixture-visitor-permission", ExpiresAt: f.expires}, nil
}
func (f *connectorFixture) ResolveService(context.Context, string) (Run, error) {
	if f.denied.Load() {
		return Run{}, failure.Wrap("resolve service", failure.ServerDenied, io.ErrClosedPipe)
	}
	f.mu.Lock()
	run := f.run
	f.mu.Unlock()
	return run, nil
}
func newConnectorFixture(t *testing.T, transport string, targets ...string) *connectorFixture {
	t.Helper()
	target := ""
	if len(targets) > 0 {
		target = targets[0]
	}
	return newConfiguredConnectorFixture(t, transport, target, nil)
}

func newConfiguredConnectorFixture(t *testing.T, transport, target string, configure func(*connectorFixture, *Config)) *connectorFixture {
	t.Helper()
	_, deviceKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	f := &connectorFixture{device: Signer{Subject: tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, DeviceID: "vdev_aaaaaaaaaaaaaaaaaaaaaa", IdentityID: connectorID(t, opaqueid.IdentityPrefix)}, PublicKey: deviceKey.Public().(ed25519.PublicKey), Sign: func(d []byte) []byte { return ed25519.Sign(deviceKey, d) }},
		run:     Run{ServiceID: connectorID(t, opaqueid.ServicePrefix), ServiceRunID: connectorID(t, opaqueid.ServiceRunPrefix), RunNumber: 3, ValidUntil: now.Add(time.Minute), Protocol: "tcp", TrustRevision: 1, Endpoint: &controlv1.ServiceEndpoint{Hostname: "db.example", Port: 25443}},
		expires: now.Add(time.Minute)}
	f.target = target
	root, certificate := providerCertificate(t)
	f.certificate = certificate
	_, f.badCertificate = testCertificateForUses(t, []string{"other.example"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(root)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
	ctx, cancel := context.WithCancel(t.Context())
	f.ctx, f.peers = ctx, make(map[string]*fixtureNativePeer)
	workers := &f.workers
	t.Cleanup(func() {
		cancel()
		f.mu.Lock()
		for _, sessions := range f.sessions {
			for _, session := range sessions {
				_ = session.Close()
			}
		}
		f.mu.Unlock()
		workers.Wait()
	})
	for slot := range uint8(2) {
		var listener net.Listener
		var udp *muxsession.QUICListener
		// tcp and udp allocate ports independently; keep both listeners on success.
		for range 32 {
			listener, err = net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			if transport != "quic" {
				break
			}
			udp, err = muxsession.ListenQUIC(listener.Addr().String(), serverTLS, muxsession.QUICConfig{Config: fixtureDatagramConfig()})
			if err == nil {
				break
			}
			_ = listener.Close()
			listener = nil
			if !errors.Is(err, syscall.EADDRINUSE) {
				t.Fatal(err)
			}
		}
		if listener == nil {
			t.Fatalf("reserve connector tcp and quic listeners: %v", err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		f.endpoints[slot] = muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "db.example"}
		if udp != nil {
			t.Cleanup(func() { _ = udp.Close() })
			workers.Go(func() {
				for {
					session, err := udp.Accept(ctx)
					if err != nil {
						return
					}
					workers.Go(func() { f.accept(ctx, session, slot) })
				}
			})
		}
		workers.Go(func() {
			for {
				network, err := listener.Accept()
				if err != nil {
					return
				}
				workers.Go(func() {
					setup, stop := context.WithTimeout(ctx, time.Second)
					session, err := muxsession.AcceptTLSYamux(setup, network, serverTLS, muxsession.TLSYamuxConfig{})
					stop()
					if err == nil {
						f.accept(ctx, session, slot)
					}
				})
			}
		})
	}
	f.run.PairReady = &controlv1.NativePeerPairReady{PublisherIdentityId: connectorID(t, opaqueid.PublisherIdentityPrefix)}
	for slot, endpoint := range f.endpoints {
		f.run.PairReady.Relays = append(f.run.PairReady.Relays, controlv1.NativePeerPairRelay{PublisherConnectionId: connectorID(t, opaqueid.PublisherConnectionPrefix), AssignmentRevision: 1, RelayAddress: endpoint.Address, TlsServerName: endpoint.ServerName,
			RelayLease: controlv1.NativePeerRelayLease{RelayServiceId: fmt.Sprintf("relay-%d", slot), RelayId: fmt.Sprintf("node-%d", slot), RelayRunId: fmt.Sprintf("run-%d", slot), RelayLeaseRevision: 1}})
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ready := make(chan struct{})
	f.finished = make(chan struct{})
	configuration := Config{Control: f, ServiceID: f.run.ServiceID, IdentityID: f.device.Subject.IdentityID, Protocol: "tcp", TrustRevision: 1, TransportTLS: &tls.Config{RootCAs: roots}, Ready: func() error { close(ready); return nil }}
	configuration.Endpoint = f.run.Endpoint
	configuration.ServiceTLS = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "db.example"}
	if configure != nil {
		configure(f, &configuration)
	}
	f.config = configuration
	go func() {
		f.serveErr = Serve(ctx, listener, configuration)
		close(f.finished)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-f.finished:
			var reload *MetadataReloadError
			if f.serveErr != nil && !f.wantStartupError && !f.denied.Load() && !errors.As(f.serveErr, &reload) {
				t.Errorf("connector shutdown: %v", f.serveErr)
			}
		case <-time.After(3 * time.Second):
			t.Error("connector did not join")
		}
	})
	select {
	case <-ready:
		if f.wantStartupError {
			t.Fatal("reported readiness before rejecting the native TLS probe")
		}
	case <-f.finished:
		if !f.wantStartupError || f.serveErr == nil {
			t.Fatal("connector failed before readiness", f.serveErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("two native relay carriers did not become ready")
	}
	f.localAddress = listener.Addr().String()
	f.startupOpened = f.opened.Load()
	return f
}

func TestOpaquePreflightVerifiesTLSBeforeReadyWithoutApplicationBytes(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "verified", true: "wrong certificate"}[invalid], func(t *testing.T) {
			f := newConfiguredConnectorFixture(t, "tls_tcp", "", func(f *connectorFixture, c *Config) {
				f.wantStartupError = invalid
				f.wrongCertificate.Store(invalid)
			})
			if f.startupOpened != 1 || f.application.Load() != 0 {
				t.Fatal("readiness did not verify exactly one stream without application bytes")
			}
			if invalid {
				if reason, ok := failure.ReasonOf(f.serveErr); !ok || reason != failure.ConnectionTLSRejected {
					t.Fatal("TLS rejection lost its failure boundary", f.serveErr)
				}
			}
		})
	}
}

func (f *connectorFixture) accept(ctx context.Context, transport muxsession.Session, slot uint8) {
	defer transport.Close()
	var native *fixtureNativePeer
	session, hello, err := tunnel.AcceptWithResult(ctx, transport, func(_ context.Context, hello tunnelv1.Message) (*tunnelv1.NativePairLegAccepted, error) {
		f.assignments[slot].Add(1)
		f.mu.Lock()
		defer f.mu.Unlock()
		proof := hello.NativePairLegProof
		if proof == nil || f.failed[slot] {
			return nil, &tunnel.ProtocolError{Code: tunnelv1.Unavailable}
		}
		native = f.peers[proof.PairID]
		message, err := proof.Message()
		if native == nil || err != nil || proof.ConnectionSlot != int(slot) || !ed25519.Verify(f.device.PublicKey, message, proof.Signature) {
			return nil, &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
		}
		receipt := native.receipt(int(slot))
		return &receipt, nil
	})
	if err != nil {
		return
	}
	f.mu.Lock()
	f.sessions[slot] = append(f.sessions[slot], transport)
	f.helloNonces[slot] = append(f.helloNonces[slot], bytes.Clone(hello.NativePairLegProof.Nonce))
	f.mu.Unlock()
	packets, err := peer.NewSharedSession(ctx, transport)
	if err != nil {
		return
	}
	defer packets.Close()
	id, _ := tunnelv1.ParsePeerDeliveryIdentifier(native.pair.DeliveryId)
	carrier, err := packets.Register(peer.PairBinding{Delivery: tunnelv1.PeerDelivery{Pair: id, Generation: 1}, Key: native.key, Role: 1, Path: slot}, false)
	if err != nil {
		return
	}
	defer carrier.Close()
	_ = session.HandleNativeLegControl(ctx, func(_ context.Context, selection tunnelv1.NativeLegBinding) error {
		if f.activationConflict[slot].Load() {
			f.rejected[slot].Add(1)
			return &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(native.nonces[slot]) != 0 || !selection.Matches(*hello.NativePairLegProof) {
			return &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
		}
		native.nonces[slot] = bytes.Clone(hello.NativePairLegProof.Nonce)
		native.paths[slot] <- carrier
		return nil
	}, func(context.Context, tunnelv1.NativePairLegProof) (tunnelv1.NativePairLegAccepted, error) {
		return native.receipt(int(slot)), nil
	})
}

func (f *connectorFixture) visitor(ctx context.Context, raw muxsession.Stream, native *fixtureNativePeer) {
	stream := net.Conn(raw)
	_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
	entry, initial, err := tunnelv1.ReadNativePeerVisitorOpening(stream)
	if err != nil {
		return
	}
	f.mu.Lock()
	run := f.run
	f.mu.Unlock()
	if f.denied.Load() || entry.ServiceID != run.ServiceID || entry.ServiceRunID != run.ServiceRunID || entry.RunNumber != run.RunNumber || entry.MetadataRevision != uint64(run.TrustRevision) {
		return
	}
	f.opened.Add(1)
	public, _ := base64.RawURLEncoding.DecodeString(entry.Permission.PublicKey)
	signature, _ := base64.RawURLEncoding.DecodeString(entry.Permission.Signature)
	message, proofErr := tunnelv1.NativePeerProofMessage(entry, initial)
	if f.wrongAdmission.Load() || proofErr != nil || !bytes.Equal(public, f.device.PublicKey) || !ed25519.Verify(public, message, signature) || entry.Subject != f.device.Subject || entry.PairID != native.pair.PairId || entry.SourceIP != "127.0.0.1" {
		return
	}
	f.mu.Lock()
	_, replay := native.seen[entry.VisitorConnectionID]
	native.seen[entry.VisitorConnectionID] = struct{}{}
	f.mu.Unlock()
	if replay {
		return
	}
	reader := tunnel.NewNativeRequestReader(raw, initial, func(tunnelv1.NativeVisitorPermission) error { return nil })
	defer reader.Finish()
	stream = reader
	certificate := f.certificate
	if f.wrongCertificate.Load() {
		certificate = f.badCertificate
	}
	f.mu.Lock()
	gate := f.tlsGate
	f.mu.Unlock()
	if gate != nil {
		gate.once.Do(func() { close(gate.entered) })
		select {
		case <-gate.release:
		case <-ctx.Done():
			return
		}
	}
	switch run.Protocol {
	case "postgres":
		var request [8]byte
		if _, err := io.ReadFull(stream, request[:]); err != nil || request != targettransport.PostgresSSLRequest {
			return
		}
		if _, err := stream.Write([]byte{'S'}); err != nil {
			return
		}
	case "mysql":
		// protocol-10 greeting with CLIENT_PROTOCOL_41, CLIENT_SSL and secure
		// connection support; no authentication exchange follows the TLS probe.
		payload := append([]byte{10}, []byte("8.0-fixture\x00")...)
		payload = append(payload, 1, 0, 0, 0)
		payload = append(payload, []byte("12345678")...)
		payload = append(payload, 0, 0, 0x8a, 45, 2, 0, 0, 0)
		payload = append(payload, make([]byte, 11)...)
		payload = append(payload, []byte("abcdefghijkl\x00")...)
		greeting := append([]byte{byte(len(payload)), 0, 0, 0}, payload...)
		if _, err := stream.Write(greeting); err != nil {
			return
		}
		if _, err := targettransport.ReadMySQLPacket(stream, 64<<10); err != nil {
			return
		}
	}
	secure := tls.Server(stream, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.NoClientCert})
	if secure.HandshakeContext(ctx) != nil {
		return
	}
	_ = stream.SetDeadline(time.Time{})
	if f.target != "" {
		target, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", f.target)
		if err != nil {
			return
		}
		defer target.Close()
		stop := context.AfterFunc(ctx, func() { _ = target.Close(); _ = stream.Close() })
		defer stop()
		_, _ = streamcopy.Copy(secure, target)
		return
	}
	buffer := make([]byte, 4096)
	for {
		n, err := secure.Read(buffer)
		if n > 0 {
			f.application.Add(1)
			if _, err := secure.Write(buffer[:n]); err != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (f *connectorFixture) local(t *testing.T) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", f.localAddress, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if f.config.Protocol != "tcp" {
		transport := targettransport.Transport{Protocol: config.ProtocolName(f.config.Protocol), TLS: f.config.ServiceTLS.Clone()}
		if f.config.Protocol == "mysql" {
			greeting, err := targettransport.ReadMySQLPacket(conn, 64<<10)
			if err != nil {
				t.Fatal(err)
			}
			request, err := targettransport.MySQLSSLRequest(greeting)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write(request); err != nil {
				t.Fatal(err)
			}
		}
		var secured net.Conn
		var err error
		if f.config.Protocol == "mysql" {
			secured, err = transport.Handshake(t.Context(), conn)
		} else {
			secured, err = transport.Secure(t.Context(), conn)
		}
		if err != nil {
			t.Fatal(err)
		}
		conn = secured
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestManagedConnectorReadinessAcrossReachabilityAndProtocols(t *testing.T) {
	for _, public := range []bool{false, true} {
		for _, protocol := range []string{"http", "postgres", "mysql", "tcp", "kubernetes"} {
			for _, transport := range []string{"quic", "tls-tcp"} {
				for _, outcome := range []string{"ready", "wrong-tls", "denied"} {
					t.Run(fmt.Sprintf("public=%v/%s/%s/%s", public, protocol, transport, outcome), func(t *testing.T) {
						f := newConfiguredConnectorFixture(t, transport, "", func(f *connectorFixture, c *Config) {
							c.Protocol, f.run.Protocol = protocol, protocol
							f.run.Endpoint.Public = public
							f.wantStartupError = outcome != "ready"
							f.wrongCertificate.Store(outcome == "wrong-tls")
							f.wrongInnerCertificate.Store(outcome == "wrong-tls" && protocol != "tcp")
							f.denied.Store(outcome == "denied")
						})
						wantPaths := int64(1)
						if outcome == "denied" {
							wantPaths = 0
						}
						if f.application.Load() != 0 || f.assignments[0].Load() != wantPaths || f.assignments[1].Load() != wantPaths {
							t.Fatal("readiness sent application bytes or bypassed the two assigned paths")
						}
						if outcome != "ready" {
							reason, _ := failure.ReasonOf(f.serveErr)
							if outcome == "wrong-tls" && reason != failure.ConnectionTLSRejected || outcome == "denied" && (reason != failure.ServerDenied || !errors.Is(f.serveErr, io.ErrClosedPipe)) {
								t.Fatalf("readiness lost its failure classification or cause: %v", f.serveErr)
							}
							return
						}
						wantOpenings := int64(0)
						if protocol == "tcp" {
							wantOpenings = 1
						}
						if f.startupOpened != wantOpenings || f.config.Endpoint.Public != public || f.config.ServiceTLS.ServerName != "db.example" {
							t.Fatal("readiness did not verify the approved endpoint unchanged")
						}
						local := f.local(t)
						_, _ = local.Write([]byte("native"))
						got := make([]byte, 6)
						if _, err := io.ReadFull(local, got); err != nil || string(got) != "native" {
							t.Fatal("native bytes", err)
						}
						// the publisher checks current policy on each native opening;
						// local arrival must not call control to make that decision.
						f.denied.Store(true)
						denied, err := net.DialTimeout("tcp", f.localAddress, time.Second)
						if err != nil {
							t.Fatal(err)
						}
						defer denied.Close()
						_ = denied.SetDeadline(time.Now().Add(time.Second))
						if _, err := denied.Read(make([]byte, 1)); err == nil || f.opened.Load() != 1 {
							t.Fatal("revoked access opened a stream")
						}
					})
				}
			}
		}
	}
}

func TestConnectorTwoAuthenticatedMuxPathsAndSurvivingIngress(t *testing.T) {
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) {
			f := newConnectorFixture(t, transport)
			for range 3 {
				conn := f.local(t)
				if _, err := conn.Write([]byte("opaque-sshd-or-db-auth")); err != nil {
					t.Fatal(err)
				}
				response := make([]byte, len("opaque-sshd-or-db-auth"))
				if _, err := io.ReadFull(conn, response); err != nil || string(response) != "opaque-sshd-or-db-auth" {
					t.Fatalf("private bytes: %q %v", response, err)
				}
				_ = conn.Close()
			}
			f.mu.Lock()
			f.failed[0] = true
			lost := append([]muxsession.Session(nil), f.sessions[0]...)
			healthy := len(f.sessions[1])
			f.mu.Unlock()
			for _, session := range lost {
				_ = session.Close()
			}
			conn := f.local(t)
			_, _ = conn.Write([]byte("surviving"))
			response := make([]byte, 9)
			if _, err := io.ReadFull(conn, response); err != nil || string(response) != "surviving" {
				t.Fatalf("surviving ingress: %q %v", response, err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.sessions[1]) != healthy {
				t.Fatal("healthy ingress session restarted")
			}
		})
	}
}

func TestSingleOpaqueStreamNeverReopensAfterAdmission(t *testing.T) {
	for _, mode := range []string{"cancel-after-bytes", "wrong-admission", "wrong-certificate"} {
		t.Run(mode, func(t *testing.T) {
			f := newConnectorFixture(t, "quic")
			f.wrongAdmission.Store(mode == "wrong-admission")
			f.wrongCertificate.Store(mode == "wrong-certificate")
			local, peer := net.Pipe()
			defer peer.Close()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			configuration := f.config
			configuration.Ready = nil
			go func() { done <- Stream(ctx, local, configuration) }()
			if mode == "cancel-after-bytes" {
				_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := io.WriteString(peer, "one-stream"); err != nil {
					t.Fatal(err)
				}
				response := make([]byte, len("one-stream"))
				if _, err := io.ReadFull(peer, response); err != nil || string(response) != "one-stream" {
					t.Fatal("single stream bytes", err)
				}
				cancel()
			}
			select {
			case err := <-done:
				if mode != "cancel-after-bytes" && err == nil {
					t.Fatal("invalid admission accepted")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("single stream did not join")
			}
			if f.opened.Load() != 2 {
				t.Fatal("single stream replayed admission", f.opened.Load())
			}
			if mode != "cancel-after-bytes" && f.application.Load() != 0 {
				t.Fatal("invalid admission forwarded application bytes")
			}
		})
	}
}

func TestConnectorInvalidAdmissionOrServiceCertificateNeverForwardsOrRetries(t *testing.T) {
	for _, badPin := range []bool{false, true} {
		t.Run(map[bool]string{false: "admission", true: "certificate"}[badPin], func(t *testing.T) {
			f := newConnectorFixture(t, "quic")
			// spend the already admitted ready stream before changing policy/TLS.
			warm := f.local(t)
			_, _ = warm.Write([]byte("warm"))
			if _, err := io.ReadFull(warm, make([]byte, 4)); err != nil {
				t.Fatal(err)
			}
			_ = warm.Close()
			f.application.Store(0)
			f.wrongAdmission.Store(!badPin)
			f.wrongCertificate.Store(badPin)
			local := f.local(t)
			_, _ = local.Write([]byte("must-not-reach-target"))
			_, err := local.Read(make([]byte, 1))
			if err == nil {
				t.Fatal("invalid admission or service certificate forwarded application bytes")
			}
			if f.opened.Load() != 2 || f.application.Load() != 0 {
				t.Fatalf("rejected native stream replayed or forwarded: streams=%d app=%d", f.opened.Load(), f.application.Load())
			}
		})
	}
}

func TestConnectorRevokedSessionStopsOnlyItsActiveStreams(t *testing.T) {
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) {
			f := newConnectorFixture(t, transport)
			healthy := f.local(t)
			check := func(conn net.Conn) {
				_, _ = conn.Write([]byte("live"))
				if _, err := io.ReadFull(conn, make([]byte, 4)); err != nil {
					t.Fatal(err)
				}
			}
			check(healthy)
			revoked := f.local(t)
			check(revoked)
			// both active streams belong to the retained native owner, not either
			// packet carrier. losing a carrier must not revoke or replay them.
			f.mu.Lock()
			f.failed[0] = true
			lost := append([]muxsession.Session(nil), f.sessions[0]...)
			siblings := len(f.sessions[1])
			f.mu.Unlock()
			for _, session := range lost {
				_ = session.Close()
			}
			check(revoked)
			_, _ = healthy.Write([]byte("still live"))
			got := make([]byte, len("still live"))
			if _, err := io.ReadFull(healthy, got); err != nil || string(got) != "still live" {
				t.Fatalf("healthy sibling was stopped: %q %v", got, err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.opened.Load() != 2 || len(f.sessions[1]) != siblings {
				t.Fatal("revoked stream replayed or restarted its healthy sibling")
			}
		})
	}
}

func TestConnectorNeverRetriesAnAttemptedAssignment(t *testing.T) {
	// losing a prepared carrier cannot repeat a hello or reopen its sibling.
	f := newConnectorFixture(t, "quic")
	f.mu.Lock()
	lost := append([]muxsession.Session(nil), f.sessions[0]...)
	f.mu.Unlock()
	for _, session := range lost {
		_ = session.Close()
	}
	local := f.local(t)
	if _, err := local.Write([]byte("retained")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(local, make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.assignments[0].Load() != 1 || len(f.sessions[0]) != 1 || len(f.sessions[1]) != 1 {
		t.Fatal("an attempted credential was reused or the healthy sibling restarted")
	}
}

func TestConnectorRejectsStaleApprovedRevisionBeforeOpeningStream(t *testing.T) {
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) {
			f := newConnectorFixture(t, transport)
			active := f.local(t)
			_, _ = active.Write([]byte("old"))
			if _, err := io.ReadFull(active, make([]byte, 3)); err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			f.run.TrustRevision++
			f.mu.Unlock()
			local := f.local(t)
			_, _ = local.Write([]byte("must-not-reach-target"))
			if _, err := local.Read(make([]byte, 1)); err == nil || f.opened.Load() != 1 {
				t.Fatal("stale approved metadata opened an application stream")
			}
			select {
			case <-f.finished:
				var reload *MetadataReloadError
				if !errors.As(f.serveErr, &reload) || reload.ServiceID != f.run.ServiceID || reload.ApprovedRevision != 1 || reload.SelectedRevision != 2 {
					t.Fatalf("missing metadata reload signal: %v", f.serveErr)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("stale runner remained ready")
			}
			if _, err := active.Read(make([]byte, 1)); err == nil {
				t.Fatal("old runner kept an active stream")
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			done, ready := make(chan error, 1), make(chan struct{})
			fresh := f.config
			fresh.TrustRevision, fresh.Ready = 2, func() error { close(ready); return nil }
			go func() { done <- Serve(ctx, listener, fresh) }()
			t.Cleanup(func() { cancel(); <-done })
			select {
			case <-ready:
			case <-time.After(5 * time.Second):
				t.Fatal("fresh approved runner did not become ready")
			}
			f.localAddress = listener.Addr().String()
			conn := f.local(t)
			_, _ = conn.Write([]byte("fresh"))
			got := make([]byte, 5)
			if _, err := io.ReadFull(conn, got); err != nil || string(got) != "fresh" || f.opened.Load() != 2 {
				t.Fatalf("fresh runner reused old traffic: %q streams=%d err=%v", got, f.opened.Load(), err)
			}
		})
	}
}

func TestConnectorPreservesNativeBytesForHTTPAndTCP(t *testing.T) {
	for _, protocol := range []string{"http", "tcp"} {
		t.Run(protocol, func(t *testing.T) {
			f := newConfiguredConnectorFixture(t, "quic", "", func(f *connectorFixture, configuration *Config) {
				configuration.Protocol, configuration.TrustRevision = protocol, 2
				f.run.Protocol, f.run.TrustRevision = protocol, 2
			})
			local := f.local(t)
			// deliberately not HTTP or a TLS handshake: omitted TLS must carry
			// native application bytes without parsing or a stale local wrapper.
			payload := []byte{0, 1, 2, 255, 3}
			_, _ = local.Write(payload)
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(local, got); err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("removed TLS retained stale settings: %x %v", got, err)
			}
		})
	}
}
