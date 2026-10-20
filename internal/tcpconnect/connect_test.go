package tcpconnect

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/streamcopy"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type connectorFixture struct {
	device           Signer
	run              Run
	endpoints        [2]muxsession.Endpoint
	localAddress     string
	target           string
	expires          time.Time
	certificate      tls.Certificate
	mu               sync.Mutex
	sessions         [2][]muxsession.Session
	failed           [2]bool
	opened           atomic.Int64
	application      atomic.Int64
	wrongAdmission   atomic.Bool
	wrongCertificate atomic.Bool
	badCertificate   tls.Certificate
	finished         chan struct{}
	serveErr         error
	config           Config
	reuseIDs         [2]string
	assignments      [2]atomic.Int64
}

func connectorID(t *testing.T, prefix string) string {
	t.Helper()
	id, err := opaqueid.New(prefix)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *connectorFixture) PrivateConnectorSigner(context.Context, string) (Signer, error) {
	return f.device, nil
}
func (f *connectorFixture) ResolvePrivateService(context.Context, string) (Run, error) {
	f.mu.Lock()
	run := f.run
	f.mu.Unlock()
	return run, nil
}
func (f *connectorFixture) PrivateConnectorAssignment(ctx context.Context, service string, subject tunnelv1.VisitorSubject, slot uint8) (Assignment, error) {
	f.assignments[slot].Add(1)
	f.mu.Lock()
	failed := f.failed[slot]
	f.mu.Unlock()
	if failed {
		return Assignment{}, errors.New("ingress is down")
	}
	id, err := opaqueid.New(opaqueid.PrivateConnectorSessionPrefix)
	if err != nil {
		return Assignment{}, err
	}
	if f.reuseIDs[slot] != "" {
		id = f.reuseIDs[slot]
	}
	return Assignment{PrivateServiceID: service, SessionID: id, Subject: subject,
		IngressID: []string{"ingress-a", "ingress-b"}[slot],
		Endpoint:  f.endpoints[slot], Credential: strings.Repeat("a", 43), ExpiresAt: f.expires}, nil
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
		run:     Run{PrivateServiceID: connectorID(t, opaqueid.PrivateServicePrefix), PrivateRunID: connectorID(t, opaqueid.PrivateRunPrefix), RunNumber: 3, ValidUntil: now.Add(time.Minute), Protocol: "tcp", TrustRevision: 1, ManagedTLS: &controlv1.ManagedServiceTLS{Hostname: "db.example", Port: 25443}},
		expires: now.Add(time.Minute)}
	f.target = target
	root, certificate := providerCertificate(t)
	f.certificate = certificate
	_, f.badCertificate = testCertificateForUses(t, []string{"other.example"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(root)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
	ctx, cancel := context.WithCancel(t.Context())
	var workers sync.WaitGroup
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
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		f.endpoints[slot] = muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "db.example"}
		if transport == "quic" {
			udp, err := muxsession.ListenPrivateQUIC(listener.Addr().String(), serverTLS, muxsession.QUICConfig{})
			if err != nil {
				t.Fatal(err)
			}
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
					session, err := muxsession.AcceptPrivateMuxTLS(setup, network, serverTLS, muxsession.TLSYamuxConfig{})
					stop()
					if err == nil {
						f.accept(ctx, session, slot)
					}
				})
			}
		})
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ready := make(chan struct{})
	f.finished = make(chan struct{})
	configuration := Config{Control: f, PrivateServiceID: f.run.PrivateServiceID, IdentityID: f.device.Subject.IdentityID, Protocol: "tcp", TrustRevision: 1, TransportTLS: &tls.Config{RootCAs: roots}, Ready: func() error { close(ready); return nil }}
	configuration.ManagedTLS = f.run.ManagedTLS
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
			if f.serveErr != nil && !errors.As(f.serveErr, &reload) {
				t.Errorf("connector shutdown: %v", f.serveErr)
			}
		case <-time.After(3 * time.Second):
			t.Error("connector did not join")
		}
	})
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("two ingress sessions did not become ready")
	}
	f.localAddress = listener.Addr().String()
	return f
}

func (f *connectorFixture) accept(ctx context.Context, transport muxsession.Session, slot uint8) {
	defer transport.Close()
	session, err := tunnel.AcceptPrivateConnector(ctx, transport, func(_ context.Context, hello tunnelv1.PrivateConnectorSessionHello) (tunnelv1.PrivateConnectorSessionAccepted, error) {
		digest, err := hello.Claim().Digest()
		if err != nil || hello.Subject != f.device.Subject || !ed25519.Verify(f.device.PublicKey, digest, hello.Signature) {
			return tunnelv1.PrivateConnectorSessionAccepted{}, ErrPrivateConnection
		}
		return tunnelv1.PrivateConnectorSessionAccepted{ProtocolVersion: tunnelv1.Version, Kind: "private_connector_session_accepted",
			PrivateServiceID: hello.PrivateServiceID, SessionID: hello.SessionID, Subject: hello.Subject, SourceIP: "127.0.0.1", ExpiresAt: f.expires}, nil
	})
	if err != nil {
		return
	}
	f.mu.Lock()
	f.sessions[slot] = append(f.sessions[slot], transport)
	f.mu.Unlock()
	var group sync.WaitGroup
	defer group.Wait()
	for {
		stream, err := session.AcceptStream(ctx)
		if err != nil {
			return
		}
		group.Go(func() { defer stream.Close(); f.visitor(ctx, stream, session.Accepted) })
	}
}

func (f *connectorFixture) visitor(ctx context.Context, stream muxsession.Stream, session tunnelv1.PrivateConnectorSessionAccepted) {
	_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
	entry, err := tunnelv1.ReadPrivateVisitorEntry(stream)
	if err != nil {
		return
	}
	f.mu.Lock()
	run := f.run
	f.mu.Unlock()
	if entry.PrivateServiceID != run.PrivateServiceID || entry.PrivateRunID != run.PrivateRunID || entry.RunNumber != run.RunNumber {
		return
	}
	f.opened.Add(1)
	visitor, _ := opaqueid.New(opaqueid.VisitorConnectionPrefix)
	connection, _ := opaqueid.New(opaqueid.PublisherConnectionPrefix)
	accepted := tunnelv1.PrivateVisitorAccepted{ProtocolVersion: tunnelv1.Version, Kind: "private_visitor_accepted", ConnectorSessionID: session.SessionID, Subject: session.Subject,
		SourceIP: session.SourceIP, VisitorConnectionID: visitor, GrantRevision: 7, PublisherConnectionID: connection, ConnectionAssignmentRevision: 2}
	if f.wrongAdmission.Load() {
		accepted.Subject.DeviceID = "vdev_bbbbbbbbbbbbbbbbbbbbbb"
	}
	if tunnelv1.WritePrivateVisitorAccepted(stream, accepted) != nil {
		return
	}
	certificate := f.certificate
	if f.wrongCertificate.Load() {
		certificate = f.badCertificate
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
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if f.config.Protocol != "tcp" {
		secure := tls.Client(conn, f.config.ServiceTLS.Clone())
		if err := secure.Handshake(); err != nil {
			t.Fatal(err)
		}
		conn = secure
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
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
			if f.opened.Load() != 1 {
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
			f.wrongAdmission.Store(!badPin)
			f.wrongCertificate.Store(badPin)
			local := f.local(t)
			_, _ = local.Write([]byte("must-not-reach-target"))
			_, err := local.Read(make([]byte, 1))
			if err == nil {
				t.Fatal("invalid admission or service certificate forwarded application bytes")
			}
			if f.opened.Load() != 1 || f.application.Load() != 0 {
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
			// admissions alternate: the second stream belongs to slot zero.
			f.mu.Lock()
			f.failed[0] = true
			lost := append([]muxsession.Session(nil), f.sessions[0]...)
			siblings := len(f.sessions[1])
			f.mu.Unlock()
			for _, session := range lost {
				_ = session.Close()
			}
			if _, err := revoked.Read(make([]byte, 1)); err == nil {
				t.Fatal("revoked session retained an active stream")
			}
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
	f := newConfiguredConnectorFixture(t, "quic", "", func(f *connectorFixture, _ *Config) {
		for slot := range uint8(2) {
			f.reuseIDs[slot] = connectorID(t, opaqueid.PrivateConnectorSessionPrefix)
		}
	})
	f.mu.Lock()
	lost := append([]muxsession.Session(nil), f.sessions[0]...)
	f.mu.Unlock()
	for _, session := range lost {
		_ = session.Close()
	}
	deadline := time.Now().Add(2 * time.Second)
	for f.assignments[0].Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.assignments[0].Load() < 3 || len(f.sessions[0]) != 1 || len(f.sessions[1]) != 1 {
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
				if !errors.As(f.serveErr, &reload) || reload.PrivateServiceID != f.run.PrivateServiceID || reload.ApprovedRevision != 1 || reload.SelectedRevision != 2 {
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
