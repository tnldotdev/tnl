package publisher

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/inspection"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func realDatabaseVisitor(t *testing.T, route *PublicURLServer, port uint16) net.Conn {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := l.Accept()
		if err == nil {
			route.handleVisitorHeader(c, false, tunnelv1.VisitorStreamHeader{VisitorConnectionID: "test-visitor"})
		}
	}()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { _ = c.Close(); awaitPublisherTest(t, done) })
	header, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.10:40001"), Destination: netip.AddrPortFrom(netip.MustParseAddr("203.0.113.10"), port)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(header); err != nil {
		t.Fatal(err)
	}
	return c
}

func plaintextCaptureTarget(t *testing.T, greeting []byte) (string, <-chan []byte) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	received := make(chan []byte, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if len(greeting) > 0 {
			_, _ = c.Write(greeting)
		}
		b, _ := io.ReadAll(c)
		received <- b
		_, _ = c.Write([]byte("response-after-eof"))
	}()
	return l.Addr().String(), received
}

func testMySQLGreeting() []byte {
	b := []byte{10}
	b = append(b, []byte("8.0.0\x00")...)
	b = append(b, 1, 0, 0, 0)
	b = append(b, []byte("abcdefgh\x00")...)
	b = append(b, 0xff, 0xf7, 45, 2, 0, 0xff, 0, 21)
	b = append(b, make([]byte, 10)...)
	b = append(b, []byte("ijklmnopqrst\x00caching_sha2_password\x00")...)
	return encodeMySQLPacket(0, b)
}

func TestDatabaseCertificateAuthorizationPrecedesAuthAndPromotion(t *testing.T) {
	for _, protocol := range []controlv1.PublicURLServiceProtocol{controlv1.Postgres, controlv1.Mysql, controlv1.Redis} {
		t.Run(string(protocol), func(t *testing.T) {
			certificate := publicURLTestCertificate(t, "route.example")
			var greeting []byte
			if protocol == controlv1.Mysql {
				greeting = testMySQLGreeting()
			}
			address, received := plaintextCaptureTarget(t, greeting)
			called := make(chan Visitor, 1)
			var promoted atomic.Int32
			route, err := NewPublicURLServer(PublicURLServerConfig{
				Hostname: "route.example", PublicURLID: "public-test", PublishRunNumber: 7,
				ServiceProtocol: protocol, PublicPort: 5432, Target: address, Certificate: certificate,
				AuthorizeVisitorCertificate: func(_ context.Context, visitor Visitor, state tls.ConnectionState) error {
					if !state.HandshakeComplete || len(state.PeerCertificates) != 1 {
						t.Error("certificate hook did not receive completed mutual TLS")
					}
					called <- visitor
					return errors.New("test certificate authorization refused")
				},
				PromoteVisitor: func(context.Context, Visitor) error { promoted.Add(1); return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			defer route.Close()
			visitor := realDatabaseVisitor(t, route, 5432)
			if protocol == controlv1.Postgres {
				_, _ = visitor.Write(postgresSSLRequest[:])
				readDatabaseByte(t, visitor, 'S')
			}
			if protocol == controlv1.Mysql {
				if _, err := readMySQLPacket(visitor, 64<<10); err != nil {
					t.Fatal(err)
				}
				_, _ = visitor.Write(mysqlTestSSLRequest())
			}
			secured := tls.Client(visitor, &tls.Config{ServerName: "route.example", RootCAs: rootsForCertificate(t, certificate), Certificates: []tls.Certificate{certificate}})
			if err := secured.Handshake(); err != nil {
				t.Fatal(err)
			}
			v := awaitPublisherTest(t, called)
			if v.Run.Number != 7 || v.Run.PublicURLID != "public-test" || v.Source.String() != "192.0.2.10:40001" || v.Header.VisitorConnectionID != "test-visitor" {
				t.Fatalf("untrusted visitor identity: %+v", v)
			}
			if b := awaitPublisherTest(t, received); len(b) != 0 || promoted.Load() != 0 {
				t.Fatalf("authentication reached target: %x promotions=%d", b, promoted.Load())
			}
		})
	}
}

func TestPostgresEncryptedCancellationPreservesResponseAfterEOF(t *testing.T) {
	address, received := plaintextCaptureTarget(t, nil)
	certificate := publicURLTestCertificate(t, "route.example")
	var observed atomic.Int32
	var promoted atomic.Int32
	route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", ServiceProtocol: controlv1.Postgres, PublicPort: 5432,
		Target: address, Certificate: certificate, ObserveSummary: func(inspection.Summary) { observed.Add(1) },
		PromoteVisitor: func(context.Context, Visitor) error { promoted.Add(1); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	visitor := realDatabaseVisitor(t, route, 5432)
	_, _ = visitor.Write(postgresSSLRequest[:])
	readDatabaseByte(t, visitor, 'S')
	secured := tls.Client(visitor, &tls.Config{ServerName: "route.example", RootCAs: rootsForCertificate(t, certificate)})
	if err := secured.Handshake(); err != nil {
		t.Fatal(err)
	}
	cancel := make([]byte, 16)
	binary.BigEndian.PutUint32(cancel, 16)
	binary.BigEndian.PutUint32(cancel[4:], 80877102)
	copy(cancel[8:], "secret!!")
	if _, err := secured.Write(cancel); err != nil {
		t.Fatal(err)
	}
	if err := secured.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got := awaitPublisherTest(t, received); !bytes.Equal(got, cancel) {
		t.Fatalf("encrypted cancellation changed: %x", got)
	}
	response, err := io.ReadAll(secured)
	if err != nil || string(response) != "response-after-eof" || observed.Load() != 0 || promoted.Load() != 1 {
		t.Fatalf("response=%q err=%v observed=%d promoted=%d", response, err, observed.Load(), promoted.Load())
	}
}

func TestPostgresPlaintextCancellationNeverForwardsSecretAndWarnsOnce(t *testing.T) {
	certificate := publicURLTestCertificate(t, "route.example")
	var warnings atomic.Int32
	// one publish run serves both attempts, even when no target receives a byte.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	received := make(chan []byte, 2)
	go func() {
		for range 2 {
			c, err := l.Accept()
			if err != nil {
				return
			}
			b, _ := io.ReadAll(c)
			_ = c.Close()
			received <- b
		}
	}()
	route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", ServiceProtocol: controlv1.Postgres, PublicPort: 5432, Target: l.Addr().String(), Certificate: certificate,
		OnWarning: func(warning string) {
			if warning != "plaintext PostgreSQL cancellation was rejected; use a client that encrypts cancellation requests" {
				t.Error("warning is not authored")
			}
			warnings.Add(1)
		}})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	for range 2 {
		visitor := realDatabaseVisitor(t, route, 5432)
		cancel := []byte{0, 0, 0, 16, 4, 210, 22, 46}
		cancel = append(cancel, []byte("secret!!")...)
		_, _ = visitor.Write(cancel)
		_, _ = io.ReadAll(visitor)
		_ = visitor.Close()
		if b := awaitPublisherTest(t, received); len(b) != 0 {
			t.Fatalf("plaintext cancellation secret forwarded: %x", b)
		}
	}
	if warnings.Load() != 1 {
		t.Fatalf("warnings=%d", warnings.Load())
	}
}

func TestReadinessProofIsExactSingleUseAndStripped(t *testing.T) {
	run := PublishRunIdentity{Hostname: "route.example", PublicURLID: "public-test", Number: 8}
	proof, err := NewReadinessProof(run, "/health")
	if err != nil {
		t.Fatal(err)
	}
	secret := proof.HeaderValue()
	var forwarded int
	var promoted int
	var checked int
	route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: run.Hostname, PublicURLID: run.PublicURLID, PublishRunNumber: run.Number, ReadinessProof: proof,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get(localproxy.ReadinessProbeHeader) != "" || !localproxy.IsReadinessProbe(r) {
				t.Error("unverified or unstripped readiness proof")
			}
			forwarded++
			w.WriteHeader(204)
		})})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	for _, test := range []struct {
		method, path, proof string
		status              int
	}{
		{"POST", "/health", secret, 403}, {"GET", "/health?x=1", secret, 403}, {"GET", "/other", secret, 403}, {"GET", "/health", "1", 403},
		{"GET", "/health", secret, 204}, {"GET", "/health", secret, 403},
	} {
		r := httptest.NewRequest(test.method, test.path, nil)
		r.Host = run.Hostname
		r.TLS = &tls.ConnectionState{ServerName: run.Hostname}
		r.Header.Set(localproxy.ReadinessProbeHeader, test.proof)
		r = r.WithContext(context.WithValue(r.Context(), denialContextKey{}, true))
		r = r.WithContext(context.WithValue(r.Context(), visitorSessionKey{}, &visitorSession{visitor: Visitor{Run: run}, guard: func(_ context.Context, v Visitor) error {
			if !v.Readiness {
				t.Error("verified readiness did not reach ownership guard")
			}
			checked++
			return nil
		}, promote: func(context.Context, Visitor) error { promoted++; return nil }}))
		w := httptest.NewRecorder()
		route.http.Handler.ServeHTTP(w, r)
		if w.Code != test.status {
			t.Fatalf("%s %s: status=%d", test.method, test.path, w.Code)
		}
	}
	if forwarded != 1 || promoted != 0 || checked != 1 {
		t.Fatalf("forwarded=%d promoted=%d checked=%d", forwarded, promoted, checked)
	}
	other, _ := NewReadinessProof(run, "/health")
	r := httptest.NewRequest("GET", "/health", nil)
	r.Header.Set(localproxy.ReadinessProbeHeader, other.HeaderValue())
	run.Number++
	if other.consume(r, run) {
		t.Fatal("proof crossed publish runs")
	}
}

func TestHTTPPromotionRunsOncePerVisitorAndBeforeTarget(t *testing.T) {
	var promoted atomic.Int32
	route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", Certificate: publicURLTestCertificate(t, "route.example"),
		PromoteVisitor: func(_ context.Context, v Visitor) error {
			if v.Source.Addr().String() != "192.0.2.10" {
				t.Error("lost trusted visitor source")
			}
			promoted.Add(1)
			return nil
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if promoted.Load() != 1 {
				t.Error("forwarded before promotion")
			}
			w.WriteHeader(204)
		})})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	if err := route.Start(); err != nil {
		t.Fatal(err)
	}
	client := singleConnectionRouteClient(t, route, false)
	for range 2 {
		response, err := client.Get("https://route.example/")
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != 204 {
			t.Fatalf("status=%d", response.StatusCode)
		}
	}
	if promoted.Load() != 1 {
		t.Fatalf("promotions=%d", promoted.Load())
	}
}

func TestHTTPPublisherAcceptsVerifiedTargetTLSServerName(t *testing.T) {
	certificate := publicURLTestCertificate(t, "target.internal")
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.ServerName != "target.internal" {
			t.Error("target TLS name missing")
		}
		w.WriteHeader(204)
	}))
	target.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	target.StartTLS()
	defer target.Close()
	route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", Target: target.URL, TargetTLSName: "target.internal", TargetOptions: localproxy.TargetOptions{RootCAs: rootsForCertificate(t, certificate)}})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "route.example"
	r.TLS = &tls.ConnectionState{ServerName: "route.example"}
	w := httptest.NewRecorder()
	route.http.Handler.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("publisher target TLS status=%d", w.Code)
	}
}
