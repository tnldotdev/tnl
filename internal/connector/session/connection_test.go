package session

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func sessionCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"service.example.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}

func testSessionConn(t *testing.T, protocol string, roots *x509.CertPool) (*Conn, *pipeConn) {
	t.Helper()
	app, server := newPipe()
	ctx, cancel := context.WithCancel(t.Context())
	owner := &Connection{
		metadata: controlv1.ServiceSummary{Protocol: controlv1.ServiceProtocol(protocol), Endpoint: &controlv1.ServiceEndpoint{Hostname: "service.example.test"}},
		trust:    &tls.Config{RootCAs: roots, ServerName: "service.example.test", MinVersion: tls.VersionTLS12},
		streams:  map[*Conn]struct{}{},
	}
	s := &Conn{Conn: app, raw: app, owner: owner, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	owner.streams[s] = struct{}{}
	t.Cleanup(func() { _ = app.Close(); _ = server.Close(); cancel() })
	return s, server
}

func mysqlSSLRequest() []byte {
	request := make([]byte, 36)
	request[0], request[3], request[12] = 32, 1, 45
	binary.LittleEndian.PutUint32(request[4:8], targettransport.MySQLClientSSL|targettransport.MySQLClientProtocol41)
	binary.LittleEndian.PutUint32(request[8:12], 1<<20)
	return request
}

func TestSessionProtocolTLSNegotiation(t *testing.T) {
	certificate, roots := sessionCertificate(t)
	for _, protocol := range []string{"http", "kubernetes", "postgres", "mysql"} {
		t.Run(protocol, func(t *testing.T) {
			s, server := testSessionConn(t, protocol, roots)
			finished := make(chan error, 1)
			go func() {
				defer close(s.done)
				if protocol == "postgres" {
					var request [8]byte
					if _, err := io.ReadFull(server, request[:]); err != nil {
						finished <- err
						return
					}
					if request != targettransport.PostgresSSLRequest {
						finished <- errors.New("wrong PostgreSQL SSLRequest")
						return
					}
					if _, err := server.Write([]byte{'S'}); err != nil {
						finished <- err
						return
					}
				}
				if protocol == "mysql" {
					if _, err := server.Write([]byte("server greeting")); err != nil {
						finished <- err
						return
					}
					request := make([]byte, 36)
					if _, err := io.ReadFull(server, request); err != nil {
						finished <- err
						return
					}
					if !bytes.Equal(request, mysqlSSLRequest()) {
						finished <- errors.New("driver MySQL capabilities changed")
						return
					}
				}
				secured := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
				if err := secured.HandshakeContext(t.Context()); err != nil {
					finished <- err
					return
				}
				var data [4]byte
				if _, err := io.ReadFull(secured, data[:]); err != nil {
					finished <- err
					return
				}
				if string(data[:]) != "ping" {
					finished <- errors.New("wrong application bytes")
					return
				}
				_, err := secured.Write([]byte("pong"))
				finished <- err
			}()
			if _, err := s.Write([]byte("login must not escape")); err == nil {
				t.Fatal("accepted pre-TLS application bytes")
			}
			if protocol == "mysql" {
				greeting := make([]byte, len("server greeting"))
				if _, err := io.ReadFull(s, greeting); err != nil {
					t.Fatal(err)
				}
				request := mysqlSSLRequest()
				for _, part := range [][]byte{request[:3], request[3:11], request[11:]} {
					if _, err := s.Write(part); err != nil {
						t.Fatal("fragmented MySQL SSLRequest", err)
					}
				}
			}
			if err := s.StartTLS(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			var data [4]byte
			if _, err := io.ReadFull(s, data[:]); err != nil || string(data[:]) != "pong" {
				t.Fatal(string(data[:]), err)
			}
			if err := <-finished; err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if err := s.StartTLS(t.Context(), nil); err == nil {
				t.Fatal("closed stream upgraded again")
			}
		})
	}
}

func TestSessionTLSRejectsWrongHostname(t *testing.T) {
	certificate, roots := sessionCertificate(t)
	s, server := testSessionConn(t, "http", roots)
	s.owner.trust.ServerName = "another.example.test"
	finished := make(chan error, 1)
	go func() {
		defer close(s.done)
		finished <- tls.Server(server, &tls.Config{Certificates: []tls.Certificate{certificate}}).HandshakeContext(t.Context())
	}()
	if err := s.StartTLS(t.Context(), nil); err == nil {
		t.Fatal("accepted another service's certificate")
	}
	if err := <-finished; err == nil {
		t.Fatal("server did not observe handshake rejection")
	}
	_ = s.Close()
}

func TestSessionPipeHalfCloseKeepsResponseDirection(t *testing.T) {
	left, right := newPipe()
	defer left.Close()
	defer right.Close()
	if err := left.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := right.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal("missing half-close EOF", err)
	}
	done := make(chan error, 1)
	go func() { _, err := right.Write([]byte("response")); done <- err }()
	data := make([]byte, 8)
	if _, err := io.ReadFull(left, data); err != nil || string(data) != "response" {
		t.Fatal(string(data), err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSessionCloseClassificationKeepsIndependentCleanup(t *testing.T) {
	independent := errors.New("independent cleanup failed")
	for _, err := range []error{
		errors.Join(context.Canceled, independent),
		&connectorstream.CleanupError{Err: context.Canceled},
		errors.Join(net.ErrClosed, &connectorstream.CleanupError{Err: io.ErrClosedPipe}),
		io.EOF,
		&tls.RecordHeaderError{Msg: "independent TLS failure"},
		connectorstream.ErrServiceConnection,
		&quic.StreamError{Remote: true, ErrorCode: 7},
		&quic.StreamError{ErrorCode: 9},
		net.ErrClosed,
	} {
		s, _ := testSessionConn(t, "tcp", nil)
		s.forwardErr = err
		close(s.done)
		if got := s.Close(); !errors.Is(got, err) {
			t.Fatal("cleanup failure hidden by local cancellation", got)
		}
	}
}

type orderedSession struct {
	ctx    context.Context
	active atomic.Int32
	err    error
}

func (s *orderedSession) Context() context.Context { return s.ctx }
func (s *orderedSession) Forward(ctx context.Context, local net.Conn) error {
	s.active.Add(1)
	defer s.active.Add(-1)
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(stopped); _ = local.Close() })
	_, _ = local.Read(make([]byte, 1))
	<-ctx.Done()
	if !stop() {
		<-stopped
	}
	if s.ctx.Err() != nil {
		return errors.New("retained session canceled before stream joined")
	}
	return s.err
}
func (s *orderedSession) Close() error {
	if s.active.Load() != 0 {
		return errors.New("retained session closed before stream joined")
	}
	return nil
}

func TestSessionCloseJoinsConcurrentIOBeforeRetainedSession(t *testing.T) {
	for _, parent := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicit", true: "parent"}[parent], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.WithoutCancel(t.Context()))
			engine := &orderedSession{ctx: ctx}
			connection := newConnection(ctx, cancel, engine, controlv1.ServiceSummary{
				Protocol: "tcp", Endpoint: &controlv1.ServiceEndpoint{Hostname: "service.example.test"},
			}, &tls.Config{})
			defer connection.Close()
			lifetime, stop := context.WithCancel(t.Context())
			defer stop()
			connection.followLifetime(lifetime)
			stream, err := connection.Open(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			read, write := make(chan error, 1), make(chan error, 1)
			go func() { _, err := stream.Read(make([]byte, 1)); read <- err }()
			go func() { _, err := stream.Write([]byte("pending write")); write <- err }()
			if parent {
				stop()
			}
			if err := connection.Close(); err != nil {
				t.Fatal(err)
			}
			for _, result := range []<-chan error{read, write} {
				select {
				case <-result:
				case <-time.After(time.Second):
					t.Fatal("close did not join blocked application I/O")
				}
			}
			if engine.active.Load() != 0 || ctx.Err() == nil {
				t.Fatal("close did not finish stream work and retained lifetime")
			}
			if _, err := connection.Open(t.Context()); !errors.Is(err, net.ErrClosed) {
				t.Fatal("closed connection admitted work", err)
			}
		})
	}
}

func TestSessionPipeAbortProvenanceDoesNotOwnEarlierClose(t *testing.T) {
	for _, earlierClose := range []bool{false, true} {
		left, right := newPipe()
		if earlierClose {
			_ = right.Close()
		}
		_ = left.Abort(context.Canceled)
		_, err := left.Write([]byte("output"))
		if left.OwnsAbortError(err) == earlierClose {
			t.Fatal("abort provenance confused an earlier peer close", earlierClose, err)
		}
		if left.OwnsAbortError(io.ErrClosedPipe) || left.OwnsAbortError(errors.Join(err, io.EOF)) {
			t.Fatal("abort provenance claimed an independent error")
		}
		_ = left.Close()
		_ = right.Close()
	}
}

type halfCloseSession struct {
	ctx    context.Context
	target *pipeConn
}

func (s *halfCloseSession) Context() context.Context { return s.ctx }
func (s *halfCloseSession) Close() error             { return s.target.Close() }
func (s *halfCloseSession) Forward(_ context.Context, local net.Conn) error {
	_, err := streamcopy.Copy(local, s.target)
	return err
}

func TestSessionStreamHalfCloseJoinsFinalResponse(t *testing.T) {
	target, peer := newPipe()
	defer peer.Close()
	ctx, cancel := context.WithCancel(t.Context())
	connection := newConnection(ctx, cancel, &halfCloseSession{ctx: ctx, target: target}, controlv1.ServiceSummary{
		Protocol: "tcp", Endpoint: &controlv1.ServiceEndpoint{Hostname: "service.example.test"},
	}, &tls.Config{})
	defer connection.Close()
	stream, err := connection.Open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan error, 1)
	go func() {
		request, err := io.ReadAll(peer)
		if err != nil || string(request) != "request" {
			done <- errors.Join(err, errors.New("request did not precede half-close"))
			return
		}
		_, err = peer.Write([]byte("final response"))
		done <- errors.Join(err, peer.CloseWrite())
	}()
	if _, err := stream.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(stream)
	if err != nil || string(response) != "final response" {
		t.Fatal("half-close discarded the final response", string(response), err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal("clean completed stream failed close", err)
	}
	if err := stream.CloseWrite(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed stream accepted a half-close", err)
	}
}

func TestSessionMySQLSSLRequestValidation(t *testing.T) {
	valid := mysqlSSLRequest()
	if !validMySQLSSLRequest(valid) {
		t.Fatal("valid SSLRequest rejected")
	}
	for _, index := range []int{0, 1, 2, 3, 13, 35} {
		invalid := bytes.Clone(valid)
		invalid[index]++
		if validMySQLSSLRequest(invalid) {
			t.Fatalf("accepted malformed byte %d", index)
		}
	}
}
