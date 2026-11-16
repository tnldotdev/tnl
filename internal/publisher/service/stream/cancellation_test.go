package stream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"
)

type streamCloseFailureConn struct {
	net.Conn
	err   error
	calls atomic.Int32
}

func (c *streamCloseFailureConn) Close() error {
	c.calls.Add(1)
	_ = c.Conn.Close()
	return c.err
}

func TestStreamSetupCancellationKeepsPhysicalCloseFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const hostname = "service.example.test"
		certificate := visitorfixture.Certificate(t, hostname)
		raw, peer := net.Pipe()
		defer peer.Close()
		cleanup := errors.New("visitor physical close failed")
		wire := &streamCloseFailureConn{Conn: raw, err: errors.Join(context.Canceled, cleanup)}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		endpoint := Stream{Protocol: config.ProtocolPostgres, Hostname: hostname, Target: "127.0.0.1:1",
			TLS: &tls.Config{Certificates: []tls.Certificate{certificate}},
			Visitor: ConnectorVisitor{Admission: AdmissionFixture{Check: func(context.Context) (Decision, error) {
				return Decision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
			}}}}
		done := make(chan error, 1)
		go func() { done <- endpoint.Forward(ctx, wire) }()
		synctest.Wait()
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) || !errors.Is(err, cleanup) || wire.calls.Load() != 1 {
			t.Fatal("setup lost cleanup failure or repeated physical close", err, wire.calls.Load())
		}
	})
}

func TestStreamCleanupKeepsClosedTargetFailuresAndOperationCause(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "operation failure", true: "cancellation"}[canceled], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const hostname = "service.example.test"
				certificate := visitorfixture.Certificate(t, hostname)
				incoming, visitor := net.Pipe()
				defer visitor.Close()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				operation := errors.New("frontend failed")
				cleanup := []error{errors.New("completed target close failed"), errors.New("active target close failed")}
				var sockets []*streamCloseFailureConn
				endpoint := Stream{Protocol: config.ProtocolHTTP, Hostname: hostname, Target: "127.0.0.1:3000",
					TLS: &tls.Config{Certificates: []tls.Certificate{certificate}},
					Visitor: HTTPVisitor{Frontend: visitorFrontendFunc(func(_ context.Context, _ *tls.Conn, target HTTPTarget) error {
						for index, failure := range cleanup {
							raw, peer := net.Pipe()
							defer peer.Close()
							wire := &streamCloseFailureConn{Conn: raw, err: errors.Join(net.ErrClosed, failure)}
							sockets = append(sockets, wire)
							tracked := target.track(wire)
							if index == 0 {
								// a completed request leaves the live-socket registry before
								// the visitor ends; its failed cleanup still belongs here.
								_ = tracked.Close()
							}
						}
						if canceled {
							cancel()
							return errors.Join(operation, context.Cause(ctx))
						}
						return operation
					})}}
				done := make(chan error, 1)
				go func() { done <- endpoint.Forward(ctx, incoming) }()
				client := tls.Client(visitor, &tls.Config{RootCAs: visitorfixture.Roots(t, certificate), ServerName: hostname})
				if err := client.HandshakeContext(t.Context()); err != nil {
					t.Fatal(err)
				}
				err := <-done
				if !errors.Is(err, operation) || errors.Is(err, context.Canceled) != canceled {
					t.Fatal("cleanup replaced the independent operation cause", err)
				}
				for index, cause := range cleanup {
					if !errors.Is(err, cause) || sockets[index].calls.Load() != 1 {
						t.Fatal("removed or active target cleanup was lost or repeated", err, sockets[index].calls.Load())
					}
				}
			})
		})
	}
}

func TestManagedSetupCancellationClosesBothNativeSockets(t *testing.T) {
	for _, phase := range []string{"mysql greeting", "mysql auth", "postgres negotiation", "postgres auth"} {
		t.Run(phase, func(t *testing.T) {
			root, certificate := testutil.TLSCertificate(t, []string{"service.example.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
			roots := x509.NewCertPool()
			roots.AppendCertsFromPEM(root)
			verifier := &tls.Config{ServerName: "service.example.test", RootCAs: roots}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			target, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			blocked, targetDone := make(chan struct{}), make(chan error, 1)
			go func() {
				conn, err := target.Accept()
				if err != nil {
					targetDone <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				switch phase {
				case "mysql auth":
					_, err = conn.Write(nativeMySQLGreeting())
					if err == nil {
						_, err = targettransport.ReadMySQLPacket(conn, 1<<20)
					}
				case "postgres negotiation":
					var request [8]byte
					_, err = io.ReadFull(conn, request[:])
					if err == nil && request != managedPostgresSSL {
						err = ErrEndpoint
					}
				case "postgres auth":
					var startup [8]byte
					_, err = io.ReadFull(conn, startup[:])
				}
				if err != nil {
					targetDone <- err
					return
				}
				close(blocked)
				var one [1]byte
				_, err = conn.Read(one[:])
				targetDone <- err
			}()
			protocol := config.ProtocolPostgres
			if phase == "mysql greeting" || phase == "mysql auth" {
				protocol = config.ProtocolMySQL
			}
			stream := Stream{Protocol: protocol, Hostname: "service.example.test", Target: target.Addr().String(), TLS: &tls.Config{Certificates: []tls.Certificate{certificate}}, Visitor: ConnectorVisitor{Admission: AdmissionFixture{Check: func(context.Context) (Decision, error) {
				return Decision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
			}}}}
			if phase == "postgres negotiation" {
				stream.TargetTLS = verifier
			}
			front, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer front.Close()
			forwardDone := make(chan error, 1)
			go func() {
				conn, err := front.Accept()
				if err != nil {
					forwardDone <- err
					return
				}
				defer conn.Close()
				forwardDone <- stream.Forward(ctx, conn)
			}()
			client, err := net.DialTimeout("tcp", front.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(3 * time.Second))
			if phase != "mysql greeting" {
				var login []byte
				if protocol == config.ProtocolPostgres {
					_, err = client.Write(managedPostgresSSL[:])
					var accepted [1]byte
					if err == nil {
						_, err = io.ReadFull(client, accepted[:])
					}
					if err == nil && accepted[0] != 'S' {
						err = ErrEndpoint
					}
				} else {
					greeting, readErr := targettransport.ReadMySQLPacket(client, 64<<10)
					err = readErr
					if err == nil {
						login, err = targettransport.MySQLSSLRequest(greeting)
					}
					if err == nil {
						_, err = client.Write(login)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				secured := tls.Client(client, verifier)
				if err := secured.HandshakeContext(t.Context()); err != nil {
					t.Fatal(err)
				}
				if phase == "postgres auth" {
					startup := binary.BigEndian.AppendUint32(nil, 8)
					startup = binary.BigEndian.AppendUint32(startup, 196608)
					_, err = secured.Write(startup)
				} else if protocol == config.ProtocolMySQL {
					login[3] = 2
					_, err = secured.Write(login)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-blocked:
			case err := <-targetDone:
				t.Fatal("target did not reach blocking read", err)
			case <-time.After(3 * time.Second):
				t.Fatal("native setup did not reach target")
			}
			cancel()
			select {
			case err := <-forwardDone:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("setup lost cancellation cause", err)
				}
			case <-time.After(time.Second):
				t.Fatal("setup waited for the ten-second deadline")
			}
			select {
			case err := <-targetDone:
				if !errors.Is(err, io.EOF) {
					t.Fatal("target socket was not closed promptly", err)
				}
			case <-time.After(time.Second):
				t.Fatal("target socket survived canceled setup")
			}
		})
	}
}
