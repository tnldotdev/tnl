package publisher

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"
)

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
			stream := ServiceStream{Protocol: protocol, Hostname: "service.example.test", Target: target.Addr().String(), TLS: &tls.Config{Certificates: []tls.Certificate{certificate}}, Visitor: ConnectorVisitor{Check: func(context.Context) (ServiceVisitorDecision, error) {
				return ServiceVisitorDecision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
			}}}
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
