package ingress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func startSeparatedPublisher(t *testing.T, f *admissionTransportFixture, c publisher.PublicURLServerConfig) {
	t.Helper()
	c.Hostname = "route.example"
	c.PublicURLID = f.entry.PublicUrlId
	c.PublishRunNumber = uint64(f.entry.PublishRunNumber)
	c.PromoteVisitor = tunnel.NewVisitorPromoter(func(v publisher.Visitor) tunnelv1.VisitorStreamHeader { return v.Header }, func(id string) *tunnel.Session {
		if id == f.ref.PublisherConnectionID {
			return f.publisher
		}
		return nil
	})
	r, err := publisher.NewPublicURLServer(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	ingressWorker(t, func() { cancel(); _ = f.publisher.Close() }, func() error { return r.ServePublisherConnection(ctx, f.publisher, f.ref) })
}

func startSeparatedIngress(t *testing.T, f *admissionTransportFixture, port uint16, protocol string) (*Server, string) {
	t.Helper()
	if port != 443 {
		p := int(port)
		f.entry.PublicPort = &p
		value := ingressv1.IngressRoutingTableEntryServiceProtocol(protocol)
		f.entry.ServiceProtocol = &value
	}
	hashedRoutingPolicyForTest(t, &f.entry, "203.0.113.0/24")
	lookup := func() (PublicURL, LookupReason) {
		route, err := f.forwarder.PublicURL(f.entry)
		if err != nil {
			return PublicURL{}, LookupInvalidProjection
		}
		return route, LookupCurrent
	}
	s, address := startIngress(t, Config{RequireProxyHeader: true, Lookup: func(string) (PublicURL, LookupReason) { return lookup() }, LookupPort: func(uint16) (PublicURL, LookupReason) { return lookup() }})
	f.forwarder.SetPromotionHandler(s.PromotePendingAdmission)
	return s, address
}

func separatedVisitor(t *testing.T, address, source string, port uint16) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", address, fixtureTimeout)
	if err != nil {
		t.Fatal(err)
	}
	ownIngressConn(t, c)
	header, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort(source), Destination: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), port)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(header); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSeparatedHTTPDeniedAllowedAndAuthenticatedPromotion(t *testing.T) {
	f := newAdmissionTransportFixture(t)
	run := publisher.PublishRunIdentity{Hostname: "route.example", PublicURLID: f.entry.PublicUrlId, Number: uint64(f.entry.PublishRunNumber)}
	proof, err := publisher.NewReadinessProof(run, "/health")
	if err != nil {
		t.Fatal(err)
	}
	var application atomic.Int32
	startSeparatedPublisher(t, f, publisher.PublicURLServerConfig{Certificate: testCertificate(t, "route.example"), ReadinessProof: proof, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(localproxy.ReadinessProbeHeader) != "" {
			t.Error("proof reached application")
		}
		application.Add(1)
		w.WriteHeader(204)
	})})
	s, address := startSeparatedIngress(t, f, 443, "http")
	for _, test := range []struct {
		source, proof string
		want          int
	}{{"198.51.100.1:40001", "", 403}, {"203.0.113.1:40002", "", 204}, {"198.51.100.2:40003", proof.HeaderValue(), 204}} {
		c := tls.Client(separatedVisitor(t, address, test.source, 443), &tls.Config{ServerName: "route.example", InsecureSkipVerify: true}) // local fixture certificate.
		if err := c.Handshake(); err != nil {
			t.Fatal(err)
		}
		_, err := fmt.Fprintf(c, "GET /health HTTP/1.1\r\nHost: route.example\r\nConnection: close\r\n%s\r\n", func() string {
			if test.proof != "" {
				return localproxy.ReadinessProbeHeader + ": " + test.proof + "\r\n"
			}
			return ""
		}())
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		_ = c.Close()
		if response.StatusCode != test.want {
			t.Fatalf("source %s status %d; want %d", test.source, response.StatusCode, test.want)
		}
	}
	if application.Load() != 2 {
		t.Fatal(application.Load())
	}
	s.mu.Lock()
	pending := len(s.pendingVisitors)
	s.mu.Unlock()
	if pending > 1 {
		t.Fatalf("pending visitor state leaked: %d", pending)
	}
}

func smokeMySQLPacket(sequence byte, payload []byte) []byte {
	return append([]byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), sequence}, payload...)
}
func smokeReadMySQL(c io.Reader) ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return nil, err
	}
	size := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
	if size < 1 || size > 64<<10 {
		return nil, errors.New("invalid smoke packet")
	}
	p := make([]byte, size)
	_, err := io.ReadFull(c, p)
	return p, err
}
func smokeMySQLGreeting() []byte {
	b := append([]byte{10}, []byte("8.0.0\x00")...)
	b = append(b, 1, 0, 0, 0)
	b = append(b, []byte("abcdefgh\x00")...)
	b = append(b, 0xff, 0xf7, 45, 2, 0, 0xff, 0, 21)
	b = append(b, make([]byte, 10)...)
	b = append(b, []byte("ijklmnopqrst\x00caching_sha2_password\x00")...)
	return smokeMySQLPacket(0, b)
}

func TestSeparatedDatabaseDeniedAllowedAndPromotionBeforeAuthentication(t *testing.T) {
	for _, protocol := range []controlv1.PublicURLServiceProtocol{controlv1.Postgres, controlv1.Mysql, controlv1.Redis} {
		for _, test := range []struct {
			name, source string
			authorized   bool
		}{{"allowed", "203.0.113.1:40001", true}, {"denied-authorized", "198.51.100.1:40002", true}, {"denied-refused", "198.51.100.2:40003", false}} {
			t.Run(string(protocol)+"/"+test.name, func(t *testing.T) {
				f := newAdmissionTransportFixture(t)
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
				received := make(chan []byte, 1)
				ingressWorker(t, func() { _ = listener.Close() }, func() error {
					c, err := listener.Accept()
					if err != nil {
						return nil
					}
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(fixtureTimeout))
					if protocol == controlv1.Mysql {
						_, _ = c.Write(smokeMySQLGreeting())
						var h [4]byte
						if _, err := io.ReadFull(c, h[:]); err != nil {
							received <- nil
							return nil
						}
						length := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
						if length < 1 || length > 64<<10 {
							received <- nil
							return nil
						}
						b := make([]byte, 4+length)
						copy(b, h[:])
						_, _ = io.ReadFull(c, b[4:])
						received <- b
						return nil
					}
					b, _ := io.ReadAll(c)
					received <- b
					return nil
				})
				certificate := testCertificate(t, "route.example")
				var authorized atomic.Int32
				startSeparatedPublisher(t, f, publisher.PublicURLServerConfig{Certificate: certificate, ServiceProtocol: protocol, PublicPort: 5432, Target: listener.Addr().String(),
					AuthorizeVisitorCertificate: func(_ context.Context, v publisher.Visitor, state tls.ConnectionState) error {
						authorized.Add(1)
						if !state.HandshakeComplete || len(state.PeerCertificates) != 1 || v.Source.String() != test.source {
							t.Error("untrusted authorization metadata")
						}
						if !test.authorized {
							return errors.New("fixture authorization refused")
						}
						return nil
					}})
				_, address := startSeparatedIngress(t, f, 5432, string(protocol))
				c := separatedVisitor(t, address, test.source, 5432)
				if protocol == controlv1.Postgres {
					_, err = c.Write([]byte{0, 0, 0, 8, 4, 210, 22, 47})
					if err != nil {
						t.Fatal(err)
					}
					var response [1]byte
					if _, err := io.ReadFull(c, response[:]); err != nil || response[0] != 'S' {
						t.Fatalf("postgres TLS startup = %q, %v", response, err)
					}
				}
				if protocol == controlv1.Mysql {
					if _, err := smokeReadMySQL(c); err != nil {
						t.Fatal(err)
					}
					request := make([]byte, 32)
					binary.LittleEndian.PutUint32(request, 1<<11)
					_, err = c.Write(smokeMySQLPacket(1, request))
					if err != nil {
						t.Fatal(err)
					}
				}
				roots := x509.NewCertPool()
				leaf, err := x509.ParseCertificate(certificate.Certificate[0])
				if err != nil {
					t.Fatal(err)
				}
				roots.AddCert(leaf)
				secured := tls.Client(c, &tls.Config{ServerName: "route.example", RootCAs: roots, Certificates: []tls.Certificate{certificate}})
				if err := secured.Handshake(); err != nil {
					t.Fatal(err)
				}
				var auth []byte
				switch protocol {
				case controlv1.Postgres:
					auth = []byte{0, 0, 0, 16, 4, 210, 22, 46, 1, 2, 3, 4, 5, 6, 7, 8}
				case controlv1.Mysql:
					login := make([]byte, 32)
					binary.LittleEndian.PutUint32(login, 1<<11)
					auth = smokeMySQLPacket(2, login)
				case controlv1.Redis:
					auth = []byte("*2\r\n$4\r\nAUTH\r\n$7\r\nfixture\r\n")
				}
				_, _ = secured.Write(auth)
				_ = secured.CloseWrite()
				b := ingressAwait(t, received)
				_ = secured.Close()
				if authorized.Load() != 1 {
					t.Fatal("TLS authorization not reached")
				}
				if !test.authorized {
					if len(b) != 0 {
						t.Fatalf("denied auth reached target: %x", b)
					}
					return
				}
				if protocol == controlv1.Mysql {
					auth = bytes.Clone(auth)
					auth[3] = 1
					binary.LittleEndian.PutUint32(auth[4:8], 0)
				}
				if !bytes.Equal(b, auth) {
					t.Fatalf("authentication = %x; want %x", b, auth)
				}
			})
		}
	}
}
