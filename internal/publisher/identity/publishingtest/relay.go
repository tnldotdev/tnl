package publishingtest

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type relaySession struct {
	session *tunnel.Session
	ref     tunnelv1.PublisherConnectionRef
}

func (f *Fixture) startRelay(ctx context.Context, setup controlv1.PublishRunSetup) (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"localhost"}}, key)
	if err != nil {
		return "", err
	}
	issued, err := f.seed.CreateCertificateIssuance(ctx, setup.PublishRun.Id, 1, credentials.PublishRunToken(setup.PublishRunToken), csr, "relay-fixture")
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	certificate, err := tls.X509KeyPair([]byte(*issued.CertificatePem), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		return "", err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	lifetime, cancel := context.WithCancel(f.t.Context())
	var workers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Go(func() {
				defer conn.Close()
				stop := context.AfterFunc(lifetime, func() { _ = conn.Close() })
				defer stop()
				transport, err := muxsession.AcceptTLSYamux(lifetime, conn, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}, muxsession.TLSYamuxConfig{})
				if err != nil {
					return
				}
				session, hello, err := tunnel.Accept(lifetime, transport, func(context.Context, tunnelv1.Message) error { return nil })
				if err != nil {
					return
				}
				defer session.Close()
				f.mu.Lock()
				f.sessions[hello.PublisherConnection.PublicURLID] = relaySession{session, *hello.PublisherConnection}
				f.mu.Unlock()
				_ = session.HandlePublisherDrain(lifetime, func(context.Context) error { return nil })
				// keep the transport alive until the publisher has read its drain
				// acknowledgement and closed, rather than resetting buffered data.
				select {
				case <-session.Done():
				case <-lifetime.Done():
				}
			})
		}
	}()
	f.t.Cleanup(func() { cancel(); _ = listener.Close(); <-done; workers.Wait() })
	return listener.Addr().String(), nil
}

// Visit carries a real HTTPS request through an authenticated publisher
// connection, including the unchanged PROXY v2 boundary and visitor TLS.
func (f *Fixture) Visit(ctx context.Context, address string) (int, []byte, error) {
	u, err := url.Parse(address)
	if err != nil {
		return 0, nil, err
	}
	f.mu.Lock()
	var selected relaySession
	for id, publicURL := range f.routes {
		if publicURL.CanonicalHostname == u.Hostname() {
			selected = f.sessions[id]
			break
		}
	}
	f.mu.Unlock()
	if selected.session == nil {
		return 0, nil, errors.New("publisher connection is not ready")
	}
	id, err := opaqueid.New(opaqueid.VisitorConnectionPrefix)
	if err != nil {
		return 0, nil, err
	}
	r := selected.ref
	sequence := f.visitorSequence.Add(1)
	reservation := tunnelv1.StreamReservation{ID: "sres_" + strings.TrimPrefix(id, "vc_"), AllocationID: "salloc_" + strings.TrimPrefix(r.PublicURLID, "url_"), Slot: sequence % 1024, Sequence: uint64(sequence),
		ResourceKind: "public_url", ResourceID: r.PublicURLID, RunID: r.PublishRunID, RunNumber: r.PublishRunNumber, VisitorConnectionID: id, IngressID: "fixture-ingress", IngressRunID: "fixture-process", IngressLeaseRevision: 1}
	stream, err := selected.session.StartVisitorStream(ctx, tunnelv1.VisitorStreamHeader{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.VisitorStream, VisitorConnectionID: id, Reservation: reservation, PublicURLID: r.PublicURLID, PublishRunID: r.PublishRunID, PublishRunNumber: r.PublishRunNumber, PublisherConnectionID: r.PublisherConnectionID, ConnectionAssignmentRevision: r.ConnectionAssignmentRevision}, nil, nil)
	if err != nil {
		return 0, nil, err
	}
	defer stream.Close()
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = stream.SetDeadline(deadline)
	metadata, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("127.0.0.1:45123"), Destination: netip.MustParseAddrPort("127.0.0.1:443")})
	if err != nil {
		return 0, nil, err
	}
	if _, err := stream.Write(metadata); err != nil {
		return 0, nil, err
	}
	connection := tls.Client(stream, &tls.Config{MinVersion: tls.VersionTLS13, ServerName: u.Hostname()})
	defer connection.Close()
	request, err := http.NewRequestWithContext(ctx, "GET", address, nil)
	if err != nil {
		return 0, nil, err
	}
	request.Close = true
	if err := request.Write(connection); err != nil {
		return 0, nil, err
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	return response.StatusCode, body, err
}
