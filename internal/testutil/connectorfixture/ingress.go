package connectorfixture

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// this fixture implements only connector admission and byte forwarding. the
// publisher fixture remains the TLS server and requests no client certificate.
func Ingress(t *testing.T, ca *x509.Certificate, caKey ed25519.PrivateKey, caPEM []byte, service, workload, target string, names ...string) ([]map[string]any, map[string]controlv1.IngressTransportTrust) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	var workers sync.WaitGroup
	t.Cleanup(func() { cancel(); workers.Wait() })
	assignments := []map[string]any{}
	trusts := map[string]controlv1.IngressTransportTrust{}
	if len(names) == 0 {
		names = []string{"ingress-a", "ingress-b"}
	}
	for slot, name := range names {
		public, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		lease, _ := url.Parse("tnl://ingress/" + name + "/irun_aaaaaaaaaaaaaaaaaaaaaa/1")
		leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(slot + 100)), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}, URIs: []*url.URL{lease}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, public, caKey)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		context.AfterFunc(ctx, func() { _ = listener.Close() })
		id, _ := opaqueid.New(opaqueid.ConnectorSessionPrefix)
		expires := time.Now().Add(time.Minute)
		assignments = append(assignments, map[string]any{"id": id, "service_id": service, "ingress_id": name, "ingress_address": listener.Addr().String(), "tls_server_name": "localhost", "credential": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "expires_at": expires})
		trusts[id] = controlv1.IngressTransportTrust{IngressId: name, IngressRunId: "irun_aaaaaaaaaaaaaaaaaaaaaa", IngressLeaseRevision: 1, TlsServerName: "localhost", IssuerPem: string(caPEM), CertificatePem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), PublicKeySha256: hex.EncodeToString(digest[:]), LeaseUri: lease.String(), NotBefore: parsed.NotBefore, NotAfter: parsed.NotAfter, ValidUntil: expires, IssuerRevision: 1}
		workers.Go(func() {
			for {
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				workers.Go(func() {
					defer connection.Close()
					stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
					defer stop()
					transport, err := muxsession.AcceptConnectorMuxTLS(ctx, connection, tlsConfig, muxsession.TLSYamuxConfig{})
					if err != nil {
						return
					}
					defer transport.Close()
					session, err := tunnel.AcceptConnector(ctx, transport, func(_ context.Context, hello tunnelv1.ConnectorSessionHello) (tunnelv1.ConnectorSessionAccepted, error) {
						if hello.SessionID != id || hello.ServiceID != service || hello.Subject.Kind != tunnelv1.VisitorWorkloadSession || hello.Subject.WorkloadSessionID != workload {
							return tunnelv1.ConnectorSessionAccepted{}, io.ErrUnexpectedEOF
						}
						return tunnelv1.ConnectorSessionAccepted{ProtocolVersion: 1, Kind: "connector_session_accepted", ServiceID: service, SessionID: id, Subject: hello.Subject, SourceIP: "127.0.0.1", ExpiresAt: expires}, nil
					})
					if err != nil {
						return
					}
					for {
						stream, err := session.AcceptStream(ctx)
						if err != nil {
							return
						}
						workers.Go(func() {
							defer stream.Close()
							if _, err := tunnelv1.ReadConnectorVisitorEntry(stream); err != nil {
								return
							}
							visitor, _ := opaqueid.New(opaqueid.VisitorConnectionPrefix)
							publisher, _ := opaqueid.New(opaqueid.PublisherConnectionPrefix)
							if err := tunnelv1.WriteConnectorVisitorAccepted(stream, tunnelv1.ConnectorVisitorAccepted{ProtocolVersion: 1, Kind: "connector_visitor_accepted", ConnectorSessionID: id, Subject: session.Accepted.Subject, SourceIP: "127.0.0.1", VisitorConnectionID: visitor, GrantRevision: 1, PublisherConnectionID: publisher, ConnectionAssignmentRevision: 1}); err != nil {
								return
							}
							backend, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", target)
							if err != nil {
								return
							}
							defer backend.Close()
							_, _ = streamcopy.Copy(stream, backend)
						})
					}
				})
			}
		})
	}
	return assignments, trusts
}
