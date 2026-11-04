package tunnel_test

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorTLSHalfCloseKeepsBoundedRenewalAndResponse(t *testing.T) {
	ca, certificate := testutil.TLSCertificate(t, []string{"service.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid test root")
	}
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			_ = client.SetDeadline(time.Now().Add(3 * time.Second))
			_ = server.SetDeadline(time.Now().Add(3 * time.Second))
			permission := tunnelv1.ConnectorVisitorPermission{Token: "signed-visitor-token", PublicKey: strings.Repeat("A", 43), Signature: strings.Repeat("A", 86)}
			renewed := make(chan struct{}, 1)
			reader := tunnel.NewConnectorRequestReader(server, nil, func(got tunnelv1.ConnectorVisitorPermission) error {
				if got != permission {
					return errors.New("TLS half-close changed renewal permission")
				}
				renewed <- struct{}{}
				return nil
			})
			defer reader.Finish()
			writer := tunnel.NewConnectorRequestWriter(client)
			secured := tls.Client(writer, &tls.Config{MinVersion: version, MaxVersion: version, ServerName: "service.test", RootCAs: roots})
			remote := tls.Server(reader, &tls.Config{MinVersion: version, MaxVersion: version, Certificates: []tls.Certificate{certificate}})
			handshake := make(chan error, 1)
			go func() { handshake <- remote.HandshakeContext(t.Context()) }()
			if err := secured.HandshakeContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := <-handshake; err != nil {
				t.Fatal(err)
			}
			if err := writer.CloseTLSWrite(secured); err != nil {
				t.Fatal(err)
			}
			if n, err := remote.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatal("TLS close_notify did not end application input", n, err)
			}
			reader.ContinueAfterTLSCloseNotify()
			if err := writer.Renew(permission, time.Now().Add(time.Second)); err != nil {
				t.Fatal("TLS close_notify deadline stopped permission renewal", err)
			}
			select {
			case <-renewed:
			case <-time.After(time.Second):
				t.Fatal("TLS half-close stopped the permission frame owner")
			}
			response := make(chan error, 1)
			go func() { _, err := remote.Write([]byte("response")); response <- err }()
			var got [8]byte
			if _, err := io.ReadFull(secured, got[:]); err != nil || string(got[:]) != "response" {
				t.Fatal("TLS half-close truncated the response", err)
			}
			if err := <-response; err != nil {
				t.Fatal(err)
			}
		})
	}
}
