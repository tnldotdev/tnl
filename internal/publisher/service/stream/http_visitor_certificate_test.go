package stream_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	visitorissuer "github.com/tnldotdev/tnl/internal/control/certificates/visitor"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
)

func TestPublicHTTPClientCertificateSelection(t *testing.T) {
	policy, update, _ := visitorfixture.Policy(t, true)
	issuer, err := visitorissuer.New(bytes.Repeat([]byte{4}, ed25519.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := visitortoken.KeyDigest(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	workload := visitortoken.Workload{SessionID: "wls_" + strings.Repeat("W", 22), KeySHA256: digest}
	update.View = update.View.WithWorkloadLeases(map[string]visitortoken.WorkloadLease{
		workload.SessionID: {KeySHA256: digest, ExpiresAt: now.Add(time.Minute)},
	})
	if err := policy.Apply(policy.Begin(), update); err != nil {
		t.Fatal(err)
	}
	signer := ed25519.NewKeyFromSeed([]byte(strings.Repeat("h", 32)))
	material, err := issuer.IssueBoundCredential(csr, now.Add(time.Minute), now, func(serial string, _ any, expires time.Time) (visitortoken.Token, error) {
		return visitortoken.SignWorkloadIdentity(update.View.Issuer, "http", signer, visitortoken.WorkloadIdentity{
			Scope: update.View.Scope, Hostname: update.View.Hostname, Port: update.View.Port, ExpiresAt: expires,
			Certificate: visitortoken.Certificate{Serial: serial, KeySHA256: digest, Source: workload},
		}, now)
	})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(material)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	tnl := tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key, Leaf: leaf}
	unrelated := serviceCertificates(t).client
	unrelated.Certificate = unrelated.Certificate[:1]
	server := visitorfixture.Certificate(t, update.View.Hostname)

	for _, test := range []struct {
		name string
		cert tls.Certificate
		send bool
		want visitortoken.Subject
		err  error
	}{
		{name: "unrelated device certificate not selected", cert: unrelated},
		{name: "tnl workload certificate selected and authorized", cert: tnl, send: true, want: visitortoken.Certificate{Serial: leaf.SerialNumber.Text(16), KeySHA256: digest, Source: workload}},
		{name: "unsolicited credential never falls back to anonymous", cert: unrelated, send: true, err: visitortoken.ErrToken},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := make(chan error, 1)
			frontend := httpFrontendFunc(func(_ context.Context, conn *tls.Conn, _ servicestream.HTTPTarget) error {
				state := conn.ConnectionState()
				if (len(state.PeerCertificates) != 0) != test.send {
					t.Error("unexpected certificate possession proof")
				}
				request := visitorfixture.Request()
				request.TLS = &state
				auth, guard, _, err := httpaccess.AuthorizeRequest(httptest.NewRecorder(), request, policy, nil)
				if guard != nil {
					guard.Finish()
				}
				if err == nil && auth.Permission().Facts().Subject != test.want {
					t.Error("HTTP authorization changed the selected subject")
				}
				result <- err
				return nil
			})
			address := managedPublisherListener(t, servicestream.Stream{
				Protocol: config.ProtocolHTTP, Hostname: update.View.Hostname, Handler: http.NotFoundHandler(),
				TLS: &tls.Config{Certificates: []tls.Certificate{server}}, Visitor: servicestream.HTTPVisitor{Frontend: frontend},
			})
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", address, &tls.Config{
				RootCAs: visitorfixture.Roots(t, server), ServerName: update.View.Hostname,
				GetClientCertificate: func(req *tls.CertificateRequestInfo) (*tls.Certificate, error) {
					if len(req.AcceptableCAs) != 1 || !bytes.Equal(req.AcceptableCAs[0], leaf.RawIssuer) {
						t.Error("CertificateRequest did not advertise only the tnl issuer")
					}
					matches := req.SupportsCertificate(&test.cert) == nil
					if matches != (test.want != nil) {
						t.Error("client would select the wrong certificate")
					}
					if test.send {
						return &test.cert, nil
					}
					return &tls.Certificate{}, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			select {
			case err := <-result:
				if !errors.Is(err, test.err) {
					t.Fatalf("HTTP authorization = %v, want %v", err, test.err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("TLS connection did not reach HTTP authorization")
			}
		})
	}
}
