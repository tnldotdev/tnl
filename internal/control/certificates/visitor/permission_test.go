package visitor

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func TestVisitorCertificateCarriesSharedTokenAndRequiresTLSKeyPossession(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	issuer, err := New(bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))
	deviceKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, 32))
	deviceDigest, err := visitortoken.KeyDigest(deviceKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	source := visitortoken.Device{IdentityID: "ident_" + strings.Repeat("A", 22), SessionID: "cs_" + strings.Repeat("B", 22), DeviceID: "vdev_" + strings.Repeat("C", 22), KeySHA256: deviceDigest}
	permission := visitortoken.Permission{Scope: visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("D", 22)}, Hostname: "service.example.test", Port: 5432, VisitorPolicyRevision: 3, ExpiresAt: now.Add(time.Minute)}
	view := visitortoken.View{Issuer: "https://control.example.test", Scope: permission.Scope, Hostname: permission.Hostname, Port: permission.Port, VisitorPolicyRevision: 3,
		ObservedAt: now, ValidUntil: now.Add(visitortoken.PolicyLifetime)}.WithVerificationKeys(map[string]ed25519.PublicKey{"visitor-key": key.Public().(ed25519.PublicKey)})
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "untrusted CSR identity"}, DNSNames: []string{"untrusted.example.test"}}, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	material, err := issuer.IssuePermission(csr, permission.ExpiresAt, now, func(serial string, public any, expires time.Time) (visitortoken.Token, error) {
		digest, err := visitortoken.KeyDigest(public)
		if err != nil {
			return "", err
		}
		permission.Subject = visitortoken.Certificate{Serial: serial, KeySHA256: digest, Source: source}
		permission.ExpiresAt = expires
		return visitortoken.Sign(view.Issuer, "visitor-key", key, permission, now)
	})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(material)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.IsCA || len(leaf.DNSNames) != 0 || leaf.Subject.CommonName != "tnl visitor" || len(leaf.URIs) != 1 || leaf.URIs[0].Host != "visitor-token" {
		t.Fatal("CSR names became certificate authority")
	}
	token, err := visitortoken.CertificateToken(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := visitortoken.VerifyBearer(token, view, now); !errors.Is(err, visitortoken.ErrBinding) {
		t.Fatal("certificate token became a bearer credential", err)
	}
	if _, err := visitortoken.VerifyCertificate(token, view, tls.ConnectionState{}, now); !errors.Is(err, visitortoken.ErrBinding) {
		t.Fatal("certificate token skipped TLS possession", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(issuer.CertificatePEM()) {
		t.Fatal("invalid issuer roots")
	}
	verified := make(chan visitortoken.Permission, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "missing visitor TLS", http.StatusForbidden)
			return
		}
		permission, err := visitortoken.VerifyCertificate(token, view, *r.TLS, time.Now())
		if err != nil {
			http.Error(w, "visitor permission denied", http.StatusForbidden)
			return
		}
		verified <- permission.Facts()
		w.WriteHeader(204)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	transport := client.Transport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{leaf.Raw}, PrivateKey: clientKey}}
	client.Transport = transport
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatalf("verified certificate visitor returned %d", response.StatusCode)
	}
	if got := <-verified; got.Subject != permission.Subject || got.Scope != permission.Scope {
		t.Fatal("TLS lost the signed permission binding")
	}
	changed := *leaf
	changed.URIs = nil
	if _, err := visitortoken.CertificateToken(&changed); !errors.Is(err, visitortoken.ErrToken) {
		t.Fatal("legacy certificate became a visitor token", err)
	}
}
