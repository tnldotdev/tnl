package state

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
	"net/url"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func TestIntegrationServiceClientCertificateScopeAndRecovery(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "service_client_scope")
	prepareVisitorTokenKeys(t, d, now)
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}}, Services: map[string]ProjectServiceConfiguration{"orders": {PublisherGroup: "production", Protocol: "postgres", Target: "orders.internal:5432"}}}
	applied, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: applied.Services[0].ServiceID}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := d.EnrollVisitorDevice(t.Context(), r.ActorID, public, now)
	if err != nil {
		t.Fatal(err)
	}
	parent := browserTestControlSession(t, d, r.ActorID, now)
	ctx := WithControlPrincipal(t.Context(), ControlPrincipal{IdentityID: r.ActorID, SessionID: parent.SessionID})
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged, _ := url.Parse("tnl://service-client/administrator")
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "administrator"}, DNSNames: []string{"*.unrelated.example"}, URIs: []*url.URL{forged}}, key)
	if err != nil {
		t.Fatal(err)
	}
	source := DeviceTokenSource{DeviceID: device.ID}
	issued, err := d.IssueVisitorClientCertificate(ctx, testVisitorIssuer, scope, source, csr, now)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := d.IssueVisitorClientCertificate(ctx, testVisitorIssuer, scope, source, csr, now.Add(time.Second))
	if err != nil || retry.CertificatePEM != issued.CertificatePEM || retry.IssuerPEM != issued.IssuerPEM || retry.ServiceID != issued.ServiceID || !retry.ExpiresAt.Equal(issued.ExpiresAt) {
		t.Fatalf("uncertain issuance changed the signed client certificate: certificate=%t issuer=%t expiry=%t error=%v", retry.CertificatePEM == issued.CertificatePEM, retry.IssuerPEM == issued.IssuerPEM, retry.ExpiresAt.Equal(issued.ExpiresAt), err)
	}
	block, _ := pem.Decode([]byte(issued.CertificatePEM))
	if block == nil {
		t.Fatal("issuer omitted certificate material")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.DNSNames) != 0 || len(leaf.URIs) != 1 || leaf.URIs[0].Host != "visitor-token" || leaf.Subject.CommonName == "administrator" || !leaf.NotAfter.Equal(issued.ExpiresAt) || leaf.NotAfter.After(now.Add(visitortoken.RenewableLifetime)) {
		t.Fatal("CSR claims or credential lifetime escaped into the certificate")
	}
	issuer, err := d.ServiceClientIssuer(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if another, err := d.ServiceClientIssuer(t.Context()); err != nil || !bytes.Equal(another.CertificatePEM(), []byte(issued.IssuerPEM)) {
		t.Fatal("control replicas changed client issuer", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(issuer.CertificatePEM()) {
		t.Fatal("client trust is not a certificate")
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		t.Fatal(err)
	}
	actual, subject, err := visitortoken.CertificateIssuanceBinding(chains)
	if err != nil || actual != scope {
		t.Fatal("signed certificate changed its service scope", err)
	}
	if deviceSource, ok := subject.(visitortoken.Device); !ok || deviceSource.IdentityID != r.ActorID || deviceSource.DeviceID != device.ID || deviceSource.SessionID != parent.SessionID {
		t.Fatal("signed certificate changed the authenticated device/session")
	}
	verify := func(at time.Time) error {
		t.Helper()
		tx, err := d.pool.Begin(t.Context())
		if err != nil {
			return err
		}
		defer tx.Rollback(t.Context())
		wire, err := d.readVisitorPolicy(t.Context(), tx, scope, 0, at)
		if err != nil {
			return err
		}
		update, err := visitorlease.Decode(wire)
		if err != nil {
			return err
		}
		token, err := visitortoken.CertificateToken(leaf)
		if err != nil {
			return err
		}
		_, err = visitortoken.VerifyCertificate(token, update.View, tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: chains}, at)
		return err
	}
	if err := verify(now); err != nil {
		t.Fatal("current signed certificate was denied", err)
	}
	outsider := finalVisitorIdentity(t, d, now, "unrelated-client@example.test")
	outsiderParent := browserTestControlSession(t, d, outsider, now)
	outsiderCtx := WithControlPrincipal(t.Context(), ControlPrincipal{IdentityID: outsider, SessionID: outsiderParent.SessionID})
	if _, err := d.IssueVisitorClientCertificate(outsiderCtx, testVisitorIssuer, scope, source, csr, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("another identity borrowed the device key", err)
	}
	if _, err := d.IssueVisitorClientCertificate(ctx, testVisitorIssuer, scope, source, csr, now.Add(8*24*time.Hour)); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("expired source recovered client material", err)
	}
	if err := d.RevokeVisitorDevice(t.Context(), r.ActorID, device.ID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.IssueVisitorClientCertificate(ctx, testVisitorIssuer, scope, source, csr, now.Add(2*time.Second)); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("revoked device obtained another certificate", err)
	}
	if err := verify(now.Add(2 * time.Second)); err == nil {
		t.Fatal("revoked certificate stayed in current local policy")
	}
}
