package controlstate

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net/url"
	"testing"
	"time"
)

func TestIntegrationServiceClientCertificateScopeAndRecovery(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "service_client_scope")
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Publishers: map[string]ProjectPublisherGroup{"production": {}}, Services: map[string]ProjectServiceConfiguration{"orders": {Publisher: "production", Protocol: "postgres", Target: "orders.internal:5432"}}}
	applied, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	service := applied.Services[0].ServiceID
	devicePublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := d.EnrollVisitorDevice(t.Context(), r.ActorID, devicePublic, now)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged, _ := url.Parse("tnl://service-client/administrator")
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "administrator"}, DNSNames: []string{"*.unrelated.example"}, URIs: []*url.URL{forged}}, key)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := d.IssueServiceClientCertificate(t.Context(), service, r.ActorID, device.ID, csr, now)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := d.IssueServiceClientCertificate(t.Context(), service, r.ActorID, device.ID, csr, now.Add(time.Second))
	if err != nil || retry != issued {
		t.Fatal("lost certificate response changed the credential", retry, err)
	}
	block, _ := pem.Decode([]byte(issued.CertificatePEM))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.DNSNames) != 0 || len(leaf.URIs) != 1 || leaf.Subject.CommonName == "administrator" || !leaf.NotAfter.Equal(now.Add(7*24*time.Hour)) {
		t.Fatal("CSR claims or decision TTL escaped into the certificate", leaf)
	}
	issuer, err := d.ServiceClientIssuer(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	identity, deviceID, err := issuer.Identity(leaf, service, now)
	if err != nil || identity != r.ActorID || deviceID != device.ID {
		t.Fatal("incorrect client identity scope", identity, deviceID, err)
	}
	rootAgain, err := d.ServiceClientIssuer(t.Context())
	if err != nil || !bytes.Equal(rootAgain.CertificatePEM(), []byte(issued.IssuerPEM)) {
		t.Fatal("control replica would use a different issuer", err)
	}
	outsider := finalVisitorIdentity(t, d, now, "unrelated-client@example.test")
	if _, err = d.IssueServiceClientCertificate(t.Context(), service, outsider, device.ID, csr, now); !errors.Is(err, ErrPrivateServiceAccess) {
		t.Fatal("another identity used this device", err)
	}
	if _, err = d.IssueServiceClientCertificate(t.Context(), service, r.ActorID, device.ID, csr, now.Add(8*24*time.Hour)); !errors.Is(err, ErrPrivateServiceAccess) {
		t.Fatal("expired CSR retry returned unregistered certificate material", err)
	}
	if err = d.RevokeVisitorDevice(t.Context(), r.ActorID, device.ID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = d.IssueServiceClientCertificate(t.Context(), service, r.ActorID, device.ID, csr, now.Add(2*time.Second)); !errors.Is(err, ErrPrivateServiceAccess) {
		t.Fatal("revoked device obtained another certificate", err)
	}
}
