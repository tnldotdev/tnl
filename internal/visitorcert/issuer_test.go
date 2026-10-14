package visitorcert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/opaqueid"
)

func TestVisitorIssuerBindsOnlyVerifiedIdentityAndURL(t *testing.T) {
	seed := bytes.Repeat([]byte{0x6a}, 32)
	issuer, err := New(seed)
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(seed)
	if err != nil || !bytes.Equal(issuer.CertificatePEM(), second.CertificatePEM()) {
		t.Fatalf("control replicas derived different visitor roots: %v", err)
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	maliciousScope, _ := url.Parse("tnl://visitor/url_other/ident_other")
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "claimed administrator"}, URIs: []*url.URL{maliciousScope},
	}, private)
	if err != nil {
		t.Fatal(err)
	}
	publicURLID := opaqueid.PublicURLPrefix + "0123456789abcdefghijkl"
	identityID := opaqueid.IdentityPrefix + "0123456789abcdefghijkl"
	now := time.Date(2026, time.October, 14, 12, 0, 0, 0, time.UTC)
	certificatePEM, err := issuer.Issue(csr, publicURLID, identityID, now.Add(30*24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatal("issuer did not return exactly one certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.IsCA || leaf.Subject.CommonName != "tnl visitor" || len(leaf.URIs) != 1 ||
		leaf.URIs[0].String() != "tnl://visitor/"+publicURLID+"/"+identityID ||
		!leaf.NotAfter.Equal(now.Add(MaxLifetime)) || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("signed certificate escaped visitor scope: %+v", leaf)
	}
	if identity, err := issuer.Identity(leaf, publicURLID, now); err != nil || identity != identityID {
		t.Fatalf("visitor identity = %q, %v", identity, err)
	}
	for _, check := range []struct {
		issuer *Issuer
		urlID  string
		now    time.Time
	}{
		{issuer: issuer, urlID: opaqueid.PublicURLPrefix + "abcdefghijkl0123456789", now: now},
		{issuer: issuer, urlID: publicURLID, now: now.Add(8 * 24 * time.Hour)},
		{issuer: mustIssuer(t, bytes.Repeat([]byte{0x7b}, 32)), urlID: publicURLID, now: now},
	} {
		if identity, err := check.issuer.Identity(leaf, check.urlID, check.now); err == nil || identity != "" {
			t.Fatalf("visitor was accepted for other URL, issuer, or expiry: %q, %v", identity, err)
		}
	}
	csr[len(csr)-1] ^= 1
	if _, err := issuer.Issue(csr, publicURLID, identityID, now.Add(time.Hour), now); err == nil {
		t.Fatal("issuer signed a CSR with an invalid signature")
	}
	shortScope, _ := url.Parse("tnl://visitor/")
	malformed, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(12), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs: []*url.URL{shortScope},
	}, issuer.certificate, &private.PublicKey, issuer.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	badLeaf, err := x509.ParseCertificate(malformed)
	if err != nil {
		t.Fatal(err)
	}
	if identity, err := issuer.Identity(badLeaf, publicURLID, now); err == nil || identity != "" {
		t.Fatalf("malformed URL scope was accepted: %q, %v", identity, err)
	}
}

func mustIssuer(t *testing.T, seed []byte) *Issuer {
	t.Helper()
	issuer, err := New(seed)
	if err != nil {
		t.Fatal(err)
	}
	return issuer
}
