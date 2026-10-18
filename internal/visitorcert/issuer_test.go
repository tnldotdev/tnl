package visitorcert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/opaqueid"
)

func TestIssuerReplicaTrustCSRProofAndControlScope(t *testing.T) {
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	seed := bytes.Repeat([]byte{3}, 32)
	issuer, err := New(seed)
	if err != nil {
		t.Fatal(err)
	}
	replica, err := New(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(issuer.CertificatePEM(), replica.CertificatePEM()) {
		t.Fatal("replicas derived different issuer certificates")
	}
	urlID, _ := opaqueid.New(opaqueid.PublicURLPrefix)
	identityID, _ := opaqueid.New(opaqueid.IdentityPrefix)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"forged.test"}, URIs: []*url.URL{{Scheme: "tnl", Host: "visitor", Path: "/forged"}}}, key)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := issuer.Issue(csr, urlID, identityID, now.Add(30*24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(signed)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.DNSNames) != 0 || leaf.IsCA || leaf.NotAfter.Sub(leaf.NotBefore) > MaxLifetime {
		t.Fatal("CSR influenced scope or lifetime")
	}
	if identity, err := replica.Identity(leaf, urlID, now); err != nil || identity != identityID {
		t.Fatal(identity, err)
	}
	wrongURL, _ := opaqueid.New(opaqueid.PublicURLPrefix)
	if _, err := replica.Identity(leaf, wrongURL, now); !errors.Is(err, ErrInvalidCertificate) {
		t.Fatal("wrong scope admitted", err)
	}
	other, _ := New(bytes.Repeat([]byte{4}, 32))
	if _, err := other.Identity(leaf, urlID, now); !errors.Is(err, ErrInvalidCertificate) {
		t.Fatal("foreign issuer admitted", err)
	}
	if _, err := replica.Identity(leaf, urlID, leaf.NotAfter.Add(time.Second)); !errors.Is(err, ErrInvalidCertificate) {
		t.Fatal("expired certificate admitted", err)
	}
	csr[len(csr)-1] ^= 1
	if _, err := issuer.Issue(csr, urlID, identityID, now.Add(time.Hour), now); !errors.Is(err, ErrInvalidCertificate) {
		t.Fatal("wrong CSR signature accepted", err)
	}
}
