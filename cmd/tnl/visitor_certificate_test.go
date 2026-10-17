package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/visitorcert"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type visitorCertificateTestIssuer struct {
	issuer *visitorcert.Issuer
	urlID  string
}

func (i visitorCertificateTestIssuer) IssueVisitorCertificate(_ context.Context, urlID string, csr []byte) (controlv1.VisitorCertificate, error) {
	if i.urlID != "" {
		urlID = i.urlID
	}
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	cert, err := i.issuer.Issue(csr, urlID, "ident_0123456789abcdefghijkl", expires, time.Now())
	return controlv1.VisitorCertificate{PublicUrlId: urlID, CertificatePem: string(cert), IssuerPem: string(i.issuer.CertificatePEM()), ExpiresAt: expires}, err
}

func TestVisitorCertificateIsFreshAndURLBound(t *testing.T) {
	issuer, err := visitorcert.New(make([]byte, ed25519.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	const urlID = "url_0123456789abcdefghijkl"
	first, issued, err := createVisitorCertificate(t.Context(), visitorCertificateTestIssuer{issuer: issuer}, urlID)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := createVisitorCertificate(t.Context(), visitorCertificateTestIssuer{issuer: issuer}, urlID)
	if err != nil {
		t.Fatal(err)
	}
	if first.PrivateKey.(*ecdsa.PrivateKey).Equal(second.PrivateKey) || first.Leaf.URIs[0].Path != "/"+urlID+"/ident_0123456789abcdefghijkl" {
		t.Fatal("visitor identity key reused or certificate has the wrong URL")
	}
	if _, _, err := createVisitorCertificate(t.Context(), visitorCertificateTestIssuer{issuer: issuer, urlID: "url_abcdefghijkl0123456789"}, urlID); !errors.Is(err, visitorcert.ErrInvalidCertificate) {
		t.Fatalf("different URL response accepted: %v", err)
	}
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateVisitorCertificate(issued, wrongKey, urlID, time.Now()); !errors.Is(err, visitorcert.ErrInvalidCertificate) {
		t.Fatalf("different local key accepted: %v", err)
	}
	if _, err := validateVisitorCertificate(issued, first.PrivateKey.(*ecdsa.PrivateKey), urlID, issued.ExpiresAt.Add(time.Second)); !errors.Is(err, visitorcert.ErrInvalidCertificate) {
		t.Fatalf("expired certificate accepted: %v", err)
	}
}
