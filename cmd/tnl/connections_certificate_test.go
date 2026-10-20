package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/connectionruntime"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/visitorcert"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func TestConnectionCredentialSnapshotsRejectAnotherSubjectAndExpiry(t *testing.T) {
	issuer, err := visitorcert.New(make([]byte, ed25519.SeedSize))
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
	service, _ := opaqueid.New(opaqueid.PrivateServicePrefix)
	sessionID, _ := opaqueid.New("wls_")
	now := time.Now().Truncate(time.Second)
	session := authorityv1.WorkloadSession{Id: sessionID, LeaseExpiresAt: now.Add(90 * time.Second), ExpiresAt: now.Add(time.Hour)}
	issue := func(at, expires time.Time) tls.Certificate {
		t.Helper()
		cert, err := issuer.IssueWorkload(csr, service, sessionID, expires, at)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(cert)
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key, Leaf: leaf}
	}
	pair := issue(now, now.Add(60*time.Second))
	if err := validateConnectionWorkloadCertificate(pair, service, session); err != nil {
		t.Fatal(err)
	}
	options, err := connectionruntime.TLSMaterial(pair, "database.example", session.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if options.CA != "" || options.Cert == "" || options.Key == "" {
		t.Fatal("snapshot mixed issuer trust or omitted its key pair")
	}
	other := session
	other.Id, _ = opaqueid.New("wls_")
	if err := validateConnectionWorkloadCertificate(pair, service, other); err == nil {
		t.Fatal("accepted another workload identity")
	}
	if err := validateConnectionWorkloadCertificate(pair, "psvc_other", session); err == nil {
		t.Fatal("accepted another service")
	}
	expired := issue(now.Add(-2*time.Minute), now.Add(-time.Minute))
	if err := validateConnectionWorkloadCertificate(expired, service, session); err == nil {
		t.Fatal("accepted an expired workload certificate")
	}
	if _, err := connectionruntime.TLSMaterial(expired, "database.example", session.ExpiresAt); err == nil {
		t.Fatal("exported expired credential material")
	}
	_, wrongKey, _ := ed25519.GenerateKey(rand.Reader)
	pair.PrivateKey = opaqueConnectionSigner{key}
	if _, err := connectionruntime.TLSMaterial(pair, "database.example", session.ExpiresAt); !errors.Is(err, connectionruntime.ErrTransport) {
		t.Fatal("opaque signer was treated as an exportable snapshot", err)
	}
	pair.PrivateKey = wrongKey
	if _, err := connectionruntime.TLSMaterial(pair, "database.example", session.ExpiresAt); err == nil {
		t.Fatal("exported a mismatched key")
	}
}

type opaqueConnectionSigner struct{ key ed25519.PrivateKey }

func (s opaqueConnectionSigner) Public() crypto.PublicKey { return s.key.Public() }
func (s opaqueConnectionSigner) Sign(reader io.Reader, digest []byte, options crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(reader, digest, options)
}
