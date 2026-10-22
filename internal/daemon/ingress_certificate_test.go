package daemon

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"

	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func ingressSourceMaterial(t *testing.T, ca *testCertificateAuthority, serial int64) ingressv1.IngressTransportCertificate {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := url.Parse("tnl://ingress/ingress-a/irun_aaaaaaaaaaaaaaaaaaaaaa/1")
	leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"ingress-a.example.test"}, URIs: []*url.URL{identity},
		NotBefore: time.Now().Add(-time.Minute).Truncate(time.Second), NotAfter: time.Now().Add(time.Duration(serial)*time.Minute + time.Hour).Truncate(time.Second),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca.certificate, public, ca.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
	return ingressv1.IngressTransportCertificate{PrivateKeyPem: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})),
		Trust: controlv1.IngressTransportTrust{IngressId: "ingress-a", IngressRunId: "irun_aaaaaaaaaaaaaaaaaaaaaa", IngressLeaseRevision: 1, TlsServerName: "ingress-a.example.test",
			CertificatePem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), IssuerPem: string(ca.certificatePEM), IssuerRevision: 1,
			LeaseUri: identity.String(), PublicKeySha256: hex.EncodeToString(pin[:]), NotBefore: parsed.NotBefore, NotAfter: parsed.NotAfter, ValidUntil: parsed.NotAfter}}
}

func TestIngressCertificateSourceRenewsAndRejectsUnboundMaterial(t *testing.T) {
	ca := newTestCertificateAuthority(t)
	source := &ingressCertificateSource{id: "ingress-a", hostname: "ingress-a.example.test"}
	config := source.TLSConfig()
	if _, err := config.GetCertificate(nil); err == nil {
		t.Fatal("empty ingress source returned certificate material")
	}
	first, second := ingressSourceMaterial(t, ca, 1), ingressSourceMaterial(t, ca, 2)
	if err := source.install(first); err != nil {
		t.Fatal(err)
	}
	old, err := config.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.install(second); err != nil {
		t.Fatal(err)
	}
	current, err := config.GetCertificate(nil)
	if err != nil || current == old || bytes.Equal(current.Certificate[0], old.Certificate[0]) {
		t.Fatal("shared TLS config did not observe renewed control material")
	}
	for name, mutate := range map[string]func(*ingressv1.IngressTransportCertificate){
		"identity": func(value *ingressv1.IngressTransportCertificate) { value.Trust.IngressId = "ingress-b" },
		"hostname": func(value *ingressv1.IngressTransportCertificate) {
			value.Trust.TlsServerName = "ingress-b.example.test"
		},
		"lease-proof": func(value *ingressv1.IngressTransportCertificate) {
			value.Trust.LeaseUri = "tnl://ingress/ingress-a/old/1"
		},
		"key-pin": func(value *ingressv1.IngressTransportCertificate) {
			value.Trust.PublicKeySha256 = hex.EncodeToString(make([]byte, 32))
		},
		"private-key": func(value *ingressv1.IngressTransportCertificate) { value.PrivateKeyPem = first.PrivateKeyPem },
		"issuer": func(value *ingressv1.IngressTransportCertificate) {
			value.Trust.IssuerPem = string(newTestCertificateAuthority(t).certificatePEM)
		},
		"deadline": func(value *ingressv1.IngressTransportCertificate) {
			value.Trust.ValidUntil = time.Now().Add(-time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := second
			mutate(&bad)
			if err := source.install(bad); err == nil {
				t.Fatal("unbound infrastructure material was installed")
			}
			retained, err := config.GetCertificate(nil)
			if err != nil || retained != current {
				t.Fatal("invalid material replaced the last valid certificate")
			}
		})
	}
}
