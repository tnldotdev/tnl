package tnldruntime

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"testing"

	"github.com/tnldotdev/tnl/pkg/api/relayv1"
)

func TestRelayCertificateSourceValidatesAndReloads(t *testing.T) {
	const hostname = "relay-a.example.test"
	certificateFile, privateKeyFile, _ := standaloneTestCertificate(t, hostname)
	certificatePEM, err := os.ReadFile(certificateFile)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPEM, err := os.ReadFile(privateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	keyPair, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	source, err := newRelayCertificateSource("relay-a", hostname)
	if err != nil {
		t.Fatal(err)
	}
	config := source.TLSConfig()
	if _, err := config.GetCertificate(nil); err == nil {
		t.Fatal("empty relay certificate source returned a certificate")
	}
	certificate := relayv1.RelayServiceCertificate{
		RelayServiceId: "relay-a", TlsServerName: hostname,
		CertificatePem: string(certificatePEM), PrivateKeyPem: string(privateKeyPEM), NotAfter: leaf.NotAfter,
	}
	if err := source.Install(certificate); err != nil {
		t.Fatal(err)
	}
	installed, err := config.GetCertificate(nil)
	if err != nil || installed.Leaf == nil || !installed.Leaf.NotAfter.Equal(leaf.NotAfter) {
		t.Fatalf("installed relay certificate = %#v, %v", installed, err)
	}
	certificate.TlsServerName = "relay-b.example.test"
	if err := source.Install(certificate); err == nil {
		t.Fatal("mismatched relay certificate identity was accepted")
	}
}
