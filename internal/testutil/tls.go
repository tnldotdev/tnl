package testutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// TLSCertificate issues a verifiable test leaf, retaining ordinary certificate
// and hostname checks on both native and infrastructure transports.
func TLSCertificate(t *testing.T, names []string, usages []x509.ExtKeyUsage) ([]byte, tls.Certificate) {
	t.Helper()
	now := time.Now()
	rootPublic, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	ca, err := x509.CreateCertificate(rand.Reader, root, root, rootPublic, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), DNSNames: names, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages}
	server, err := x509.CreateCertificate(rand.Reader, leaf, root, public, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca}), tls.Certificate{Certificate: [][]byte{server, ca}, PrivateKey: private}
}
