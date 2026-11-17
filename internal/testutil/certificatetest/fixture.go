// package certificatetest supplies private test CA chains without installing
// machine trust. certificate, storage, publisher and state tests share it.
package certificatetest

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

type Issuer struct {
	Roots *x509.CertPool
	ca    *x509.Certificate
	key   ed25519.PrivateKey
}

type Material struct {
	Chain, Key  []byte
	Certificate tls.Certificate
}

func New(t *testing.T, now time.Time) *Issuer {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return &Issuer{Roots: roots, ca: ca, key: private}
}

func (i *Issuer) Issue(t *testing.T, names []string, now, expires time.Time, change func(*x509.Certificate)) Material {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: names,
		NotBefore: now.Add(-time.Minute), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if change != nil {
		change(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, i.ca, public, i.key)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	material := Material{Chain: append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.ca.Raw})...),
		Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})}
	material.Certificate, err = tls.X509KeyPair(material.Chain, material.Key)
	if err != nil {
		t.Fatal(err)
	}
	return material
}
