// package visitorcert owns control's client-certificate issuer. publishers prove
// key possession in native TLS; control checks the exact service, identity and
// device against current state before permitting application authentication.
package visitor

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/tnldotdev/tnl/internal/security/visitorcert"
)

type Issuer struct {
	root *x509.Certificate
	key  ed25519.PrivateKey
}

func New(seed []byte) (*Issuer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, visitorcert.ErrInvalidCertificate
	}
	key := ed25519.NewKeyFromSeed(seed)
	digest := sha256.Sum256(append([]byte("tnl service client issuer v1\x00"), key.Public().(ed25519.PublicKey)...))
	digest[0] &= 0x7f
	template := &x509.Certificate{SerialNumber: new(big.Int).SetBytes(digest[:]), Subject: pkix.Name{CommonName: "tnl service client issuer"},
		NotBefore: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2044, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, err
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Issuer{root: root, key: key}, nil
}

func (i *Issuer) CertificatePEM() []byte {
	if i == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.root.Raw})
}

func ValidateCSR(der []byte) (*x509.CertificateRequest, error) {
	if len(der) == 0 || len(der) > 8192 {
		return nil, visitorcert.ErrInvalidCertificate
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil {
		return nil, visitorcert.ErrInvalidCertificate
	}
	allowed := false
	switch key := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		allowed = key.Curve == elliptic.P256() || key.Curve == elliptic.P384()
	case ed25519.PublicKey:
		allowed = len(key) == ed25519.PublicKeySize
	case *rsa.PublicKey:
		allowed = key.N.BitLen() >= 2048 && key.N.BitLen() <= 4096 && key.E == 65537
	}
	if !allowed {
		return nil, visitorcert.ErrInvalidCertificate
	}
	return csr, nil
}
