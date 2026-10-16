// package visitorcert owns the private, control-only database visitor issuer.
package visitorcert

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
	"errors"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/opaqueid"
)

const MaxLifetime = 7 * 24 * time.Hour

var ErrInvalidCertificate = errors.New("invalid visitor certificate")

type Issuer struct {
	root *x509.Certificate
	key  ed25519.PrivateKey
}

// New derives the same private issuer on each control replica from its separate
// seed. neither publishers nor ingress/relays receive this seed.
func New(seed []byte) (*Issuer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("visitor issuer seed must contain 32 bytes")
	}
	key := ed25519.NewKeyFromSeed(seed)
	hash := sha256.Sum256(append([]byte("tnl private visitor issuer v1\x00"), key.Public().(ed25519.PublicKey)...))
	hash[0] &= 0x7f
	template := &x509.Certificate{SerialNumber: new(big.Int).SetBytes(hash[:]), Subject: pkix.Name{CommonName: "tnl private visitor issuer"},
		NotBefore: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2044, 1, 1, 0, 0, 0, 0, time.UTC), IsCA: true,
		BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}
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
		return nil, ErrInvalidCertificate
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil {
		return nil, ErrInvalidCertificate
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
		return nil, ErrInvalidCertificate
	}
	return csr, nil
}

// Issue copies only the proven public key, never CSR subjects or extensions.
func (i *Issuer) Issue(der []byte, urlID, identityID string, expires, now time.Time) ([]byte, error) {
	if i == nil || !opaqueid.Valid(urlID, opaqueid.PublicURLPrefix) || !opaqueid.Valid(identityID, opaqueid.IdentityPrefix) || !expires.After(now) {
		return nil, ErrInvalidCertificate
	}
	csr, err := ValidateCSR(der)
	if err != nil {
		return nil, err
	}
	notBefore := now.Add(-time.Minute)
	if expires.After(notBefore.Add(MaxLifetime)) {
		expires = notBefore.Add(MaxLifetime)
	}
	if expires.After(i.root.NotAfter) {
		expires = i.root.NotAfter
	}
	if !expires.After(now) {
		return nil, ErrInvalidCertificate
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	scope := &url.URL{Scheme: "tnl", Host: "visitor", Path: "/" + urlID + "/" + identityID}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "tnl visitor"}, NotBefore: notBefore, NotAfter: expires,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{scope}}
	signed, err := x509.CreateCertificate(rand.Reader, template, i.root, csr.PublicKey, i.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signed}), nil
}

// Identity verifies both issuer and exact control-selected URL scope. TLS must
// already have proved possession of the peer certificate's private key.
func (i *Issuer) Identity(leaf *x509.Certificate, urlID string, now time.Time) (string, error) {
	if i == nil || leaf == nil || !opaqueid.Valid(urlID, opaqueid.PublicURLPrefix) || leaf.IsCA || len(leaf.URIs) != 1 || leaf.NotAfter.Sub(leaf.NotBefore) > MaxLifetime {
		return "", ErrInvalidCertificate
	}
	roots := x509.NewCertPool()
	roots.AddCert(i.root)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return "", ErrInvalidCertificate
	}
	scope := leaf.URIs[0]
	if scope.Scheme != "tnl" || scope.Host != "visitor" || scope.User != nil || scope.RawQuery != "" || scope.Fragment != "" || scope.RawPath != "" || scope.Opaque != "" {
		return "", ErrInvalidCertificate
	}
	identity, found := strings.CutPrefix(scope.Path, "/"+urlID+"/")
	if !found || !opaqueid.Valid(identity, opaqueid.IdentityPrefix) {
		return "", ErrInvalidCertificate
	}
	return identity, nil
}
