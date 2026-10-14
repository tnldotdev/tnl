// package visitorcert issues short-lived, URL-bound client certificates for database visitors.
package visitorcert

import (
	"crypto"
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
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/opaqueid"
)

const MaxLifetime = 7 * 24 * time.Hour

var ErrInvalidCertificate = errors.New("invalid visitor certificate")

type Issuer struct {
	certificate *x509.Certificate
	privateKey  ed25519.PrivateKey
}

// New loads a dedicated 32-byte issuer seed; all control processes with the
// same seed derive the same private CA, independently of public URL ACME keys.
func New(seed []byte) (*Issuer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("visitor issuer seed must contain 32 bytes")
	}
	key := ed25519.NewKeyFromSeed(seed)
	serial := sha256.Sum256(append([]byte("tnl visitor issuer v1\x00"), key.Public().(ed25519.PublicKey)...))
	serial[0] &= 0x7f
	root := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(serial[:]),
		Subject:      pkix.Name{CommonName: "tnl private visitor issuer"},
		NotBefore:    time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2044, time.January, 1, 0, 0, 0, 0, time.UTC),
		IsCA:         true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	encoded, err := x509.CreateCertificate(rand.Reader, root, root, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("create visitor issuer: %w", err)
	}
	parsed, err := x509.ParseCertificate(encoded)
	if err != nil {
		return nil, fmt.Errorf("parse visitor issuer: %w", err)
	}
	return &Issuer{certificate: parsed, privateKey: key}, nil
}

func (i *Issuer) CertificatePEM() []byte {
	if i == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.certificate.Raw})
}

// Issue signs a client's CSR without copying its subject or extensions. the
// private key stays on the visitor's machine; the caller must check current
// identity and public URL access before calling this method.
func (i *Issuer) Issue(csrDER []byte, publicURLID, identityID string, expiresAt, now time.Time) ([]byte, error) {
	if i == nil || !opaqueid.Valid(publicURLID, opaqueid.PublicURLPrefix) ||
		!opaqueid.Valid(identityID, opaqueid.IdentityPrefix) || !expiresAt.After(now) || len(csrDER) > 8<<10 {
		return nil, ErrInvalidCertificate
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || csr.CheckSignature() != nil || !allowedPublicKey(csr.PublicKey) {
		return nil, ErrInvalidCertificate
	}
	serial := make([]byte, 20)
	if _, err := rand.Read(serial); err != nil {
		return nil, fmt.Errorf("create visitor certificate serial: %w", err)
	}
	serial[0] &= 0x7f
	notBefore := now.Add(-time.Minute)
	if expiresAt.After(notBefore.Add(MaxLifetime)) {
		expiresAt = notBefore.Add(MaxLifetime)
	}
	if expiresAt.After(i.certificate.NotAfter) {
		expiresAt = i.certificate.NotAfter
	}
	if !expiresAt.After(now) {
		return nil, ErrInvalidCertificate
	}
	scope, err := url.Parse("tnl://visitor/" + publicURLID + "/" + identityID)
	if err != nil {
		return nil, ErrInvalidCertificate
	}
	template := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(serial),
		Subject:      pkix.Name{CommonName: "tnl visitor"},
		NotBefore:    notBefore, NotAfter: expiresAt,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, URIs: []*url.URL{scope},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, i.certificate, csr.PublicKey, i.privateKey)
	if err != nil {
		return nil, fmt.Errorf("sign visitor certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func allowedPublicKey(value crypto.PublicKey) bool {
	switch key := value.(type) {
	case *ecdsa.PublicKey:
		return key.Curve == elliptic.P256() || key.Curve == elliptic.P384()
	case ed25519.PublicKey:
		return true
	case *rsa.PublicKey:
		return key.N.BitLen() >= 2048 && key.N.BitLen() <= 4096 && key.E == 65537
	default:
		return false
	}
}

// Identity verifies the client-auth chain and exact public URL scope. the
// caller must then recheck current identity and grant state before forwarding.
func (i *Issuer) Identity(leaf *x509.Certificate, publicURLID string, now time.Time) (string, error) {
	if i == nil || leaf == nil || !opaqueid.Valid(publicURLID, opaqueid.PublicURLPrefix) {
		return "", ErrInvalidCertificate
	}
	roots := x509.NewCertPool()
	roots.AddCert(i.certificate)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return "", ErrInvalidCertificate
	}
	if len(leaf.URIs) != 1 || leaf.IsCA {
		return "", ErrInvalidCertificate
	}
	scope := leaf.URIs[0]
	if scope.Scheme != "tnl" || scope.Host != "visitor" || scope.RawQuery != "" || scope.Fragment != "" || scope.User != nil || scope.Opaque != "" || scope.RawPath != "" {
		return "", ErrInvalidCertificate
	}
	identity, ok := strings.CutPrefix(scope.Path, "/"+publicURLID+"/")
	if ok && opaqueid.Valid(identity, opaqueid.IdentityPrefix) {
		return identity, nil
	}
	return "", ErrInvalidCertificate
}
