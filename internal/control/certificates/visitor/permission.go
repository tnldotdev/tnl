package visitor

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"time"

	"github.com/tnldotdev/tnl/internal/security/visitorcert"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

// IssuePermission certifies the proven CSR key and a control-signed permission.
// control's state owner authorizes and signs against this exact serial, public
// key and deadline. this issuer owns only certificate construction and trust.
func (i *Issuer) IssuePermission(der []byte, expires, now time.Time, bind func(string, any, time.Time) (visitortoken.Token, error)) ([]byte, error) {
	if i == nil || bind == nil || !expires.After(now) || expires.After(now.Add(visitorcert.MaxWorkloadLifetime)) {
		return nil, visitorcert.ErrInvalidCertificate
	}
	csr, err := ValidateCSR(der)
	if err != nil {
		return nil, err
	}
	if expires.After(i.root.NotAfter) {
		expires = i.root.NotAfter
	}
	expires = expires.Truncate(time.Second)
	if !expires.After(now) {
		return nil, visitorcert.ErrInvalidCertificate
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	token, err := bind(serial.Text(16), csr.PublicKey, expires)
	if err != nil {
		return nil, err
	}
	uri, err := visitortoken.CertificateURI(token)
	if err != nil {
		return nil, err
	}
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "tnl visitor"}, NotBefore: now.Add(-time.Second), NotAfter: expires,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}
	signed, err := x509.CreateCertificate(rand.Reader, leaf, i.root, csr.PublicKey, i.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signed}), nil
}
