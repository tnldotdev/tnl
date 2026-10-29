package visitortoken

import (
	"crypto/x509"
	"encoding/base64"
	"net/url"
	"strings"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

// CertificateURI carries the key-bound permission in the standard subjectAltName
// extension (OID 2.5.29.17), using one tnl://visitor-token/<compact-JWS> URI.
// CSR-supplied names and extensions never supply this value.
func CertificateURI(token Token) (*url.URL, error) {
	if len(token.Reveal()) == 0 || len(token.Reveal()) > MaxTokenBytes || strings.ContainsAny(token.Reveal(), "/\x00\r\n?#") {
		return nil, ErrToken
	}
	return &url.URL{Scheme: "tnl", Host: "visitor-token", Path: "/" + token.Reveal()}, nil
}

func CertificateToken(leaf *x509.Certificate) (Token, error) {
	if leaf == nil || len(leaf.URIs) != 1 || leaf.URIs[0] == nil {
		return "", ErrToken
	}
	uri := leaf.URIs[0]
	if uri.Scheme != "tnl" || uri.Host != "visitor-token" || uri.User != nil || uri.RawQuery != "" || uri.Fragment != "" || uri.RawPath != "" || uri.Opaque != "" {
		return "", ErrToken
	}
	raw, found := strings.CutPrefix(uri.Path, "/")
	if !found {
		return "", ErrToken
	}
	token := Token(raw)
	if _, err := CertificateURI(token); err != nil {
		return "", err
	}
	return token, nil
}

// CertificateIssuanceBinding reads the scope and source attested by a verified
// client-certificate CA. client state uses it to bind a returned leaf to its
// issuance request. it returns no permission or current visitor authorization.
func CertificateIssuanceBinding(chains [][]*x509.Certificate) (visitorscope.Scope, Subject, error) {
	deny := func() (visitorscope.Scope, Subject, error) { return visitorscope.Scope{}, nil, ErrBinding }
	if len(chains) == 0 || len(chains[0]) < 2 || chains[0][0] == nil || chains[0][0].IsCA {
		return deny()
	}
	leaf := chains[0][0]
	token, err := CertificateToken(leaf)
	if err != nil {
		return deny()
	}
	parts := strings.Split(token.Reveal(), ".")
	if len(parts) != 3 {
		return deny()
	}
	headerBytes, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	var header protectedHeader
	if err != nil || decode(headerBytes, &header) != nil || header.Algorithm != "EdDSA" || header.Type != Type || !validText(header.KeyID, 128) {
		return deny()
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(signature) != 64 {
		return deny()
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	var value claims
	if err != nil || decode(payload, &value) != nil || value.Version != 1 || !validText(value.Issuer, 256) || !validResource(value.Scope, value.Hostname, value.Port) || value.Revision < 1 || value.Issued <= 0 || value.Expires <= value.Issued || value.Expires != leaf.NotAfter.Unix() {
		return deny()
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(value.ID)
	if err != nil || len(nonce) != 16 {
		return deny()
	}
	subject, err := decodeSubject(value.Subject)
	certificate, ok := subject.(Certificate)
	digest, keyErr := KeyDigest(leaf.PublicKey)
	if err != nil || keyErr != nil || !ok || leaf.SerialNumber == nil || certificate.Serial != leaf.SerialNumber.Text(16) || certificate.KeySHA256 != digest {
		return deny()
	}
	return value.Scope, certificate.Source, nil
}
