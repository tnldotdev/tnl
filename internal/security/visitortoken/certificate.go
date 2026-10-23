package visitortoken

import (
	"crypto/x509"
	"net/url"
	"strings"
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
