package connectionruntime

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"time"
)

func bytesReader(data []byte) *bytes.Reader { return bytes.NewReader(data) }

func tlsMaterial(pair tls.Certificate, serverName string, expires time.Time) (TLSOptions, error) {
	if len(pair.Certificate) == 0 || pair.PrivateKey == nil {
		return TLSOptions{}, ErrUnavailable
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.NotBefore.After(time.Now()) || !leaf.NotAfter.After(time.Now()) || !expires.After(time.Now()) {
		return TLSOptions{}, ErrExpired
	}
	key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		return TLSOptions{}, ErrTransport
	}
	var certificates []byte
	for _, der := range pair.Certificate {
		certificates = append(certificates, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	if _, err := tls.X509KeyPair(certificates, private); err != nil {
		return TLSOptions{}, ErrUnavailable
	}
	return TLSOptions{ServerName: serverName, RejectUnauthorized: true, Cert: string(certificates), Key: string(private)}, nil
}
