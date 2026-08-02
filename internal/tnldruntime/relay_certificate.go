package tnldruntime

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/relayv1"
)

type relayCertificateSource struct {
	relayServiceIDs map[string]struct{}
	tlsServerName   string

	mu          sync.RWMutex
	certificate *tls.Certificate
}

func newRelayCertificateSource(relayServiceID, tlsServerName string) (*relayCertificateSource, error) {
	if relayServiceID == "" || tlsServerName == "" {
		return nil, errors.New("relay certificate identity is required")
	}
	return newSharedRelayCertificateSource([]string{relayServiceID}, tlsServerName)
}

func newSharedRelayCertificateSource(relayServiceIDs []string, tlsServerName string) (*relayCertificateSource, error) {
	if len(relayServiceIDs) == 0 || tlsServerName == "" {
		return nil, errors.New("relay certificate identity is required")
	}
	ids := make(map[string]struct{}, len(relayServiceIDs))
	for _, relayServiceID := range relayServiceIDs {
		if relayServiceID == "" {
			return nil, errors.New("relay certificate identity is required")
		}
		ids[relayServiceID] = struct{}{}
	}
	return &relayCertificateSource{relayServiceIDs: ids, tlsServerName: tlsServerName}, nil
}

func (s *relayCertificateSource) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		s.mu.RLock()
		defer s.mu.RUnlock()
		if s.certificate == nil {
			return nil, errors.New("relay transport certificate is not ready")
		}
		return s.certificate, nil
	}}
}

func (s *relayCertificateSource) Install(certificate relayv1.RelayServiceCertificate) error {
	if _, ok := s.relayServiceIDs[certificate.RelayServiceId]; !ok || certificate.TlsServerName != s.tlsServerName {
		return errors.New("relay transport certificate identity does not match")
	}
	keyPair, err := tls.X509KeyPair([]byte(certificate.CertificatePem), []byte(certificate.PrivateKeyPem))
	if err != nil || len(keyPair.Certificate) == 0 {
		return errors.New("relay transport certificate key pair is invalid")
	}
	leaf, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil || leaf.VerifyHostname(s.tlsServerName) != nil || !leaf.NotAfter.Equal(certificate.NotAfter) ||
		!leaf.NotAfter.After(time.Now()) {
		return errors.New("relay transport certificate is invalid")
	}
	keyPair.Leaf = leaf
	s.mu.Lock()
	s.certificate = &keyPair
	s.mu.Unlock()
	return nil
}
