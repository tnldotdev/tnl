package tnldruntime

import (
	"crypto/tls"
	"crypto/x509"
	"time"

	tnldconfig "github.com/tnldotdev/tnl/internal/daemon/config"
)

func staticServerTLS(certificateFile, privateKeyFile string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(certificateFile, privateKeyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}, nil
}

func relayTLSConfig(cfg tnldconfig.Config, fallback *tls.Config) (*tls.Config, error) {
	if cfg.RelayTLSCertificateFile != "" {
		return staticServerTLS(cfg.RelayTLSCertificateFile, cfg.RelayTLSPrivateKeyFile)
	}
	if fallback == nil {
		return nil, nil
	}
	return fallback.Clone(), nil
}

func firstCertificateExpiry(config *tls.Config) (time.Time, bool) {
	if config == nil || len(config.Certificates) == 0 {
		return time.Time{}, false
	}
	certificate := config.Certificates[0]
	leaf := certificate.Leaf
	if leaf == nil && len(certificate.Certificate) > 0 {
		leaf, _ = x509.ParseCertificate(certificate.Certificate[0])
	}
	if leaf == nil {
		return time.Time{}, false
	}
	return leaf.NotAfter, true
}
