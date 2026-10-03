package tnldruntime

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/controltls"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
)

type controlTLSSettings struct {
	certificateFile     string
	privateKeyFile      string
	directoryURL        string
	hostname            string
	additionalHostnames []string
	email               string
	acceptTerms         bool
}

func controlTLSSettingsFrom(cfg tnldconfig.Config) controlTLSSettings {
	additionalHostnames := []string(nil)
	if cfg.Role == tnldconfig.RoleStandalone && cfg.ControlTLSCertificateFile == "" &&
		cfg.RelayTLSCertificateFile == "" && !cfg.RelayCertificateAutomationEnabled() {
		additionalHostnames = []string{cfg.StandaloneRelayHostname()}
	}
	return controlTLSSettings{
		certificateFile:     cfg.ControlTLSCertificateFile,
		privateKeyFile:      cfg.ControlTLSPrivateKeyFile,
		directoryURL:        cfg.ACMEDirectoryURL,
		hostname:            cfg.ServerHostname(),
		additionalHostnames: additionalHostnames,
		email:               cfg.ACMEEmail,
		acceptTerms:         cfg.ACMEAcceptTerms,
	}
}

func controlTLSConfig(
	settings controlTLSSettings,
	database *controlstate.Database,
	account controlstate.ACMEAccount,
	acmeHTTPClient *http.Client,
) (*tls.Config, *controltls.Source, error) {
	if settings.certificateFile != "" {
		config, err := staticServerTLS(settings.certificateFile, settings.privateKeyFile)
		return config, nil, err
	}
	cache, err := database.ControlTLSCache(settings.directoryURL)
	if err != nil {
		return nil, nil, err
	}
	source, err := controltls.New(controltls.Config{
		Hostname: settings.hostname, Cache: cache, DirectoryURL: settings.directoryURL,
		AdditionalHostnames: settings.additionalHostnames,
		Email:               settings.email, AcceptTerms: settings.acceptTerms, AccountKey: account.AccountKeyDER,
		HTTPClient: acmeHTTPClient, RunLeader: database.RunControlTLSLeader,
		Report: func(err error) {
			logOperationalError("manage public control certificate", failure.ServerCertificateFailed, err)
		},
	})
	if err != nil {
		return nil, nil, err
	}
	return source.TLSConfig(), source, nil
}

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
