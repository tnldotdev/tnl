package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"
	"time"
)

func workflowNativeHTTPClient(t *testing.T, f *cliWorkflow, hostname string) *http.Client {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(f.issuer)
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: hostname}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 2 * time.Second}
}
