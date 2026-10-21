package tnldruntime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/devoidc"
	"github.com/tnldotdev/tnl/internal/testutil/oidctest"
)

func binaryOIDCProvider(t *testing.T, certificate integrationCertificate, control string) string {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(certificate.certificateFile, certificate.privateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server := httptest.NewUnstartedServer(mux)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}
	server.StartTLS()
	t.Cleanup(server.Close)
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	issuer := "https://localhost:" + port
	p, err := devoidc.New(devoidc.Config{Issuer: issuer, ClientID: "server", ClientSecret: "fixture-secret", Subject: "developer", RedirectURLs: []string{control + "/v1/auth/device/callback", control + "/v1/browser/callback"}})
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/", p)
	return issuer
}

func binaryApproveDevice(t *testing.T, payload []byte, trustFile string) clientstate.AuthOperation {
	t.Helper()
	var op clientstate.AuthOperation
	if err := json.Unmarshal(payload, &op); err != nil {
		t.Fatal(err)
	}
	pem, err := os.ReadFile(trustFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("missing test trust roots")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}
	defer transport.CloseIdleConnections()
	if err := oidctest.Approve(t.Context(), &http.Client{Transport: transport, Timeout: 10 * time.Second}, op.ApprovalURL); err != nil {
		t.Fatal(err)
	}
	return op
}

func binaryOIDCLogin(t *testing.T, root string, env []string, binary, trustFile string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "auth", "login", "start", "--output=json")
	command.Dir = root
	command.Env = env
	payload, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	op := binaryApproveDevice(t, payload, trustFile)
	runIntegrationBinaryCommand(t, root, env, binary, "auth", "login", "wait", op.ID, "--output=json")
}
