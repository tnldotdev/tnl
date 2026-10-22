package daemon

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clientAuth "github.com/tnldotdev/tnl/internal/client/auth"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/testutil/oidctest"
)

func TestIntegrationControlProxyDeviceBrowserFlow(t *testing.T) {
	databaseURL, _ := standaloneTestDatabase(t)
	ca := newIntegrationTestCA(t)
	certificate := ca.issueServer(t, "control.proxy.test")
	issuerCertificate := ca.issueServer(t, "localhost")
	const origin = "https://control.proxy.test"
	issuer := binaryOIDCProvider(t, issuerCertificate, origin)
	acme := standaloneTestACMEServer(t)
	cfg := splitTestConfig(daemonconfig.RoleControl, unusedTCPAddress(t))
	cfg.DatabaseURL, cfg.StorageKey, cfg.ClusterSecret = databaseURL, testStorageKey, testClusterSecret
	cfg.ServerDomain, cfg.ManagedDomain = "proxy.test", "apps.proxy.test"
	cfg.ControlListen, cfg.PrivateControlListen = unusedTCPAddress(t), unusedTCPAddress(t)
	cfg.ControlTLSCertificateFile, cfg.ControlTLSPrivateKeyFile = certificate.certificateFile, certificate.privateKeyFile
	cfg.ACMEDirectoryURL, cfg.ACMEEmail, cfg.ACMEAcceptTerms, cfg.ACMEProfile = acme.URL+"/directory", "operator@example.test", true, "tlsserver"
	cfg.AccessTokenLifetime, cfg.RefreshTokenLifetime = 5*time.Minute, time.Hour
	cfg.OIDCIssuer, cfg.OIDCClientID, cfg.OIDCClientSecret = issuer, "server", "fixture-secret"
	cfg.InitialAdministrators, cfg.InitialTeamOwners = []string{"developer"}, map[string]string{"local": "developer"}
	cfg.OIDCAdmissionFile = filepath.Join("..", "..", "development", "local", "oidc-admission.json")
	serviceTransport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.roots, MinVersion: tls.VersionTLS13}}
	t.Cleanup(serviceTransport.CloseIdleConnections)
	public := unusedTCPAddress(t)
	secure, err := staticServerTLS(certificate.certificateFile, certificate.privateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	startIntegrationControlProxy(t, nil, public, cfg.ControlListen, secure)
	process := startIntegrationProcess(t, cfg, acme.Client(), &http.Client{Transport: serviceTransport, Timeout: 10 * time.Second})
	waitForProcessReady(t, process)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.roots, MinVersion: tls.VersionTLS13}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "control.proxy.test:443" {
			address = public
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	state, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	auth := clientAuth.Config{Team: "local", ServerEndpoint: origin, State: state, HTTPClient: client, Diagnostics: io.Discard}
	operation, err := clientAuth.StartLogin(t.Context(), auth)
	if err != nil {
		t.Fatal(err)
	}
	if err := oidctest.Approve(t.Context(), client, operation.ApprovalURL); err != nil {
		t.Fatal(err)
	}
	if _, err := clientAuth.WaitLogin(t.Context(), auth, operation.ID, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	loggedIn, err := clientAuth.Authenticate(t.Context(), auth)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := loggedIn.Authority.IdentityContext(t.Context())
	if err != nil || identity.PersonalTeamId == "" {
		t.Fatalf("proxied OIDC identity missing: %v", err)
	}
	// public ingress never exposes cluster APIs through the control proxy.
	response, err := client.Post(origin+"/internal/v1/ingresses/register", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("private API surfaced publicly: %d", response.StatusCode)
	}
}
