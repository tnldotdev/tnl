package tnldruntime

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	tnldconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
)

type integrationBinaryStandalone struct {
	repositoryRoot string
	tnlPath        string
	databaseURL    string
	stateDirectory string
	trustFile      string
	environment    []string
	server         *integrationBinaryProcess
	pebble         integrationPebble
}

func startIntegrationBinaryStandalone(t *testing.T, modes ...string) *integrationBinaryStandalone {
	return startIntegrationBinaryStandaloneWithBind(t, false, modes...)
}

func startIntegrationBinaryStandaloneWithBind(t *testing.T, containerReachable bool, modes ...string) *integrationBinaryStandalone {
	t.Helper()
	testutil.RequireTestTier(t, testutil.TestTierBinary)
	if runtime.GOOS == "darwin" {
		t.Fatal("binary integration requires a disposable Linux environment: macOS binaries use the login Keychain and do not use SSL_CERT_FILE for system trust; in-process keyring mocks cannot isolate these subprocesses")
	}
	assertIntegrationPort443Available(t)
	testutil.PostgresURL(t)
	repositoryRoot := integrationRepositoryRoot(t)
	binaryDirectory := t.TempDir()
	tnldPath, tnlPath := filepath.Join(binaryDirectory, "tnld"), filepath.Join(binaryDirectory, "tnl")
	buildIntegrationBinary(t, repositoryRoot, tnldPath, "./cmd/tnld")
	buildIntegrationBinary(t, repositoryRoot, tnlPath, "./cmd/tnl")
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "standalone")
	trustRoot := newIntegrationTestCA(t)
	serverCertificate := trustRoot.issueServer(t, "*.127.0.0.1.nip.io")
	const controlOrigin = "https://control.127.0.0.1.nip.io:8445"
	oidcIssuer := binaryOIDCProvider(t, trustRoot.issueServer(t, "localhost"), controlOrigin)
	dns := newIntegrationRoute53(t, "binary", "routes.127.0.0.1.nip.io")
	pebble := startIntegrationPebble(t, 443, dns.address)
	trustFile := filepath.Join(t.TempDir(), "integration-roots.pem")
	trustedCertificates := append([]byte{}, trustRoot.certificatePEM...)
	trustedCertificates = append(trustedCertificates, pebble.apiRootPEM...)
	trustedCertificates = append(trustedCertificates, pebble.rootPEM...)
	if err := os.WriteFile(trustFile, trustedCertificates, 0o600); err != nil {
		t.Fatal(err)
	}
	runIntegrationBinaryCommand(t, repositoryRoot, integrationBinaryEnvironment(map[string]string{"TNLD_DATABASE_DIRECT_URL": databaseURL}), tnldPath, "migrate")
	if containerReachable {
		// the disposable test has no Route 53 zone. seed only the verified front
		// destination for this fresh database, as the split database test does.
		inspect := inspectStandaloneTestDatabase(t, databaseURL)
		if _, err := inspect.ExecContext(t.Context(), `UPDATE control.ingress_pools SET ipv4_address = '127.0.0.1'::inet, state = 'enabled' WHERE id = 'ingress-a'`); err != nil {
			t.Fatal(err)
		}
	}
	metricsAddress := unusedTCPAddress(t)
	controlBackend := unusedTCPAddress(t)
	controlTLS, err := staticServerTLS(serverCertificate.certificateFile, serverCertificate.privateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	controlBind := "127.0.0.1:8445"
	if containerReachable {
		controlBind = "0.0.0.0:8445"
	}
	startIntegrationControlProxy(t, nil, controlBind, controlBackend, controlTLS)
	// standalone creates its own internal listeners. the unused split-role
	// addresses below only need to satisfy configuration validation.
	publicListen := "127.0.0.1:443"
	relayUDPListen := publicListen
	if containerReachable {
		// the front accepts container connections at :443, then preserves their
		// original destination for public and private ingress.
		publicListen = unusedTCPAddress(t)
		startBinaryPublicProxy(t, 443, publicListen)
		relayUDPListen = unusedTCPAddress(t)
	}
	serveSettings := map[string]string{
		"SSL_CERT_FILE":                trustFile,
		"TNLD_ACCESS_TOKEN_LIFETIME":   "5m",
		"TNLD_ACME_ACCEPT_TERMS":       "true",
		"TNLD_ACME_DIRECTORY_URL":      pebble.directoryURL,
		"TNLD_ACME_EMAIL":              "integration@example.test",
		"TNLD_ACME_PROFILE":            "tlsserver",
		"TNLD_CONTROL_LISTEN":          controlBackend,
		"TNLD_CONTROL_URL":             controlOrigin,
		"TNLD_ROUTE53_MANAGED_ZONE_ID": "binary",
		"TNLD_INGRESS_IPV4_ADDRESSES":  "127.0.0.1",
		"TNLD_DNS_SERVER":              dns.address,
		"AWS_ENDPOINT_URL_ROUTE_53":    dns.server.URL,
		"AWS_ACCESS_KEY_ID":            "tnl-integration-only",
		"AWS_SECRET_ACCESS_KEY":        "tnl-integration-only",
		"AWS_EC2_METADATA_DISABLED":    "true",
		"TNLD_DATABASE_URL":            databaseURL,
		"TNLD_DRAIN_TIMEOUT":           "1s",
		"TNLD_INGRESS_LEASE_DURATION":  "5s",
		"TNLD_INGRESS_LISTEN":          publicListen,
		"TNLD_INTERNAL_RELAY_LISTEN":   "127.0.0.1:1",
		"TNLD_LEASE_RENEWAL_INTERVAL":  "500ms",
		"TNLD_OIDC_ISSUER":             oidcIssuer, "TNLD_OIDC_CLIENT_ID": "server", "TNLD_OIDC_CLIENT_SECRET": "fixture-secret", "TNLD_INITIAL_ADMINISTRATORS": "developer",
		"TNLD_MANAGED_DOMAIN":             "routes.127.0.0.1.nip.io",
		"TNLD_METRICS_LISTEN":             metricsAddress,
		"TNLD_ROLE":                       "standalone",
		"TNLD_PRIVATE_CONTROL_LISTEN":     "127.0.0.1:1",
		"TNLD_REFRESH_TOKEN_LIFETIME":     "1h",
		"TNLD_RELAY_LEASE_DURATION":       "5s",
		"TNLD_RELAY_TCP_LISTEN":           publicListen,
		"TNLD_RELAY_TLS_CERTIFICATE_FILE": serverCertificate.certificateFile,
		"TNLD_RELAY_TLS_PRIVATE_KEY_FILE": serverCertificate.privateKeyFile,
		"TNLD_RELAY_UDP_LISTEN":           relayUDPListen,
		"TNLD_ROUTING_TABLE_WAIT":         "1s",
		"TNLD_SERVER_DOMAIN":              "127.0.0.1.nip.io",
		"TNLD_STORAGE_KEY":                testStorageKey,
	}
	if containerReachable {
		serveSettings["TNLD_REQUIRE_PROXY_HEADER"] = "true"
		serveSettings["TNLD_INGRESS_TRUSTED_PROXIES"] = "127.0.0.1/32"
	}
	serveEnvironment := integrationBinaryEnvironment(serveSettings)
	if len(modes) != 0 {
		serveEnvironment = append(serveEnvironment, "TNLD_MANAGED_URL_MODE="+modes[0])
	}
	owner := newBinaryTopology(t)
	server := owner.start(t, tnldconfig.RoleStandalone, repositoryRoot, serveEnvironment, tnldPath, "serve")
	waitForIntegrationBinaryReady(t, server, metricsAddress, databaseURL)
	stateDirectory := binaryStateDirectory(t)
	clientEnvironment := integrationBinaryEnvironment(map[string]string{
		"SSL_CERT_FILE": trustFile, "TNL_NO_TELEMETRY": "1",
		"TNL_SERVER": controlOrigin, "TNL_STATE_DIR": stateDirectory,
	})
	binaryOIDCLogin(t, repositoryRoot, clientEnvironment, tnlPath, trustFile)
	return &integrationBinaryStandalone{repositoryRoot: repositoryRoot, tnlPath: tnlPath, databaseURL: databaseURL, trustFile: trustFile,
		stateDirectory: stateDirectory, environment: clientEnvironment, server: server, pebble: pebble}
}

func startBinaryPublicProxy(t *testing.T, port int, backend string) {
	t.Helper()
	listener, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		t.Fatalf("listen for public test port %d: %v", port, err)
	}
	var connections sync.WaitGroup
	accepted := make(chan struct{})
	t.Cleanup(func() {
		_ = listener.Close()
		<-accepted
		connections.Wait()
	})
	go func() {
		defer close(accepted)
		for {
			visitor, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer visitor.Close()
				upstream, err := net.DialTimeout("tcp", backend, 5*time.Second)
				if err != nil {
					return
				}
				defer upstream.Close()
				original, err := proxyproto.Encode(proxyproto.Header{
					Source:      visitor.RemoteAddr().(*net.TCPAddr).AddrPort(),
					Destination: visitor.LocalAddr().(*net.TCPAddr).AddrPort(),
				})
				if err == nil {
					_, err = upstream.Write(original)
				}
				if err != nil {
					return
				}
				finished := make(chan struct{})
				go func() {
					_, _ = io.Copy(visitor, upstream)
					_ = visitor.(*net.TCPConn).CloseWrite()
					close(finished)
				}()
				_, _ = io.Copy(upstream, visitor)
				_ = upstream.(*net.TCPConn).CloseWrite()
				<-finished
			}()
		}
	}()
}
