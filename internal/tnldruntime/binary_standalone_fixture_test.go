package tnldruntime

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
)

type integrationBinaryStandalone struct {
	repositoryRoot string
	tnlPath        string
	databaseURL    string
	stateDirectory string
	environment    []string
	server         *integrationBinaryProcess
	pebble         integrationPebble
}

func startIntegrationBinaryStandalone(t *testing.T) *integrationBinaryStandalone {
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
	pebble := startIntegrationPebble(t, 443, startIntegrationDNS(t))
	trustFile := filepath.Join(t.TempDir(), "integration-roots.pem")
	trustedCertificates := append([]byte{}, trustRoot.certificatePEM...)
	trustedCertificates = append(trustedCertificates, pebble.apiRootPEM...)
	trustedCertificates = append(trustedCertificates, pebble.rootPEM...)
	if err := os.WriteFile(trustFile, trustedCertificates, 0o600); err != nil {
		t.Fatal(err)
	}
	runIntegrationBinaryCommand(t, repositoryRoot, integrationBinaryEnvironment(map[string]string{"TNLD_DATABASE_DIRECT_URL": databaseURL}), tnldPath, "migrate")
	metricsAddress := unusedTCPAddress(t)
	// Standalone creates its own internal listeners. The unused split-role
	// addresses below only need to satisfy configuration validation.
	serveEnvironment := integrationBinaryEnvironment(map[string]string{
		"SSL_CERT_FILE":                     trustFile,
		"TNLD_ACCESS_TOKEN_LIFETIME":        "5m",
		"TNLD_ACME_ACCEPT_TERMS":            "true",
		"TNLD_ACME_DIRECTORY_URL":           pebble.directoryURL,
		"TNLD_ACME_EMAIL":                   "integration@example.test",
		"TNLD_ACME_PROFILE":                 "tlsserver",
		"TNLD_CONTROL_LISTEN":               "127.0.0.1:443",
		"TNLD_CONTROL_TLS_CERTIFICATE_FILE": serverCertificate.certificateFile,
		"TNLD_CONTROL_TLS_PRIVATE_KEY_FILE": serverCertificate.privateKeyFile,
		"TNLD_DATABASE_URL":                 databaseURL,
		"TNLD_DRAIN_TIMEOUT":                "1s",
		"TNLD_INGRESS_LEASE_DURATION":       "5s",
		"TNLD_INGRESS_LISTEN":               "127.0.0.1:443",
		"TNLD_INTERNAL_RELAY_LISTEN":        "127.0.0.1:1",
		"TNLD_LEASE_RENEWAL_INTERVAL":       "500ms",
		"TNLD_LOGIN_TOKEN":                  testLoginToken,
		"TNLD_MANAGED_DEPLOYMENT_DOMAIN":    "routes.127.0.0.1.nip.io",
		"TNLD_METRICS_LISTEN":               metricsAddress,
		"TNLD_ROLE":                         "standalone",
		"TNLD_PRIVATE_CONTROL_LISTEN":       "127.0.0.1:1",
		"TNLD_REFRESH_TOKEN_LIFETIME":       "1h",
		"TNLD_RELAY_LEASE_DURATION":         "5s",
		"TNLD_RELAY_TCP_LISTEN":             "127.0.0.1:443",
		"TNLD_RELAY_TLS_CERTIFICATE_FILE":   serverCertificate.certificateFile,
		"TNLD_RELAY_TLS_PRIVATE_KEY_FILE":   serverCertificate.privateKeyFile,
		"TNLD_RELAY_UDP_LISTEN":             "127.0.0.1:443",
		"TNLD_ROUTING_TABLE_WAIT":           "1s",
		"TNLD_SERVER_DOMAIN":                "127.0.0.1.nip.io",
		"TNLD_STORAGE_KEY":                  testStorageKey,
	})
	owner := newBinaryTopology(t)
	server := owner.start(t, tnldconfig.RoleStandalone, repositoryRoot, serveEnvironment, tnldPath, "serve")
	waitForIntegrationBinaryReady(t, server, metricsAddress, databaseURL)
	stateDirectory := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	clientEnvironment := integrationBinaryEnvironment(map[string]string{
		"SSL_CERT_FILE": trustFile, "TNL_LOGIN_TOKEN": testLoginToken, "TNL_NO_TELEMETRY": "1",
		"TNL_SERVER": "https://control.127.0.0.1.nip.io", "TNL_STATE_DIR": stateDirectory,
	})
	runIntegrationBinaryCommand(t, repositoryRoot, clientEnvironment, tnlPath, "login", "--token")
	clientEnvironment = removeIntegrationEnvironment(clientEnvironment, "TNL_LOGIN_TOKEN")
	return &integrationBinaryStandalone{repositoryRoot: repositoryRoot, tnlPath: tnlPath, databaseURL: databaseURL,
		stateDirectory: stateDirectory, environment: clientEnvironment, server: server, pebble: pebble}
}
