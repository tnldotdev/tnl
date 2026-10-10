package tnldruntime

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
)

type integrationBinarySplit struct {
	repositoryRoot, tnlPath, databaseURL, publicURLHost string
	environment                                         []string
	pebble                                              integrationPebble
}

func startIntegrationBinarySplit(t *testing.T) *integrationBinarySplit {
	t.Helper()
	testutil.RequireTestTier(t, testutil.TestTierBinary)
	if runtime.GOOS == "darwin" {
		t.Fatal("binary integration requires a disposable Linux environment")
	}
	testutil.PostgresURL(t)
	assertIntegrationTCPAddressAvailable(t, "127.0.0.1:443")
	assertIntegrationTCPAddressAvailable(t, "127.0.0.2:443")
	assertIntegrationTCPAddressAvailable(t, "127.0.0.2:9443")

	repositoryRoot := integrationRepositoryRoot(t)
	binaryDirectory := t.TempDir()
	tnldPath := filepath.Join(binaryDirectory, "tnld")
	tnlPath := filepath.Join(binaryDirectory, "tnl")
	buildIntegrationBinary(t, repositoryRoot, tnldPath, "./cmd/tnld")
	buildIntegrationBinary(t, repositoryRoot, tnlPath, "./cmd/tnl")
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "split-binary")
	runIntegrationBinaryCommand(t, repositoryRoot, integrationBinaryEnvironment(map[string]string{
		"TNLD_DATABASE_DIRECT_URL": databaseURL,
	}), tnldPath, "migrate")

	const (
		serverDomain  = "127.0.0.2.nip.io"
		controlHost   = "control." + serverDomain
		publicURLHost = "split-binary.routes.127.0.0.1.nip.io"
	)
	root := newIntegrationTestCA(t)
	controlCertificate := root.issueServer(t, controlHost)
	relayAHost, relayBHost := "relay-a."+serverDomain, "relay-b."+serverDomain
	relayACertificate := root.issueServer(t, relayAHost)
	relayBCertificate := root.issueServer(t, relayBHost)
	dnsAddress := startIntegrationDNS(t)
	pebble := startIntegrationPebble(t, 443, dnsAddress)
	trustFile := filepath.Join(t.TempDir(), "integration-roots.pem")
	trustedCertificates := append([]byte{}, root.certificatePEM...)
	trustedCertificates = append(trustedCertificates, pebble.apiRootPEM...)
	trustedCertificates = append(trustedCertificates, pebble.rootPEM...)
	if err := os.WriteFile(trustFile, trustedCertificates, 0o600); err != nil {
		t.Fatal(err)
	}

	controlMetrics := unusedTCPAddress(t)
	controlEnvironment := integrationBinaryEnvironment(map[string]string{
		"SSL_CERT_FILE":                     trustFile,
		"TNLD_ACCESS_TOKEN_LIFETIME":        "5m",
		"TNLD_ACME_ACCEPT_TERMS":            "true",
		"TNLD_ACME_DIRECTORY_URL":           pebble.directoryURL,
		"TNLD_ACME_EMAIL":                   "integration@example.test",
		"TNLD_ACME_PROFILE":                 "tlsserver",
		"TNLD_CLUSTER_SECRET":               testClusterSecret,
		"TNLD_CONTROL_LISTEN":               "127.0.0.2:443",
		"TNLD_CONTROL_TLS_CERTIFICATE_FILE": controlCertificate.certificateFile,
		"TNLD_CONTROL_TLS_PRIVATE_KEY_FILE": controlCertificate.privateKeyFile,
		"TNLD_DATABASE_URL":                 databaseURL,
		"TNLD_DRAIN_TIMEOUT":                "3s",
		"TNLD_INGRESS_LEASE_DURATION":       "5s",
		"TNLD_LEASE_RENEWAL_INTERVAL":       "500ms",
		"TNLD_LOGIN_TOKEN":                  testLoginToken,
		"TNLD_MANAGED_DOMAIN":               "routes.127.0.0.1.nip.io",
		"TNLD_MANAGED_URL_MODE":             "simple",
		"TNLD_METRICS_LISTEN":               controlMetrics,
		"TNLD_ROLE":                         "control",
		"TNLD_PRIVATE_CONTROL_LISTEN":       "127.0.0.2:9443",
		"TNLD_REFRESH_TOKEN_LIFETIME":       "1h",
		"TNLD_RELAY_LEASE_DURATION":         "5s",
		"TNLD_ROUTING_TABLE_WAIT":           "1s",
		"TNLD_SERVER_DOMAIN":                serverDomain,
		"TNLD_STORAGE_KEY":                  testStorageKey,
	})
	owner := newBinaryTopology(t)
	control := owner.start(t, tnldconfig.RoleControl, repositoryRoot, controlEnvironment, tnldPath, "serve")
	waitForIntegrationBinaryReady(t, control, controlMetrics, databaseURL)

	ingressMetrics := unusedTCPAddress(t)
	ingressEnvironment := integrationBinaryEnvironment(map[string]string{
		"SSL_CERT_FILE":               trustFile,
		"TNLD_CLUSTER_SECRET":         testClusterSecret,
		"TNLD_CONTROL_HOSTNAME":       controlHost,
		"TNLD_CONTROL_RETRY_INTERVAL": "50ms",
		"TNLD_DRAIN_TIMEOUT":          "3s",
		"TNLD_INGRESS_ID":             "ingress-binary",
		"TNLD_INGRESS_LEASE_DURATION": "5s",
		"TNLD_INGRESS_LISTEN":         "127.0.0.1:443",
		"TNLD_LEASE_RENEWAL_INTERVAL": "500ms",
		"TNLD_METRICS_LISTEN":         ingressMetrics,
		"TNLD_ROLE":                   "ingress",
		"TNLD_RELAY_LEASE_DURATION":   "5s",
		"TNLD_ROUTING_TABLE_WAIT":     "1s",
	})
	ingress := owner.start(t, tnldconfig.RoleIngress, repositoryRoot, ingressEnvironment, tnldPath, "serve")
	waitForIntegrationBinaryReady(t, ingress, ingressMetrics, databaseURL)

	relayAPort := unusedTCPAndUDPPortOn(t, "127.0.0.2")
	relayA, relayAMetrics := startIntegrationBinaryRelay(t, owner, repositoryRoot, tnldPath, trustFile,
		controlHost, "relay-a", "relay-a-binary", relayAHost, relayAPort, relayACertificate)
	waitForIntegrationBinaryReady(t, relayA, relayAMetrics, databaseURL)
	relayBPort := unusedTCPAndUDPPortOn(t, "127.0.0.2")
	relayB, relayBMetrics := startIntegrationBinaryRelay(t, owner, repositoryRoot, tnldPath, trustFile,
		controlHost, "relay-b", "relay-b-binary", relayBHost, relayBPort, relayBCertificate)
	waitForIntegrationBinaryReady(t, relayB, relayBMetrics, databaseURL)

	stateDirectory := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	clientEnvironment := integrationBinaryEnvironment(map[string]string{
		"SSL_CERT_FILE":    trustFile,
		"TNL_LOGIN_TOKEN":  testLoginToken,
		"TNL_NO_TELEMETRY": "1",
		"TNL_SERVER":       "https://" + controlHost,
		"TNL_STATE_DIR":    stateDirectory,
	})
	runIntegrationBinaryCommand(t, repositoryRoot, clientEnvironment, tnlPath, "auth", "login", "--login-token")
	clientEnvironment = removeIntegrationEnvironment(clientEnvironment, "TNL_LOGIN_TOKEN")

	return &integrationBinarySplit{repositoryRoot: repositoryRoot, tnlPath: tnlPath, databaseURL: databaseURL,
		publicURLHost: publicURLHost, environment: clientEnvironment, pebble: pebble}
}

func startIntegrationBinaryRelay(
	t *testing.T,
	owner *binaryTopology,
	repositoryRoot, tnldPath, trustFile, controlHost, serviceID, relayID, relayHost, relayPort string,
	certificate integrationCertificate,
) (*integrationBinaryProcess, string) {
	t.Helper()
	metricsAddress := unusedTCPAddress(t)
	internalAddress := unusedTCPAddressOn(t, "127.0.0.2")
	environment := integrationBinaryEnvironment(map[string]string{
		"SSL_CERT_FILE":                   trustFile,
		"TNLD_CLUSTER_SECRET":             testClusterSecret,
		"TNLD_CONTROL_HOSTNAME":           controlHost,
		"TNLD_CONTROL_RETRY_INTERVAL":     "50ms",
		"TNLD_DRAIN_TIMEOUT":              "3s",
		"TNLD_INGRESS_LEASE_DURATION":     "5s",
		"TNLD_INTERNAL_RELAY_ADDRESS":     internalAddress,
		"TNLD_INTERNAL_RELAY_LISTEN":      internalAddress,
		"TNLD_LEASE_RENEWAL_INTERVAL":     "500ms",
		"TNLD_METRICS_LISTEN":             metricsAddress,
		"TNLD_ROLE":                       "relay",
		"TNLD_RELAY_ADDRESS":              net.JoinHostPort(relayHost, relayPort),
		"TNLD_RELAY_ID":                   relayID,
		"TNLD_RELAY_LEASE_DURATION":       "5s",
		"TNLD_RELAY_SERVICE_ID":           serviceID,
		"TNLD_RELAY_TCP_LISTEN":           net.JoinHostPort("127.0.0.2", relayPort),
		"TNLD_RELAY_TLS_CERTIFICATE_FILE": certificate.certificateFile,
		"TNLD_RELAY_TLS_PRIVATE_KEY_FILE": certificate.privateKeyFile,
		"TNLD_RELAY_UDP_LISTEN":           net.JoinHostPort("127.0.0.2", relayPort),
		"TNLD_ROUTING_TABLE_WAIT":         "1s",
	})
	process := owner.start(t, tnldconfig.RoleRelay, repositoryRoot, environment, tnldPath, "serve")
	return process, metricsAddress
}

func unusedTCPAddressOn(t *testing.T, host string) string {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func unusedTCPAndUDPPortOn(t *testing.T, host string) string {
	t.Helper()
	tcpListener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	_, port, err := net.SplitHostPort(tcpListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	udpListener, err := net.ListenPacket("udp", net.JoinHostPort(host, port))
	if err != nil {
		_ = tcpListener.Close()
		t.Fatal(err)
	}
	if err := udpListener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tcpListener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func assertIntegrationTCPAddressAvailable(t *testing.T, address string) {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("binary integration requires TCP %s: %v", address, err)
	}
	_ = listener.Close()
}

func removeIntegrationEnvironment(environment []string, name string) []string {
	prefix := name + "="
	result := make([]string, 0, len(environment))
	for _, value := range environment {
		if !strings.HasPrefix(value, prefix) {
			result = append(result, value)
		}
	}
	return result
}
