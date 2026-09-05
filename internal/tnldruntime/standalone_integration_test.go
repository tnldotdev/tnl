package tnldruntime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const testLoginToken = "tnl_login_AAECAwQFBgcICQoLDA0ODw.EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8"
const testClusterSecret = "0123456789abcdef0123456789abcdef"
const testStorageKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestIntegrationStandaloneLifecycle(t *testing.T) {
	directURL := os.Getenv("TNL_TEST_POSTGRES_URL")
	if directURL == "" {
		t.Skip("TNL_TEST_POSTGRES_URL is not set")
	}
	databaseURL, inspect := standaloneTestDatabase(t, directURL)
	acmeServer := standaloneTestACMEServer(t)
	certificateFile, keyFile, roots := standaloneTestCertificate(t, "control.tnl.test")
	relayCertificateFile, relayKeyFile, _ := standaloneTestCertificate(t, "relay.tnl.test")
	publicAddress := unusedTCPAddress(t)
	metricsAddress := unusedTCPAddress(t)
	cfg := config.TNLD{
		Mode: config.TNLDModeStandalone, DatabaseURL: databaseURL, MetricsListen: metricsAddress,
		ControlListen: unusedTCPAddress(t), PrivateControlListen: unusedTCPAddress(t), IngressListen: publicAddress,
		RelayTCPListen: unusedTCPAddress(t), RelayUDPListen: unusedUDPAddress(t), InternalRelayListen: unusedTCPAddress(t),
		ServerDomain: "tnl.test", ManagedDeploymentDomain: "tunnels.test",
		ControlTLSCertificateFile: certificateFile, ControlTLSPrivateKeyFile: keyFile,
		RelayTLSCertificateFile: relayCertificateFile, RelayTLSPrivateKeyFile: relayKeyFile,
		ACMEDirectoryURL: acmeServer.URL + "/directory", ACMEEmail: "operator@example.test",
		ACMEAcceptTerms: true, ACMEProfile: "tlsserver", LoginToken: testLoginToken,
		StorageKey:          testStorageKey,
		AccessTokenLifetime: 5 * time.Minute, RefreshTokenLifetime: time.Hour,
		PublicConnectionLimit: 100, RouteConnectionLimit: 10, PublisherConnectionLimit: 10,
		RelayStreamCapacity: 100, QUICMaxIncomingStreams: 100, QUICIdleTimeout: time.Minute,
		TunnelFallbackDelay: 10 * time.Millisecond, IngressLeaseDuration: 3 * time.Second,
		RelayLeaseDuration: 3 * time.Second, LeaseRenewalInterval: time.Second,
		ControlRetryInterval: 10 * time.Millisecond, RoutingTableWait: time.Second, DrainTimeout: 2 * time.Second,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	serviceClient := splitTestServiceHTTPClient(t, roots, cfg.PrivateControlListen)
	go func() { done <- serveWithHTTPClients(ctx, cfg, acmeServer.Client(), serviceClient) }()
	waitForProcessReady(t, done, metricsAddress)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return new(net.Dialer).DialContext(ctx, network, publicAddress)
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get("https://control.tnl.test/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var health controlv1.HealthResponse
	if err := json.NewDecoder(response.Body).Decode(&health); err != nil || response.StatusCode != http.StatusOK ||
		health.Status != controlv1.HealthResponseStatusOk {
		t.Fatalf("control health = %s, %#v, %v", response.Status, health, err)
	}
	var relayServices, relayLeases, ingressLeases int
	if err := inspect.QueryRowContext(t.Context(), `
		SELECT
			(SELECT COUNT(*) FROM control.relay_services),
			(SELECT COUNT(*) FROM control.relay_leases WHERE NOT draining),
			(SELECT COUNT(*) FROM control.ingress_leases WHERE NOT draining)
	`).Scan(&relayServices, &relayLeases, &ingressLeases); err != nil {
		t.Fatal(err)
	}
	if relayServices != 2 || relayLeases != 2 || ingressLeases != 1 {
		t.Fatalf("standalone topology = %d relay services, %d relay leases, %d ingress leases", relayServices, relayLeases, ingressLeases)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("standalone did not shut down within its drain deadline")
	}
}

func TestIntegrationSplitLifecycle(t *testing.T) {
	directURL := os.Getenv("TNL_TEST_POSTGRES_URL")
	if directURL == "" {
		t.Skip("TNL_TEST_POSTGRES_URL is not set")
	}
	databaseURL, inspect := standaloneTestDatabase(t, directURL)
	const serverDomain = "127.0.0.1.nip.io"
	controlHostname := "control." + serverDomain
	certificateFile, keyFile, roots := standaloneTestCertificate(t, controlHostname)
	acmeServer := standaloneTestACMEServer(t)
	controlAddress := unusedTCPAddress(t)
	privateControlAddress := unusedTCPAddress(t)
	serviceClient := splitTestServiceHTTPClient(t, roots, privateControlAddress)
	controlConfig := splitTestConfig(config.TNLDModeControl, unusedTCPAddress(t))
	controlConfig.DatabaseURL = databaseURL
	controlConfig.ControlListen = controlAddress
	controlConfig.PrivateControlListen = privateControlAddress
	controlConfig.ClusterSecret = testClusterSecret
	controlConfig.ServerDomain = serverDomain
	controlConfig.ManagedDeploymentDomain = "tunnels.test"
	controlConfig.ControlTLSCertificateFile = certificateFile
	controlConfig.ControlTLSPrivateKeyFile = keyFile
	controlConfig.ACMEDirectoryURL = acmeServer.URL + "/directory"
	controlConfig.ACMEEmail = "operator@example.test"
	controlConfig.ACMEAcceptTerms = true
	controlConfig.ACMEProfile = "tlsserver"
	controlConfig.LoginToken = testLoginToken
	controlConfig.StorageKey = testStorageKey
	controlConfig.AccessTokenLifetime = 5 * time.Minute
	controlConfig.RefreshTokenLifetime = time.Hour
	if err := controlConfig.Validate(); err != nil {
		t.Fatal(err)
	}
	control := startIntegrationProcess(t, controlConfig, acmeServer.Client(), serviceClient)
	waitForProcessReady(t, control.done, controlConfig.MetricsListen)

	ingressConfig := splitTestConfig(config.TNLDModeIngress, unusedTCPAddress(t))
	ingressConfig.ControlHostname = controlHostname
	ingressConfig.ClusterSecret = testClusterSecret
	ingressConfig.IngressID = "ingress-split"
	ingressConfig.IngressListen = unusedTCPAddress(t)
	relayAConfig := splitTestRelayConfig(t, controlHostname, "relay-a", "relay-a-1", certificateFile, keyFile)
	relayBConfig := splitTestRelayConfig(t, controlHostname, "relay-b", "relay-b-1", certificateFile, keyFile)
	for _, cfg := range []config.TNLD{ingressConfig, relayAConfig, relayBConfig} {
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	ingressProcess := startIntegrationProcess(t, ingressConfig, acmeServer.Client(), serviceClient)
	relayAProcess := startIntegrationProcess(t, relayAConfig, acmeServer.Client(), serviceClient)
	relayBProcess := startIntegrationProcess(t, relayBConfig, acmeServer.Client(), serviceClient)
	for _, process := range []*integrationProcess{ingressProcess, relayAProcess, relayBProcess} {
		waitForProcessReady(t, process.done, process.metricsAddress)
	}
	assertSplitLeases(t, inspect, 1, 2, 0, 0)

	stopIntegrationProcess(t, relayAProcess)
	var relayARunID string
	var relayARevision int64
	var relayAExpiresAt time.Time
	if err := inspect.QueryRowContext(t.Context(), `
		SELECT relay_run_id, relay_lease_revision, lease_expires_at
		FROM control.relay_leases
		WHERE relay_id = 'relay-a-1' AND draining
	`).Scan(&relayARunID, &relayARevision, &relayAExpiresAt); err != nil {
		t.Fatal(err)
	}
	if delay := time.Until(relayAExpiresAt.Add(100 * time.Millisecond)); delay > 0 {
		time.Sleep(delay)
	}
	relayAReplacementConfig := splitTestRelayConfig(t, controlHostname, "relay-a", "relay-a-1", certificateFile, keyFile)
	relayAReplacement := startIntegrationProcess(t, relayAReplacementConfig, acmeServer.Client(), serviceClient)
	waitForProcessReady(t, relayAReplacement.done, relayAReplacement.metricsAddress)
	var replacementRunID string
	var replacementRevision int64
	var replacementDraining bool
	if err := inspect.QueryRowContext(t.Context(), `
		SELECT relay_run_id, relay_lease_revision, draining
		FROM control.relay_leases
		WHERE relay_id = 'relay-a-1'
	`).Scan(&replacementRunID, &replacementRevision, &replacementDraining); err != nil {
		t.Fatal(err)
	}
	if replacementRunID == relayARunID || replacementRevision != relayARevision+1 || replacementDraining {
		t.Fatalf(
			"replacement relay lease = run %q, revision %d, draining %t; previous run %q, revision %d",
			replacementRunID, replacementRevision, replacementDraining, relayARunID, relayARevision,
		)
	}

	for _, process := range []*integrationProcess{ingressProcess, relayAReplacement, relayBProcess} {
		process.cancel()
	}
	for _, process := range []*integrationProcess{ingressProcess, relayAReplacement, relayBProcess} {
		waitForIntegrationProcess(t, process)
	}
	assertSplitLeases(t, inspect, 0, 0, 1, 2)
	serviceClient.CloseIdleConnections()
	stopIntegrationProcess(t, control)
}

type integrationProcess struct {
	cancel         context.CancelFunc
	done           chan error
	metricsAddress string
}

func startIntegrationProcess(
	t *testing.T,
	cfg config.TNLD,
	acmeHTTPClient, serviceHTTPClient *http.Client,
) *integrationProcess {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	process := &integrationProcess{cancel: cancel, done: make(chan error, 1), metricsAddress: cfg.MetricsListen}
	go func() {
		process.done <- serveWithHTTPClients(ctx, cfg, acmeHTTPClient, serviceHTTPClient)
	}()
	t.Cleanup(cancel)
	return process
}

func stopIntegrationProcess(t *testing.T, process *integrationProcess) {
	t.Helper()
	process.cancel()
	waitForIntegrationProcess(t, process)
}

func waitForIntegrationProcess(t *testing.T, process *integrationProcess) {
	t.Helper()
	select {
	case err := <-process.done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("tnld process did not shut down within its drain deadline")
	}
}

func splitTestConfig(mode config.TNLDMode, metricsAddress string) config.TNLD {
	return config.TNLD{
		Mode: mode, MetricsListen: metricsAddress,
		PublicConnectionLimit: 100, RouteConnectionLimit: 10, PublisherConnectionLimit: 10,
		RelayStreamCapacity: 100, QUICMaxIncomingStreams: 100, QUICIdleTimeout: time.Minute,
		TunnelFallbackDelay: 10 * time.Millisecond, IngressLeaseDuration: 2 * time.Second,
		RelayLeaseDuration: 2 * time.Second, LeaseRenewalInterval: 500 * time.Millisecond,
		ControlRetryInterval: 50 * time.Millisecond, RoutingTableWait: time.Second, DrainTimeout: time.Second,
	}
}

func splitTestRelayConfig(
	t *testing.T,
	controlHostname, relayServiceID, relayID, certificateFile, privateKeyFile string,
) config.TNLD {
	t.Helper()
	cfg := splitTestConfig(config.TNLDModeRelay, unusedTCPAddress(t))
	cfg.ControlHostname = controlHostname
	cfg.ClusterSecret = testClusterSecret
	cfg.RelayServiceID = relayServiceID
	cfg.RelayID = relayID
	cfg.RelayAddress = relayServiceID + ".127.0.0.1.nip.io:443"
	cfg.RelayTLSCertificateFile = certificateFile
	cfg.RelayTLSPrivateKeyFile = privateKeyFile
	cfg.RelayTCPListen = unusedTCPAddress(t)
	cfg.RelayUDPListen = unusedUDPAddress(t)
	cfg.InternalRelayListen = unusedTCPAddress(t)
	cfg.InternalRelayAddress = cfg.InternalRelayListen
	return cfg
}

func splitTestServiceHTTPClient(t *testing.T, roots *x509.CertPool, controlAddress string) *http.Client {
	t.Helper()
	dialer := new(net.Dialer)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, controlAddress)
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func assertSplitLeases(
	t *testing.T,
	database *sql.DB,
	activeIngress, activeRelays, drainingIngress, drainingRelays int,
) {
	t.Helper()
	var gotActiveIngress, gotActiveRelays, gotDrainingIngress, gotDrainingRelays int
	if err := database.QueryRowContext(t.Context(), `
		SELECT
			(SELECT count(*) FROM control.ingress_leases WHERE NOT draining AND lease_expires_at > now()),
			(SELECT count(*) FROM control.relay_leases WHERE NOT draining AND lease_expires_at > now()),
			(SELECT count(*) FROM control.ingress_leases WHERE draining),
			(SELECT count(*) FROM control.relay_leases WHERE draining)
	`).Scan(&gotActiveIngress, &gotActiveRelays, &gotDrainingIngress, &gotDrainingRelays); err != nil {
		t.Fatal(err)
	}
	if gotActiveIngress != activeIngress || gotActiveRelays != activeRelays ||
		gotDrainingIngress != drainingIngress || gotDrainingRelays != drainingRelays {
		t.Fatalf(
			"split leases = active ingress/relays %d/%d, draining ingress/relays %d/%d",
			gotActiveIngress, gotActiveRelays, gotDrainingIngress, gotDrainingRelays,
		)
	}
}

func waitForProcessReady(t *testing.T, done <-chan error, address string) {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatalf("standalone exited before readiness: %v", err)
		default:
		}
		response, err := client.Get("http://" + address + "/ready")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusNoContent {
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("standalone did not become ready")
}

func standaloneTestDatabase(t *testing.T, directURL string) (string, *sql.DB) {
	t.Helper()
	adminConfig, err := pgx.ParseConfig(directURL)
	if err != nil {
		t.Fatal(err)
	}
	admin := stdlib.OpenDB(*adminConfig)
	t.Cleanup(func() { _ = admin.Close() })
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	databaseName := "tnl_standalone_" + hex.EncodeToString(random)
	identifier := pgx.Identifier{databaseName}.Sanitize()
	if _, err := admin.ExecContext(t.Context(), "CREATE DATABASE "+identifier); err != nil {
		t.Skipf("standalone integration requires permission to create a database: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = admin.ExecContext(ctx, `
			SELECT pg_terminate_backend(pid) FROM pg_stat_activity
			WHERE datname = $1 AND pid <> pg_backend_pid()
		`, databaseName)
		_, _ = admin.ExecContext(ctx, "DROP DATABASE IF EXISTS "+identifier)
	})
	parsed, err := url.Parse(directURL)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Path, parsed.RawPath = "/"+databaseName, ""
	databaseURL := parsed.String()
	if err := controlstate.Migrate(t.Context(), databaseURL); err != nil {
		t.Fatal(err)
	}
	inspectConfig, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	inspect := stdlib.OpenDB(*inspectConfig)
	t.Cleanup(func() { _ = inspect.Close() })
	return databaseURL, inspect
}

func standaloneTestACMEServer(t *testing.T) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Replay-Nonce", "test-nonce")
		switch request.URL.Path {
		case "/directory":
			_ = json.NewEncoder(response).Encode(map[string]any{
				"newNonce": server.URL + "/nonce", "newAccount": server.URL + "/account",
				"newOrder": server.URL + "/order", "meta": map[string]any{"termsOfService": server.URL + "/terms"},
			})
		case "/nonce":
			response.WriteHeader(http.StatusNoContent)
		case "/account":
			response.Header().Set("Location", server.URL+"/account/1")
			response.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(response, `{"status":"valid","contact":["mailto:operator@example.test"]}`)
		case "/account/1":
			_, _ = io.WriteString(response, `{"status":"valid","contact":["mailto:operator@example.test"]}`)
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func standaloneTestCertificate(t *testing.T, hostname string) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{}, DNSNames: []string{hostname},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certificateFile, keyFile := filepath.Join(directory, "control.pem"), filepath.Join(directory, "control-key.pem")
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := errors.Join(os.WriteFile(certificateFile, certificatePEM, 0o600), os.WriteFile(keyFile, keyPEM, 0o600)); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(certificate)
	return certificateFile, keyFile, roots
}

func unusedTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func unusedUDPAddress(t *testing.T) string {
	t.Helper()
	connection, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := connection.LocalAddr().String()
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}
