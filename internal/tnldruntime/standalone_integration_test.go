package tnldruntime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestIntegrationStandaloneLifecycle(t *testing.T) {
	directURL := os.Getenv("TNL_TEST_POSTGRES_URL")
	if directURL == "" {
		t.Skip("TNL_TEST_POSTGRES_URL is not set")
	}
	databaseURL, inspect := standaloneTestDatabase(t, directURL)
	acmeServer := standaloneTestACMEServer(t)
	certificateAuthority := newIntegrationTestCA(t)
	controlCertificate := certificateAuthority.issueServer(t, "control.tnl.test")
	relayCertificate := certificateAuthority.issueServer(t, "relay.tnl.test")
	publicAddress := unusedTCPAddress(t)
	metricsAddress := unusedTCPAddress(t)
	cfg := config.TNLD{
		Mode: config.TNLDModeStandalone, DatabaseURL: databaseURL, MetricsListen: metricsAddress,
		ControlListen: unusedTCPAddress(t), PrivateControlListen: unusedTCPAddress(t), IngressListen: publicAddress,
		RelayTCPListen: unusedTCPAddress(t), RelayUDPListen: unusedUDPAddress(t), InternalRelayListen: unusedTCPAddress(t),
		ServerDomain: "tnl.test", ManagedDeploymentDomain: "tunnels.test",
		ControlTLSCertificateFile: controlCertificate.certificateFile,
		ControlTLSPrivateKeyFile:  controlCertificate.privateKeyFile,
		RelayTLSCertificateFile:   relayCertificate.certificateFile,
		RelayTLSPrivateKeyFile:    relayCertificate.privateKeyFile,
		ACMEDirectoryURL:          acmeServer.URL + "/directory", ACMEEmail: "operator@example.test",
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
	serviceClient := splitTestServiceHTTPClient(t, certificateAuthority.roots, cfg.PrivateControlListen)
	process := startIntegrationProcess(t, cfg, acmeServer.Client(), serviceClient)
	waitForProcessReady(t, process)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: certificateAuthority.roots, MinVersion: tls.VersionTLS13},
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

	stopIntegrationProcess(t, process)
}

func TestIntegrationSplitLifecycle(t *testing.T) {
	directURL := os.Getenv("TNL_TEST_POSTGRES_URL")
	if directURL == "" {
		t.Skip("TNL_TEST_POSTGRES_URL is not set")
	}
	databaseURL, inspect := standaloneTestDatabase(t, directURL)
	const serverDomain = "127.0.0.1.nip.io"
	controlHostname := "control." + serverDomain
	certificateAuthority := newIntegrationTestCA(t)
	controlCertificate := certificateAuthority.issueServer(t, controlHostname)
	relayACertificate := certificateAuthority.issueServer(t, "relay-a."+serverDomain)
	relayBCertificate := certificateAuthority.issueServer(t, "relay-b."+serverDomain)
	acmeServer := standaloneTestACMEServer(t)
	controlAddress := unusedTCPAddress(t)
	privateControlAddress := unusedTCPAddress(t)
	serviceClient := splitTestServiceHTTPClient(t, certificateAuthority.roots, privateControlAddress)
	controlConfig := splitTestConfig(config.TNLDModeControl, unusedTCPAddress(t))
	controlConfig.DatabaseURL = databaseURL
	controlConfig.ControlListen = controlAddress
	controlConfig.PrivateControlListen = privateControlAddress
	controlConfig.ClusterSecret = testClusterSecret
	controlConfig.ServerDomain = serverDomain
	controlConfig.ManagedDeploymentDomain = "tunnels.test"
	controlConfig.ControlTLSCertificateFile = controlCertificate.certificateFile
	controlConfig.ControlTLSPrivateKeyFile = controlCertificate.privateKeyFile
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
	waitForProcessReady(t, control)

	ingressConfig := splitTestConfig(config.TNLDModeIngress, unusedTCPAddress(t))
	ingressConfig.ControlHostname = controlHostname
	ingressConfig.ClusterSecret = testClusterSecret
	ingressConfig.IngressID = "ingress-split"
	ingressConfig.IngressListen = unusedTCPAddress(t)
	relayAConfig := splitTestRelayConfig(
		t, controlHostname, "relay-a", "relay-a-1",
		relayACertificate.certificateFile, relayACertificate.privateKeyFile,
	)
	relayBConfig := splitTestRelayConfig(
		t, controlHostname, "relay-b", "relay-b-1",
		relayBCertificate.certificateFile, relayBCertificate.privateKeyFile,
	)
	for _, cfg := range []config.TNLD{ingressConfig, relayAConfig, relayBConfig} {
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	ingressProcess := startIntegrationProcess(t, ingressConfig, acmeServer.Client(), serviceClient)
	relayAProcess := startIntegrationProcess(t, relayAConfig, acmeServer.Client(), serviceClient)
	relayBProcess := startIntegrationProcess(t, relayBConfig, acmeServer.Client(), serviceClient)
	for _, process := range []*integrationProcess{ingressProcess, relayAProcess, relayBProcess} {
		waitForProcessReady(t, process)
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
	relayAReplacementConfig := splitTestRelayConfig(
		t, controlHostname, "relay-a", "relay-a-1",
		relayACertificate.certificateFile, relayACertificate.privateKeyFile,
	)
	relayAReplacement := startIntegrationProcess(t, relayAReplacementConfig, acmeServer.Client(), serviceClient)
	waitForProcessReady(t, relayAReplacement)
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
