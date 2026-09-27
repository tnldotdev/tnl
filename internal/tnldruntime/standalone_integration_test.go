package tnldruntime

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/tnldconfig"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestIntegrationStandaloneLifecycle(t *testing.T) {
	databaseURL, inspect := standaloneTestDatabase(t)
	acmeServer := standaloneTestACMEServer(t)
	certificateAuthority := newIntegrationTestCA(t)
	controlCertificate := certificateAuthority.issueServer(t, "control.tnl.test")
	relayCertificate := certificateAuthority.issueServer(t, "relay.tnl.test")
	publicAddress := unusedTCPAddress(t)
	metricsAddress := unusedTCPAddress(t)
	cfg := tnldconfig.Config{
		Role: tnldconfig.RoleStandalone, DatabaseURL: databaseURL, MetricsListen: metricsAddress,
		ControlListen: "127.0.0.1:1", PrivateControlListen: "127.0.0.1:1", IngressListen: publicAddress,
		RelayTCPListen: "127.0.0.1:1", RelayUDPListen: unusedUDPAddress(t), InternalRelayListen: "127.0.0.1:1",
		ServerDomain: "tnl.test", ManagedDeploymentDomain: "tunnels.test",
		ControlTLSCertificateFile: controlCertificate.certificateFile,
		ControlTLSPrivateKeyFile:  controlCertificate.privateKeyFile,
		RelayTLSCertificateFile:   relayCertificate.certificateFile,
		RelayTLSPrivateKeyFile:    relayCertificate.privateKeyFile,
		ACMEDirectoryURL:          acmeServer.URL + "/directory", ACMEEmail: "operator@example.test",
		ACMEAcceptTerms: true, ACMEProfile: "tlsserver", LoginToken: testLoginToken,
		PublicURLCertificateWorkers: 4,
		StorageKey:                  testStorageKey,
		AccessTokenLifetime:         5 * time.Minute, RefreshTokenLifetime: time.Hour,
		VisitorConnectionLimit: 100, PublisherConnectionLimit: 10,
		ClientHelloConnectionLimit: 1024, ChallengeConnectionLimit: 1024, ChallengeHostnameConnectionLimit: 8,
		StandaloneControlConnectionLimit: 1024, StandaloneRelayConnectionLimit: 4096,
		RelayStreamCapacity: 100, QUICMaxIncomingStreams: 100, QUICIdleTimeout: time.Minute,
		IngressLeaseDuration: 3 * time.Second,
		RelayLeaseDuration:   3 * time.Second, LeaseRenewalInterval: time.Second,
		ControlRetryInterval: 10 * time.Millisecond, RoutingTableWait: time.Second, DrainTimeout: 2 * time.Second,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	serviceClient := splitTestServiceHTTPClient(t, certificateAuthority.roots, cfg.PrivateControlListen)
	process := startIntegrationProcess(t, cfg, acmeServer.Client(), serviceClient)
	waitForProcessReady(t, process)
	metricsResponse, err := http.Get("http://" + metricsAddress + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	metricsBody, readErr := io.ReadAll(metricsResponse.Body)
	closeErr := metricsResponse.Body.Close()
	if readErr != nil || closeErr != nil || metricsResponse.StatusCode != http.StatusOK {
		t.Fatalf("read standalone metrics: status=%s read=%v close=%v", metricsResponse.Status, readErr, closeErr)
	}
	metricsText := string(metricsBody)
	for _, want := range []string{
		"tnl_database_client_connections", "tnl_database_operations_omitted",
		`tnl_streams_active{stage="ingress"}`, `tnl_streams_active{stage="relay"}`,
	} {
		if !strings.Contains(metricsText, want) {
			t.Errorf("standalone metrics missing %q", want)
		}
	}
	if strings.Contains(metricsText, "tnl_public_urls") {
		t.Error("standalone metrics retained the unwired route family")
	}

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
	if err := inspect.QueryRowContext(integrationOperationContext(t), `
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
	databaseURL, inspect := standaloneTestDatabase(t)
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
	controlConfig := splitTestConfig(tnldconfig.RoleControl, unusedTCPAddress(t))
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

	ingressConfig := splitTestConfig(tnldconfig.RoleIngress, unusedTCPAddress(t))
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
	for _, cfg := range []tnldconfig.Config{ingressConfig, relayAConfig, relayBConfig} {
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
	if err := inspect.QueryRowContext(integrationOperationContext(t), `
		SELECT relay_run_id, relay_lease_revision, lease_expires_at
		FROM control.relay_leases
		WHERE relay_id = 'relay-a-1' AND draining
	`).Scan(&relayARunID, &relayARevision, &relayAExpiresAt); err != nil {
		t.Fatal(err)
	}
	waitUntilIntegrationTime(t, relayAExpiresAt.Add(100*time.Millisecond))
	relayAReplacementConfig := splitTestRelayConfig(
		t, controlHostname, "relay-a", "relay-a-1",
		relayACertificate.certificateFile, relayACertificate.privateKeyFile,
	)
	relayAReplacement := startIntegrationProcess(t, relayAReplacementConfig, acmeServer.Client(), serviceClient)
	waitForProcessReady(t, relayAReplacement)
	var replacementRunID string
	var replacementRevision int64
	var replacementDraining bool
	if err := inspect.QueryRowContext(integrationOperationContext(t), `
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
