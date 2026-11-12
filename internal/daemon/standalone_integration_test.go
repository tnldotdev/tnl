package daemon

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

	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/naming"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationStandaloneLifecycle(t *testing.T) {
	databaseURL, inspect := standaloneTestDatabase(t)
	owner := newRuntimeTopology(t)
	acmeServer := standaloneTestACMEServer(t, owner)
	certificateAuthority := newIntegrationTestCA(t)
	controlCertificate := certificateAuthority.issueServer(t, "control.tnl.test", owner)
	relayCertificate := certificateAuthority.issueServer(t, "relay.tnl.test", owner)
	publicListener, controlProxy := serviceRuntimeListener(t, owner), serviceRuntimeListener(t, owner)
	controlListener, metrics := serviceRuntimeListener(t, owner), serviceRuntimeListener(t, owner)
	publicAddress, publicControlAddress, metricsAddress := publicListener.Addr().String(), controlProxy.Addr().String(), metrics.Addr().String()
	relayUDP := integrationPacketListener(t, owner)
	serviceListeners := newServicePortListeners(t, owner)
	ingressListener := combineIngressListeners(append([]net.Listener{publicListener}, serviceListeners...))
	owner.cleanupResource(t, func() { _ = ingressListener.Close() })
	cfg := daemonconfig.Config{
		ServicePortRanges: serviceListeners.inventory(),
		Role:              daemonconfig.RoleStandalone, DatabaseURL: databaseURL, MetricsListen: metricsAddress,
		ControlListen: controlListener.Addr().String(), PrivateControlListen: "127.0.0.1:1", IngressListen: publicAddress,
		ControlTrustedProxies: []string{"127.0.0.1/32"}, ControlClientIPHeader: "X-Forwarded-For",
		RelayTCPListen: "127.0.0.1:1", RelayUDPListen: relayUDP.LocalAddr().String(), InternalRelayListen: "127.0.0.1:1",
		ServerDomain: "tnl.test", ManagedDomain: "tunnels.test",
		ManagedURLMode:            naming.ManagedURLModeGenerated,
		ControlTLSCertificateFile: controlCertificate.certificateFile,
		ControlTLSPrivateKeyFile:  controlCertificate.privateKeyFile,
		RelayTLSCertificateFile:   relayCertificate.certificateFile,
		RelayTLSPrivateKeyFile:    relayCertificate.privateKeyFile,
		ACMEDirectoryURL:          acmeServer.URL + "/directory", ACMEEmail: "operator@example.test",
		ACMEAcceptTerms: true, ACMEProfile: "tlsserver", OIDCIssuer: testOIDCIssuer, OIDCClientID: "server",
		PublicURLCertificateWorkers: 4,
		StorageKey:                  testStorageKey,
		AccessTokenLifetime:         5 * time.Minute, RefreshTokenLifetime: time.Hour,
		VisitorConnectionLimit: 100, PublisherConnectionLimit: 10,
		ClientHelloConnectionLimit:       1024,
		StandaloneControlConnectionLimit: 1024, StandaloneRelayConnectionLimit: 4096,
		RelayStreamCapacity: 100, QUICMaxIncomingStreams: 100, QUICIdleTimeout: time.Minute,
		IngressLeaseDuration: 3 * time.Second,
		RelayLeaseDuration:   3 * time.Second, LeaseRenewalInterval: time.Second,
		ControlRetryInterval: 10 * time.Millisecond, RoutingTableWait: time.Second, DrainTimeout: 2 * time.Second,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	serviceClient := splitTestServiceHTTPClient(t, certificateAuthority.roots, cfg.PrivateControlListen, owner)
	controlTLS, err := staticServerTLS(controlCertificate.certificateFile, controlCertificate.privateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	serveIntegrationControlProxy(t, owner, controlProxy, cfg.ControlListen, controlTLS)
	process := startIntegrationProcessWithOptions(t, cfg, integrationProcessOptions{owner: owner, acmeHTTPClient: acmeServer.Client(), serviceHTTPClient: serviceClient, listeners: runtimeListeners{control: controlListener, metrics: metrics, ingress: ingressListener, relayUDP: relayUDP}})
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
		"tnl_ingress_backend_streams", "tnl_relay_visitor_stream_slots_occupied",
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
			return new(net.Dialer).DialContext(ctx, network, publicControlAddress)
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
	readinessResponse, err := client.Get("https://control.tnl.test/v1/ready")
	if err != nil {
		t.Fatal(err)
	}
	defer readinessResponse.Body.Close()
	var readiness controlv1.ReadinessResponse
	if err := json.NewDecoder(readinessResponse.Body).Decode(&readiness); err != nil ||
		readinessResponse.StatusCode != http.StatusOK || readiness.Status != controlv1.ReadinessResponseStatusReady ||
		readiness.Checks.Database != controlv1.ReadinessResponseChecksDatabaseOk ||
		readiness.Checks.Control != controlv1.ReadinessResponseChecksControlOk ||
		readiness.Checks.Ingress == nil || *readiness.Checks.Ingress != controlv1.ReadinessResponseChecksIngressOk ||
		readiness.Checks.Relay == nil || *readiness.Checks.Relay != controlv1.ReadinessResponseChecksRelayOk {
		t.Fatalf("standalone readiness = %s, %#v, %v", readinessResponse.Status, readiness, err)
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
	owner := newRuntimeTopology(t)
	const serverDomain = "127.0.0.1.nip.io"
	controlHostname := "control." + serverDomain
	certificateAuthority := newIntegrationTestCA(t)
	controlCertificate := certificateAuthority.issueServer(t, controlHostname, owner)
	relayACertificate := certificateAuthority.issueServer(t, "relay-a."+serverDomain, owner)
	relayBCertificate := certificateAuthority.issueServer(t, "relay-b."+serverDomain, owner)
	acmeServer := standaloneTestACMEServer(t, owner)
	controlSockets := runtimeListeners{control: serviceRuntimeListener(t, owner), privateControl: serviceRuntimeListener(t, owner), metrics: serviceRuntimeListener(t, owner)}
	controlAddress, privateControlAddress := controlSockets.control.Addr().String(), controlSockets.privateControl.Addr().String()
	serviceClient := splitTestServiceHTTPClient(t, certificateAuthority.roots, privateControlAddress, owner)
	controlConfig := splitTestConfig(daemonconfig.RoleControl, controlSockets.metrics.Addr().String())
	serviceListeners := newServicePortListeners(t, owner)
	controlConfig.ServicePortRanges = serviceListeners.inventory()
	controlConfig.DatabaseURL = databaseURL
	controlConfig.ControlListen = controlAddress
	controlConfig.PrivateControlListen = privateControlAddress
	controlConfig.ClusterSecret = testClusterSecret
	controlConfig.ServerDomain = serverDomain
	controlConfig.ManagedDomain = "tunnels.test"
	controlConfig.ControlTLSCertificateFile = controlCertificate.certificateFile
	controlConfig.ControlTLSPrivateKeyFile = controlCertificate.privateKeyFile
	controlConfig.ACMEDirectoryURL = acmeServer.URL + "/directory"
	controlConfig.ACMEEmail = "operator@example.test"
	controlConfig.ACMEAcceptTerms = true
	controlConfig.ACMEProfile = "tlsserver"
	controlConfig.OIDCIssuer, controlConfig.OIDCClientID = testOIDCIssuer, "server"
	controlConfig.StorageKey = testStorageKey
	controlConfig.AccessTokenLifetime = 5 * time.Minute
	controlConfig.RefreshTokenLifetime = time.Hour
	if err := controlConfig.Validate(); err != nil {
		t.Fatal(err)
	}
	control := startIntegrationProcessWithOptions(t, controlConfig, integrationProcessOptions{owner: owner, acmeHTTPClient: acmeServer.Client(), serviceHTTPClient: serviceClient, listeners: controlSockets})
	waitForProcessReady(t, control)

	ingressSockets := runtimeListeners{ingress: serviceRuntimeListener(t, owner), metrics: serviceRuntimeListener(t, owner)}
	ingressConfig := splitTestConfig(daemonconfig.RoleIngress, ingressSockets.metrics.Addr().String())
	ingressConfig.ServicePortRanges = controlConfig.ServicePortRanges
	ingressConfig.ControlHostname = controlHostname
	ingressConfig.ClusterSecret = testClusterSecret
	ingressConfig.IngressID = "ingress-split"
	ingressConfig.IngressListen = ingressSockets.ingress.Addr().String()
	ingressSockets.ingress = combineIngressListeners(append([]net.Listener{ingressSockets.ingress}, serviceListeners...))
	owner.cleanupResource(t, func() { _ = ingressSockets.ingress.Close() })
	relayAConfig, relayAListeners := splitTestRelayConfig(
		t, controlHostname, "relay-a", "relay-a-1",
		relayACertificate.certificateFile, relayACertificate.privateKeyFile, owner,
	)
	relayBConfig, relayBListeners := splitTestRelayConfig(
		t, controlHostname, "relay-b", "relay-b-1",
		relayBCertificate.certificateFile, relayBCertificate.privateKeyFile, owner,
	)
	for _, cfg := range []daemonconfig.Config{ingressConfig, relayAConfig, relayBConfig} {
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	ingressProcess := startIntegrationProcessWithOptions(t, ingressConfig, integrationProcessOptions{owner: owner, acmeHTTPClient: acmeServer.Client(), serviceHTTPClient: serviceClient, listeners: ingressSockets})
	relayAProcess := startIntegrationProcessWithOptions(t, relayAConfig, integrationProcessOptions{owner: owner, acmeHTTPClient: acmeServer.Client(), serviceHTTPClient: serviceClient, listeners: relayAListeners})
	relayBProcess := startIntegrationProcessWithOptions(t, relayBConfig, integrationProcessOptions{owner: owner, acmeHTTPClient: acmeServer.Client(), serviceHTTPClient: serviceClient, listeners: relayBListeners})
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
	relayAReplacementConfig, replacementListeners := splitTestRelayConfig(
		t, controlHostname, "relay-a", "relay-a-1",
		relayACertificate.certificateFile, relayACertificate.privateKeyFile, owner,
	)
	relayAReplacement := startIntegrationProcessWithOptions(t, relayAReplacementConfig, integrationProcessOptions{owner: owner, acmeHTTPClient: acmeServer.Client(), serviceHTTPClient: serviceClient, listeners: replacementListeners})
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
