package tnldruntime

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/publisher"
)

func TestIntegrationSplitPublishAndVisit(t *testing.T) {
	fixture := newSplitPublishFixture(t, "split")
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("X-Tnl-Integration", "split")
		_, _ = io.WriteString(response, request.URL.RequestURI())
	}))
	t.Cleanup(target.Close)
	quicConnector, tcpConnector := fixture.connectors()
	handle := fixture.startPublisher(t, target.URL, quicConnector, tcpConnector)
	ready := fixture.waitReady(t, handle)
	assertSplitRoutePlacement(t, fixture.inspect, ready.RouteID, ready.RouteVersion)

	response, body, err := fixture.visitor.requestURL(http.MethodGet, ready.PublicURL+"/through-split?source=integration", nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "/through-split?source=integration" ||
		response.Header.Get("X-Tnl-Integration") != "split" {
		t.Fatalf("split visitor response = %s, headers %#v, body %q", response.Status, response.Header, body)
	}
	assertIntegrationRouteCertificate(t, response, fixture.identity.hostname)
}

func TestIntegrationSplitRelayLossAndReplenishment(t *testing.T) {
	fixture := newSplitPublishFixture(t, "relay-loss")
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, "relay recovery")
	}))
	t.Cleanup(target.Close)
	quicConnector, tcpConnector := fixture.connectors()
	handle := fixture.startPublisher(t, target.URL, quicConnector, tcpConnector)
	ready := fixture.waitReady(t, handle)
	beforeConnection := readSplitConnectionState(t, fixture.inspect, ready.RouteID, ready.RouteVersion, "relay-a")
	beforeLease := readSplitRelayLease(t, fixture.inspect, fixture.relayA.config.RelayID)

	stopIntegrationProcess(t, fixture.relayA.process)
	stoppedLease := readSplitRelayLease(t, fixture.inspect, fixture.relayA.config.RelayID)
	waitForReadyPublisherConnections(t, fixture.inspect, ready.RouteID, ready.RouteVersion, 1)
	waitForIngressRoutingCurrent(t, fixture.inspect, 1)
	response, body, err := fixture.visitor.requestURL(http.MethodGet, ready.PublicURL+"/during-relay-loss", nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "relay recovery" {
		t.Fatalf("visitor during relay loss = %s, %q", response.Status, body)
	}
	assertRouteVersion(t, fixture.inspect, ready.RouteID, ready.RouteVersion)

	waitUntilIntegrationTime(t, stoppedLease.expiresAt.Add(25*time.Millisecond))
	fixture.relayA.process = fixture.startRelay(t, fixture.relayA.config)
	t.Cleanup(func() {
		fixture.stopDataPlane(t, handle)
	})
	waitForProcessReady(t, fixture.relayA.process)
	waitForReadyPublisherConnections(t, fixture.inspect, ready.RouteID, ready.RouteVersion, 2)
	waitForIngressRoutingCurrent(t, fixture.inspect, 1)
	afterConnection := readSplitConnectionState(t, fixture.inspect, ready.RouteID, ready.RouteVersion, "relay-a")
	afterLease := readSplitRelayLease(t, fixture.inspect, fixture.relayA.config.RelayID)
	if afterLease.runID == beforeLease.runID || afterLease.revision != beforeLease.revision+1 {
		t.Fatalf(
			"replacement relay lease = run %q revision %d, want a new run after %q revision %d",
			afterLease.runID, afterLease.revision, beforeLease.runID, beforeLease.revision,
		)
	}
	if afterConnection.publisherConnectionID == beforeConnection.publisherConnectionID ||
		afterConnection.assignmentRevision != beforeConnection.assignmentRevision+1 ||
		afterConnection.connectedRelayRunID != afterLease.runID {
		t.Fatalf("replacement publisher connection = before %#v, after %#v, lease %#v", beforeConnection, afterConnection, afterLease)
	}
	assertRouteVersion(t, fixture.inspect, ready.RouteID, ready.RouteVersion)
	response, body, err = fixture.visitor.requestURL(http.MethodGet, ready.PublicURL+"/after-relay-recovery", nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "relay recovery" {
		t.Fatalf("visitor after relay recovery = %s, %q", response.Status, body)
	}
}

func TestIntegrationControlRestartPreservesDataPlane(t *testing.T) {
	fixture := newSplitPublishFixture(t, "control-restart")
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, "control restart")
	}))
	t.Cleanup(target.Close)
	quicConnector, tcpConnector := fixture.connectors()
	handle := fixture.startPublisher(t, target.URL, quicConnector, tcpConnector)
	ready := fixture.waitReady(t, handle)
	beforeIngress := readSplitIngressLease(t, fixture.inspect, fixture.ingressConfig.IngressID)
	beforeRelayA := readSplitRelayLease(t, fixture.inspect, fixture.relayA.config.RelayID)
	beforeRelayB := readSplitRelayLease(t, fixture.inspect, fixture.relayB.config.RelayID)
	originalDeadline := beforeIngress.expiresAt
	for _, expiresAt := range []time.Time{beforeRelayA.expiresAt, beforeRelayB.expiresAt} {
		if expiresAt.After(originalDeadline) {
			originalDeadline = expiresAt
		}
	}

	stopIntegrationProcess(t, fixture.control)
	response, body, err := fixture.visitor.requestURL(http.MethodGet, ready.PublicURL+"/without-control", nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "control restart" {
		t.Fatalf("visitor while control was stopped = %s, %q", response.Status, body)
	}
	if !time.Now().Before(originalDeadline) {
		t.Fatal("control did not restart before the existing process leases expired")
	}
	fixture.control = startIntegrationProcessWithOptions(t, fixture.controlConfig, fixture.controlOptions)
	// The replacement control registers after the data-plane cleanups, so drain
	// those processes explicitly while the replacement control is still alive.
	t.Cleanup(func() {
		fixture.stopDataPlane(t, handle)
	})
	waitForProcessReady(t, fixture.control)

	waitForIntegrationCondition(t, 10*time.Second, func() (bool, error) {
		ingress := readSplitIngressLeaseResult(fixture.inspect, fixture.ingressConfig.IngressID)
		relayA := readSplitRelayLeaseResult(fixture.inspect, fixture.relayA.config.RelayID)
		relayB := readSplitRelayLeaseResult(fixture.inspect, fixture.relayB.config.RelayID)
		for _, lease := range []splitProcessLease{ingress, relayA, relayB} {
			if lease.err != nil {
				return false, lease.err
			}
		}
		if ingress.runID != beforeIngress.runID || ingress.revision != beforeIngress.revision ||
			relayA.runID != beforeRelayA.runID || relayA.revision != beforeRelayA.revision ||
			relayB.runID != beforeRelayB.runID || relayB.revision != beforeRelayB.revision {
			return false, fmt.Errorf("process identity changed across control restart")
		}
		return ingress.expiresAt.After(originalDeadline) && relayA.expiresAt.After(originalDeadline) &&
			relayB.expiresAt.After(originalDeadline), nil
	})
	waitUntilIntegrationTime(t, originalDeadline.Add(25*time.Millisecond))
	waitForReadyPublisherConnections(t, fixture.inspect, ready.RouteID, ready.RouteVersion, 2)
	assertRouteVersion(t, fixture.inspect, ready.RouteID, ready.RouteVersion)
	response, body, err = fixture.visitor.requestURL(http.MethodGet, ready.PublicURL+"/after-control-restart", nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "control restart" {
		t.Fatalf("visitor after control restart = %s, %q", response.Status, body)
	}
}

type splitRelayFixture struct {
	config  config.TNLD
	process *integrationProcess
}

type splitPublishFixture struct {
	databaseURL string
	inspect     *sql.DB
	pebble      integrationPebble
	roots       *tls.Config

	controlConfig  config.TNLD
	controlOptions integrationProcessOptions
	ingressConfig  config.TNLD
	control        *integrationProcess
	ingress        *integrationProcess
	relayA         splitRelayFixture
	relayB         splitRelayFixture

	serviceHTTP *http.Client
	controlHTTP *http.Client
	identity    *integrationPublishingIdentity
	visitor     *integrationVisitor
}

func newSplitPublishFixture(t *testing.T, hostnameLabel string) *splitPublishFixture {
	t.Helper()
	directURL := os.Getenv("TNL_TEST_POSTGRES_URL")
	if directURL == "" {
		t.Skip("TNL_TEST_POSTGRES_URL is not set")
	}
	databaseURL, inspect := standaloneTestDatabase(t, directURL)
	const serverDomain = "split.integration.test"
	controlHostname := "control." + serverDomain
	certificateAuthority := newIntegrationTestCA(t)
	controlCertificate := certificateAuthority.issueServer(t, controlHostname)
	relayACertificate := certificateAuthority.issueServer(t, "relay-a."+serverDomain)
	relayBCertificate := certificateAuthority.issueServer(t, "relay-b."+serverDomain)
	controlAddress := unusedTCPAddress(t)
	privateControlAddress := unusedTCPAddress(t)
	ingressAddress := unusedTCPAddress(t)
	dnsAddress := startIntegrationDNS(t)
	pebble := startIntegrationPebble(t, integrationPort(t, ingressAddress), dnsAddress)
	serviceHTTP := splitTestServiceHTTPClient(t, certificateAuthority.roots, privateControlAddress)

	controlConfig := splitPublishConfig(t, config.TNLDModeControl)
	controlConfig.DatabaseURL = databaseURL
	controlConfig.ControlListen = controlAddress
	controlConfig.PrivateControlListen = privateControlAddress
	controlConfig.ClusterSecret = testClusterSecret
	controlConfig.ServerDomain = serverDomain
	controlConfig.ManagedDeploymentDomain = "routes." + serverDomain
	controlConfig.ControlTLSCertificateFile = controlCertificate.certificateFile
	controlConfig.ControlTLSPrivateKeyFile = controlCertificate.privateKeyFile
	controlConfig.ACMEDirectoryURL = pebble.directoryURL
	controlConfig.ACMEEmail = "integration@example.test"
	controlConfig.ACMEAcceptTerms = true
	controlConfig.ACMEProfile = "tlsserver"
	controlConfig.LoginToken = testLoginToken
	controlConfig.StorageKey = testStorageKey
	controlConfig.AccessTokenLifetime = 5 * time.Minute
	controlConfig.RefreshTokenLifetime = time.Hour
	if err := controlConfig.Validate(); err != nil {
		t.Fatal(err)
	}
	controlOptions := integrationProcessOptions{acmeHTTPClient: pebble.httpClient, serviceHTTPClient: serviceHTTP}
	control := startIntegrationProcessWithOptions(t, controlConfig, controlOptions)
	waitForProcessReady(t, control)

	ingressConfig := splitPublishConfig(t, config.TNLDModeIngress)
	ingressConfig.ControlHostname = controlHostname
	ingressConfig.ClusterSecret = testClusterSecret
	ingressConfig.IngressID = "ingress-split"
	ingressConfig.IngressListen = ingressAddress
	relayAConfig := splitPublishRelayConfig(
		t, controlHostname, serverDomain, "relay-a", "relay-a-1", relayACertificate,
	)
	relayBConfig := splitPublishRelayConfig(
		t, controlHostname, serverDomain, "relay-b", "relay-b-1", relayBCertificate,
	)
	for _, cfg := range []config.TNLD{ingressConfig, relayAConfig, relayBConfig} {
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	fixture := &splitPublishFixture{
		databaseURL: databaseURL, inspect: inspect, pebble: pebble,
		roots:         &tls.Config{RootCAs: certificateAuthority.roots, MinVersion: tls.VersionTLS13},
		controlConfig: controlConfig, controlOptions: controlOptions, ingressConfig: ingressConfig,
		control: control, serviceHTTP: serviceHTTP,
		relayA: splitRelayFixture{config: relayAConfig}, relayB: splitRelayFixture{config: relayBConfig},
	}
	fixture.relayA.process = fixture.startRelay(t, relayAConfig)
	fixture.relayB.process = fixture.startRelay(t, relayBConfig)
	fixture.ingress = startIntegrationProcessWithOptions(t, ingressConfig, integrationProcessOptions{
		acmeHTTPClient: pebble.httpClient, serviceHTTPClient: serviceHTTP,
		relayClientTLS: fixture.roots,
	})
	for _, process := range []*integrationProcess{fixture.relayA.process, fixture.relayB.process, fixture.ingress} {
		waitForProcessReady(t, process)
	}
	assertSplitLeases(t, inspect, 1, 2, 0, 0)
	controlHTTP, _ := newIntegrationHTTPSClient(t, certificateAuthority.roots, controlAddress, false)
	fixture.identity = newIntegrationPublishingIdentity(t, "https://"+controlHostname, controlHTTP, hostnameLabel)
	fixture.controlHTTP = controlHTTP
	fixture.visitor = newIntegrationVisitor(t, pebble.roots, ingressAddress)
	return fixture
}

func splitPublishConfig(t *testing.T, mode config.TNLDMode) config.TNLD {
	t.Helper()
	cfg := splitTestConfig(mode, "")
	cfg.MetricsListen = unusedTCPAddress(t)
	cfg.IngressLeaseDuration = 5 * time.Second
	cfg.RelayLeaseDuration = 5 * time.Second
	cfg.LeaseRenewalInterval = 500 * time.Millisecond
	cfg.DrainTimeout = 5 * time.Second
	return cfg
}

func splitPublishRelayConfig(
	t *testing.T,
	controlHostname, serverDomain, relayServiceID, relayID string,
	certificate integrationCertificate,
) config.TNLD {
	t.Helper()
	cfg := splitPublishConfig(t, config.TNLDModeRelay)
	cfg.ControlHostname = controlHostname
	cfg.ClusterSecret = testClusterSecret
	cfg.RelayServiceID = relayServiceID
	cfg.RelayID = relayID
	cfg.RelayAddress = relayServiceID + "." + serverDomain + ":443"
	cfg.RelayTLSCertificateFile = certificate.certificateFile
	cfg.RelayTLSPrivateKeyFile = certificate.privateKeyFile
	cfg.RelayTCPListen = unusedTCPAddress(t)
	cfg.RelayUDPListen = unusedUDPAddress(t)
	cfg.InternalRelayListen = unusedTCPAddress(t)
	cfg.InternalRelayAddress = cfg.InternalRelayListen
	return cfg
}

func (f *splitPublishFixture) startRelay(t *testing.T, cfg config.TNLD) *integrationProcess {
	t.Helper()
	return startIntegrationProcessWithOptions(t, cfg, integrationProcessOptions{
		acmeHTTPClient: f.pebble.httpClient, serviceHTTPClient: f.serviceHTTP,
	})
}

func (f *splitPublishFixture) connectors() (muxsession.Connector, muxsession.Connector) {
	quicAddresses := map[string]string{
		f.relayA.config.RelayAddress: f.relayA.config.RelayUDPListen,
		f.relayB.config.RelayAddress: f.relayB.config.RelayUDPListen,
	}
	tcpAddresses := map[string]string{
		f.relayA.config.RelayAddress: f.relayA.config.RelayTCPListen,
		f.relayB.config.RelayAddress: f.relayB.config.RelayTCPListen,
	}
	return routeIntegrationConnector(quicAddresses, muxsession.QUICConnector{TLSConfig: f.roots}),
		routeIntegrationConnector(tcpAddresses, muxsession.TLSYamuxConnector{TLSConfig: f.roots})
}

func (f *splitPublishFixture) startPublisher(
	t *testing.T,
	target string,
	quicConnector, tcpConnector muxsession.Connector,
) *integrationPublisher {
	t.Helper()
	return startIntegrationPublisher(t, f.identity.publisherConfig(target, quicConnector, tcpConnector), func() string {
		return integrationPublisherDiagnostics(f.inspect, f.pebble.logPath)
	})
}

func (f *splitPublishFixture) waitReady(t *testing.T, handle *integrationPublisher) publisher.Event {
	t.Helper()
	ready := waitForPublisherReady(t, handle)
	if ready.Hostname != f.identity.hostname || ready.PublicURL != "https://"+f.identity.hostname {
		t.Fatalf("publisher ready event = %#v", ready)
	}
	waitForReadyPublisherConnections(t, f.inspect, ready.RouteID, ready.RouteVersion, 2)
	waitForIngressRoutingCurrent(t, f.inspect, 1)
	return ready
}

func (f *splitPublishFixture) stopDataPlane(t *testing.T, handle *integrationPublisher) {
	t.Helper()
	stopIntegrationPublisher(t, handle)
	stopIntegrationProcess(t, f.ingress)
	stopIntegrationProcess(t, f.relayB.process)
	stopIntegrationProcess(t, f.relayA.process)
	f.serviceHTTP.CloseIdleConnections()
	f.controlHTTP.CloseIdleConnections()
	f.visitor.transport.CloseIdleConnections()
}

type splitConnectionState struct {
	publisherConnectionID string
	assignmentRevision    int64
	connectedRelayRunID   string
}

func readSplitConnectionState(
	t *testing.T,
	database *sql.DB,
	routeID string,
	routeVersion uint64,
	relayServiceID string,
) splitConnectionState {
	t.Helper()
	var state splitConnectionState
	if err := database.QueryRowContext(t.Context(), `
		SELECT publisher_connection_id, connection_assignment_revision, connected_relay_run_id
		FROM control.route_session_connections
		WHERE route_id = $1 AND route_version = $2 AND relay_service_id = $3 AND state = 'ready'
	`, routeID, routeVersion, relayServiceID).Scan(
		&state.publisherConnectionID, &state.assignmentRevision, &state.connectedRelayRunID,
	); err != nil {
		t.Fatal(err)
	}
	return state
}

type splitProcessLease struct {
	runID     string
	revision  int64
	expiresAt time.Time
	err       error
}

func readSplitRelayLease(t *testing.T, database *sql.DB, relayID string) splitProcessLease {
	t.Helper()
	lease := readSplitRelayLeaseResult(database, relayID)
	if lease.err != nil {
		t.Fatal(lease.err)
	}
	return lease
}

func readSplitRelayLeaseResult(database *sql.DB, relayID string) splitProcessLease {
	var lease splitProcessLease
	lease.err = database.QueryRow(`
		SELECT relay_run_id, relay_lease_revision, lease_expires_at
		FROM control.relay_leases
		WHERE relay_id = $1
	`, relayID).Scan(&lease.runID, &lease.revision, &lease.expiresAt)
	return lease
}

func readSplitIngressLease(t *testing.T, database *sql.DB, ingressID string) splitProcessLease {
	t.Helper()
	lease := readSplitIngressLeaseResult(database, ingressID)
	if lease.err != nil {
		t.Fatal(lease.err)
	}
	return lease
}

func readSplitIngressLeaseResult(database *sql.DB, ingressID string) splitProcessLease {
	var lease splitProcessLease
	lease.err = database.QueryRow(`
		SELECT ingress_run_id, ingress_lease_revision, lease_expires_at
		FROM control.ingress_leases
		WHERE ingress_id = $1
	`, ingressID).Scan(&lease.runID, &lease.revision, &lease.expiresAt)
	return lease
}

func assertSplitRoutePlacement(t *testing.T, database *sql.DB, routeID string, routeVersion uint64) {
	t.Helper()
	var connections, services, relays int
	if err := database.QueryRowContext(t.Context(), `
		SELECT count(*), count(DISTINCT relay_service_id), count(DISTINCT connected_relay_id)
		FROM control.route_session_connections
		WHERE route_id = $1 AND route_version = $2 AND state = 'ready'
	`, routeID, routeVersion).Scan(&connections, &services, &relays); err != nil {
		t.Fatal(err)
	}
	if connections != 2 || services != 2 || relays != 2 {
		t.Fatalf("split route placement = %d connections across %d services and %d relays", connections, services, relays)
	}
}

func assertRouteVersion(t *testing.T, database *sql.DB, routeID string, routeVersion uint64) {
	t.Helper()
	var current int64
	if err := database.QueryRowContext(t.Context(), `
		SELECT route_version
		FROM control.route_sessions
		WHERE route_id = $1 AND closed_at IS NULL
	`, routeID).Scan(&current); err != nil {
		t.Fatal(err)
	}
	if uint64(current) != routeVersion {
		t.Fatalf("route version = %d, want %d", current, routeVersion)
	}
}

func waitUntilIntegrationTime(t *testing.T, at time.Time) {
	t.Helper()
	delay := time.Until(at)
	if delay <= 0 {
		return
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
		t.Fatal(context.Cause(t.Context()))
	}
}
