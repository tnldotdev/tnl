package tnldruntime

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
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

func TestIntegrationControlRestartResumesCertificateOrder(t *testing.T) {
	blocked := make(chan context.Context, 1)
	resume := make(chan struct{})
	release := sync.OnceFunc(func() { close(resume) })
	defer release()
	var newOrders atomic.Int64
	fixture := newSplitPublishFixtureWithOptions(t, "issuance-restart", splitPublishOptions{}, func(client *http.Client) {
		base := client.Transport
		client.Timeout = 10 * time.Second
		client.Transport = splitACMERoundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.Method == http.MethodPost && request.URL.Path == "/order-plz" {
				newOrders.Add(1)
			}
			// Pebble authorizations are fetched only after the order URL is saved.
			if strings.HasPrefix(request.URL.Path, "/authZ/") {
				select {
				case blocked <- request.Context():
				default:
				}
				select {
				case <-resume:
				case <-request.Context().Done():
					_ = request.Body.Close()
					return nil, request.Context().Err()
				}
			}
			return base.RoundTrip(request)
		})
	})
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, "resumed certificate order")
	}))
	t.Cleanup(target.Close)
	quicConnector, tcpConnector := fixture.connectors()
	handle := fixture.startPublisher(t, target.URL, quicConnector, tcpConnector)
	var authorizationContext context.Context
	select {
	case authorizationContext = <-blocked:
	case <-handle.done:
		t.Fatalf("publisher stopped before authorization: %v%s", handle.result(), handle.diagnostics())
	case <-time.After(30 * time.Second):
		t.Fatalf("ACME authorization did not reach the gate%s", handle.diagnostics())
	}

	var orderID, orderURL, routeSessionID, routeID, accountURL, workerID string
	var routeVersion uint64
	var pending bool
	if err := fixture.inspect.QueryRowContext(t.Context(), `
		SELECT orders.id, orders.order_url, orders.route_session_id, orders.route_id,
			orders.route_version, accounts.account_url, orders.work_owner,
			orders.state = 'authorizing' AND orders.challenge_method = 'tls-alpn-01'
			AND orders.certificate_pem IS NULL AND orders.installed_at IS NULL
			AND sessions.certificate_installed_at IS NULL AND sessions.ready_at IS NULL
		FROM control.acme_orders AS orders
		JOIN control.route_sessions AS sessions ON sessions.id = orders.route_session_id
		JOIN control.acme_accounts AS accounts ON accounts.id = orders.account_id
		WHERE orders.certificate_identifiers = ARRAY[$1]::text[]
	`, fixture.identity.hostname).Scan(
		&orderID, &orderURL, &routeSessionID, &routeID, &routeVersion, &accountURL, &workerID, &pending,
	); err != nil {
		t.Fatal(err)
	}
	if !pending || orderURL == "" || accountURL == "" || newOrders.Load() != 1 {
		t.Fatalf("expected one persisted TLS-ALPN order and registered account, with no certificate before restart: pending %v, order %q, account %q, new orders %d",
			pending, orderURL, accountURL, newOrders.Load())
	}
	beforeLeases := []splitProcessLease{
		readSplitIngressLease(t, fixture.inspect, fixture.ingressConfig.IngressID),
		readSplitRelayLease(t, fixture.inspect, fixture.relayA.config.RelayID),
		readSplitRelayLease(t, fixture.inspect, fixture.relayB.config.RelayID),
	}
	stopIntegrationProcess(t, fixture.control)
	if !errors.Is(authorizationContext.Err(), context.Canceled) {
		t.Fatalf("blocked certificate worker was not canceled by control shutdown: %v", authorizationContext.Err())
	}
	// The canceled operation retains its work lease. Expire only that stopped
	// worker's lease instead of waiting two minutes; data-plane leases stay real.
	result, err := fixture.inspect.ExecContext(t.Context(), `
		UPDATE control.acme_orders SET work_expires_at = now()
		WHERE id = $1 AND order_url = $2 AND work_owner = $3 AND state = 'authorizing'
		  AND certificate_pem IS NULL AND installed_at IS NULL
	`, orderID, orderURL, workerID)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		t.Fatalf("expire stopped certificate worker lease = %d rows, %v", count, err)
	}
	fixture.control = startIntegrationProcessWithOptions(t, fixture.controlConfig, fixture.controlOptions)
	t.Cleanup(func() { fixture.stopDataPlane(t, handle) })
	waitForProcessReady(t, fixture.control)
	release()
	ready := fixture.waitReady(t, handle)
	if ready.RouteID != routeID || ready.RouteVersion != routeVersion {
		t.Fatalf("publisher changed route across issuance restart: %s version %d, want %s version %d",
			ready.RouteID, ready.RouteVersion, routeID, routeVersion)
	}
	waitForIntegrationCondition(t, 10*time.Second, func() (bool, error) {
		afterLeases := []splitProcessLease{
			readSplitIngressLeaseResult(fixture.inspect, fixture.ingressConfig.IngressID),
			readSplitRelayLeaseResult(fixture.inspect, fixture.relayA.config.RelayID),
			readSplitRelayLeaseResult(fixture.inspect, fixture.relayB.config.RelayID),
		}
		for index, after := range afterLeases {
			before := beforeLeases[index]
			if after.err != nil {
				return false, after.err
			}
			if after.runID != before.runID || after.revision != before.revision {
				return false, fmt.Errorf("process identity changed during certificate issuance restart")
			}
			if !after.expiresAt.After(before.expiresAt) {
				return false, nil
			}
		}
		return true, nil
	})
	var installed bool
	if err := fixture.inspect.QueryRowContext(t.Context(), `
		SELECT orders.order_url = $2 AND orders.route_session_id = $3
			AND orders.state = 'installed' AND orders.certificate_pem IS NOT NULL
			AND orders.not_before IS NOT NULL AND orders.not_after IS NOT NULL
			AND sessions.certificate_issuance_id = orders.id AND sessions.certificate_installed_at IS NOT NULL
			AND sessions.closed_at IS NULL AND accounts.account_url = $4
			AND (SELECT count(*) FROM control.acme_authorizations
				WHERE order_id = orders.id AND challenge_type = 'tls-alpn-01' AND state = 'complete'
				AND presented_at IS NOT NULL AND validated_at IS NOT NULL AND cleanup_completed_at IS NOT NULL) = 1
		FROM control.acme_orders AS orders
		JOIN control.route_sessions AS sessions ON sessions.id = orders.route_session_id
		JOIN control.acme_accounts AS accounts ON accounts.id = orders.account_id
		WHERE orders.id = $1
	`, orderID, orderURL, routeSessionID, accountURL).Scan(&installed); err != nil {
		t.Fatal(err)
	}
	if !installed || integrationRouteOrderCount(t, fixture.inspect, routeID) != 1 || newOrders.Load() != 1 {
		t.Fatalf("original certificate order was not installed and acknowledged without duplication: installed %v, new orders %d",
			installed, newOrders.Load())
	}
	response, body, err := fixture.visitor.requestURL(http.MethodGet, ready.PublicURL+"/after-issuance-restart", nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "resumed certificate order" {
		t.Fatalf("visitor after issuance restart = %s, %q", response.Status, body)
	}
	assertIntegrationRouteCertificate(t, response, fixture.identity.hostname)
	if len(response.TLS.VerifiedChains) == 0 || len(response.TLS.PeerCertificates) < 2 {
		t.Fatal("resumed certificate has no verified visitor TLS chain")
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

type splitACMERoundTripFunc func(*http.Request) (*http.Response, error)

func (f splitACMERoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type splitRelayFixture struct {
	config  tnldconfig.Config
	process *integrationProcess
}

type splitPublishFixture struct {
	databaseURL string
	inspect     *sql.DB
	pebble      integrationPebble
	roots       *tls.Config

	controlConfig  tnldconfig.Config
	controlOptions integrationProcessOptions
	ingressConfig  tnldconfig.Config
	control        *integrationProcess
	ingress        *integrationProcess
	relayA         splitRelayFixture
	relayB         splitRelayFixture

	serviceHTTP *http.Client
	controlHTTP *http.Client
	identity    *integrationPublishingIdentity
	visitor     *integrationVisitor
}

type splitPublishOptions struct {
	dns *integrationRoute53
}

func newSplitPublishFixture(t *testing.T, hostnameLabel string) *splitPublishFixture {
	t.Helper()
	return newSplitPublishFixtureWithOptions(t, hostnameLabel, splitPublishOptions{})
}

func newSplitPublishFixtureWithOptions(
	t *testing.T,
	hostnameLabel string,
	options splitPublishOptions,
	configureACME ...func(*http.Client),
) *splitPublishFixture {
	t.Helper()
	databaseURL, inspect := standaloneTestDatabase(t)
	const serverDomain = "split.integration.test"
	controlHostname := "control." + serverDomain
	certificateAuthority := newIntegrationTestCA(t)
	controlCertificate := certificateAuthority.issueServer(t, controlHostname)
	var relayACertificate, relayBCertificate integrationCertificate
	if options.dns == nil {
		relayACertificate = certificateAuthority.issueServer(t, "relay-a."+serverDomain)
		relayBCertificate = certificateAuthority.issueServer(t, "relay-b."+serverDomain)
	}
	controlAddress := unusedTCPAddress(t)
	privateControlAddress := unusedTCPAddress(t)
	ingressAddress := unusedTCPAddress(t)
	var dnsAddress string
	if options.dns != nil {
		dnsAddress = options.dns.address
	} else {
		dnsAddress = startIntegrationDNS(t)
	}
	pebble := startIntegrationPebble(t, integrationPort(t, ingressAddress), dnsAddress)
	for _, configure := range configureACME {
		configure(pebble.httpClient)
	}
	serviceHTTP := splitTestServiceHTTPClient(t, certificateAuthority.roots, privateControlAddress)

	controlConfig := splitPublishConfig(t, tnldconfig.RoleControl)
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
	if options.dns != nil {
		controlConfig.ManagedDeploymentDomain = serverDomain
		controlConfig.DNSServer = options.dns.address
		controlConfig.Route53Region = "us-east-1"
		controlConfig.Route53ManagedZoneID = options.dns.zoneID
		controlConfig.Route53ServerZoneID = options.dns.zoneID
		controlConfig.IngressIPv4Addresses = []string{"127.0.0.1"}
	}
	if err := controlConfig.Validate(); err != nil {
		t.Fatal(err)
	}
	controlOptions := integrationProcessOptions{acmeHTTPClient: pebble.httpClient, serviceHTTPClient: serviceHTTP}
	control := startIntegrationProcessWithOptions(t, controlConfig, controlOptions)
	waitForProcessReady(t, control)

	ingressConfig := splitPublishConfig(t, tnldconfig.RoleIngress)
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
	if options.dns != nil {
		relayAConfig.ControlRetryInterval = 100 * time.Millisecond
		relayBConfig.ControlRetryInterval = 100 * time.Millisecond
	}
	for _, cfg := range []tnldconfig.Config{ingressConfig, relayAConfig, relayBConfig} {
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	relayRoots := certificateAuthority.roots
	if options.dns != nil {
		relayRoots = pebble.roots
	}
	fixture := &splitPublishFixture{
		databaseURL: databaseURL, inspect: inspect, pebble: pebble,
		roots:         &tls.Config{RootCAs: relayRoots, MinVersion: tls.VersionTLS13},
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

func splitPublishConfig(t *testing.T, role tnldconfig.Role) tnldconfig.Config {
	t.Helper()
	cfg := splitTestConfig(role, "")
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
) tnldconfig.Config {
	t.Helper()
	cfg := splitPublishConfig(t, tnldconfig.RoleRelay)
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

func (f *splitPublishFixture) startRelay(t *testing.T, cfg tnldconfig.Config) *integrationProcess {
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
