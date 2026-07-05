package tnldruntime

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
)

func TestIntegrationStandalonePublishAndVisit(t *testing.T) {
	fixture := newStandalonePublishFixture(t, "visit")
	type targetRequest struct {
		host    string
		path    string
		headers http.Header
	}
	targetRequests := make(chan targetRequest, 1)
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		select {
		case targetRequests <- targetRequest{
			host: request.Host, path: request.URL.RequestURI(), headers: request.Header.Clone(),
		}:
		default:
		}
		response.Header().Set("X-Tnl-Integration", "publisher")
		_, _ = io.WriteString(response, "visitor reached local service")
	}))
	t.Cleanup(target.Close)

	quicConnector, tcpConnector := fixture.connectors()
	handle := fixture.startPublisher(t, target.URL, quicConnector, tcpConnector)
	ready := fixture.waitReady(t, handle)
	request, err := http.NewRequest(http.MethodGet, ready.PublicURL+"/through-tnl?source=integration", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Forwarded", "for=198.51.100.1")
	request.Header.Set("X-Forwarded-For", "198.51.100.1")
	request.Header.Set("X-Forwarded-Host", "spoofed.example")
	request.Header.Set("X-Forwarded-Proto", "http")
	request.Header.Set("X-Real-IP", "198.51.100.1")
	response, body, err := fixture.visitor.request(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "visitor reached local service" ||
		response.Header.Get("X-Tnl-Integration") != "publisher" {
		t.Fatalf("visitor response = %s, headers %#v, body %q", response.Status, response.Header, body)
	}
	assertIntegrationRouteCertificate(t, response, fixture.identity.hostname)

	select {
	case observed := <-targetRequests:
		if observed.host != fixture.identity.hostname || observed.path != "/through-tnl?source=integration" {
			t.Fatalf("local service request = %#v", observed)
		}
		if observed.headers.Get("X-Forwarded-For") != "127.0.0.1" ||
			observed.headers.Get("X-Forwarded-Host") != fixture.identity.hostname ||
			observed.headers.Get("X-Forwarded-Proto") != "https" ||
			observed.headers.Get("Forwarded") != "" || observed.headers.Get("X-Real-IP") != "" {
			t.Fatalf("local service forwarding headers = %#v", observed.headers)
		}
	case <-time.After(time.Second):
		t.Fatal("local service did not observe the visitor request")
	}

	fixture.visitor.transport.CloseIdleConnections()
	stopIntegrationPublisher(t, handle)
	stopIntegrationProcess(t, fixture.process)
	assertStandaloneUsage(t, fixture.databaseURL, fixture.inspect, ready.RouteID, ready.RouteVersion)
}

func TestIntegrationPublisherTransportMatrix(t *testing.T) {
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) {
			fixture := newStandalonePublishFixture(t, "transport-"+transport)
			var (
				mu       sync.Mutex
				requests = make(map[string]int)
			)
			target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				body, err := io.ReadAll(io.LimitReader(request.Body, 2<<20))
				if err != nil {
					http.Error(response, err.Error(), http.StatusBadRequest)
					return
				}
				mu.Lock()
				requests[request.URL.Path]++
				mu.Unlock()
				if request.Method == http.MethodPost {
					_, _ = response.Write(body)
					return
				}
				_, _ = io.WriteString(response, request.URL.Path)
			}))
			t.Cleanup(target.Close)

			quicBase, tcpBase := fixture.connectors()
			var quicStats, tcpStats *integrationConnectorStats
			var quicConnector, tcpConnector muxsession.Connector
			if transport == "quic" {
				quicConnector, quicStats = observeIntegrationConnector(quicBase)
				tcpConnector, tcpStats = disabledIntegrationConnector("TLS/TCP disabled by integration test")
			} else {
				quicConnector, quicStats = disabledIntegrationConnector("QUIC disabled by integration test")
				tcpConnector, tcpStats = observeIntegrationConnector(tcpBase)
			}
			handle := fixture.startPublisher(t, target.URL, quicConnector, tcpConnector)
			ready := fixture.waitReady(t, handle)

			const concurrentRequests = 16
			results := make(chan error, concurrentRequests)
			for index := range concurrentRequests {
				go func() {
					path := fmt.Sprintf("/parallel/%d", index)
					request, err := http.NewRequest(http.MethodGet, ready.PublicURL+path, nil)
					if err != nil {
						results <- err
						return
					}
					response, body, err := fixture.visitor.request(request)
					if err != nil {
						results <- err
						return
					}
					if response.StatusCode != http.StatusOK || string(body) != path {
						results <- fmt.Errorf("%s response = %s, %q", path, response.Status, body)
						return
					}
					results <- nil
				}()
			}
			for range concurrentRequests {
				if err := <-results; err != nil {
					t.Error(err)
				}
			}
			if t.Failed() {
				t.FailNow()
			}

			largeBody := bytes.Repeat([]byte("tnl-transport-payload-"), (1<<20)/len("tnl-transport-payload-")+1)
			largeBody = largeBody[:1<<20]
			request, err := http.NewRequest(http.MethodPost, ready.PublicURL+"/large-post", bytes.NewReader(largeBody))
			if err != nil {
				t.Fatal(err)
			}
			response, body, err := fixture.visitor.request(request)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusOK || !bytes.Equal(body, largeBody) {
				t.Fatalf("large POST response = %s, %d bytes", response.Status, len(body))
			}

			mu.Lock()
			defer mu.Unlock()
			if len(requests) != concurrentRequests+1 {
				t.Fatalf("local service observed %d distinct requests, want %d", len(requests), concurrentRequests+1)
			}
			for path, count := range requests {
				if count != 1 {
					t.Fatalf("local service observed %s %d times", path, count)
				}
			}
			if transport == "quic" {
				if quicStats.successful.Load() != 2 || tcpStats.successful.Load() != 0 {
					t.Fatalf("transport sessions = QUIC %d, TLS/TCP %d", quicStats.successful.Load(), tcpStats.successful.Load())
				}
			} else if tcpStats.successful.Load() != 2 || quicStats.successful.Load() != 0 || quicStats.attempts.Load() < 2 {
				t.Fatalf(
					"transport sessions = QUIC %d/%d attempts, TLS/TCP %d",
					quicStats.successful.Load(), quicStats.attempts.Load(), tcpStats.successful.Load(),
				)
			}
		})
	}
}

func TestIntegrationPublisherRestartReusesCertificate(t *testing.T) {
	fixture := newStandalonePublishFixture(t, "restart")
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, "publisher restart")
	}))
	t.Cleanup(target.Close)
	quicConnector, tcpConnector := fixture.connectors()

	first := fixture.startPublisher(t, target.URL, quicConnector, tcpConnector)
	firstReady := fixture.waitReady(t, first)
	firstResponse, body, err := fixture.visitor.requestURL(http.MethodGet, firstReady.PublicURL+"/before", nil)
	if err != nil {
		t.Fatal(err)
	}
	if firstResponse.StatusCode != http.StatusOK || string(body) != "publisher restart" {
		t.Fatalf("first visitor response = %s, %q", firstResponse.Status, body)
	}
	assertIntegrationRouteCertificate(t, firstResponse, fixture.identity.hostname)
	firstSerial := firstResponse.TLS.PeerCertificates[0].SerialNumber.String()
	firstOrderCount := integrationRouteOrderCount(t, fixture.inspect, firstReady.RouteID)

	stopIntegrationPublisher(t, first)
	waitForIntegrationCondition(t, 10*time.Second, func() (bool, error) {
		var closed bool
		err := fixture.inspect.QueryRowContext(t.Context(), `
			SELECT closed_at IS NOT NULL
			FROM control.route_sessions
			WHERE route_id = $1 AND route_version = $2
		`, firstReady.RouteID, firstReady.RouteVersion).Scan(&closed)
		return err == nil && closed, err
	})
	waitForIngressRoutingCurrent(t, fixture.inspect, 1)
	response, _, unavailableErr := fixture.visitor.requestURL(http.MethodGet, firstReady.PublicURL+"/unavailable", nil)
	if unavailableErr == nil && response.StatusCode == http.StatusOK {
		t.Fatal("route remained available after the publisher stopped")
	}

	second := fixture.startPublisher(t, target.URL, quicConnector, tcpConnector)
	secondReady := fixture.waitReady(t, second)
	if secondReady.RouteID != firstReady.RouteID || secondReady.RouteVersion != firstReady.RouteVersion+1 {
		t.Fatalf("restarted route = %q version %d, want %q version %d", secondReady.RouteID, secondReady.RouteVersion, firstReady.RouteID, firstReady.RouteVersion+1)
	}
	secondResponse, body, err := fixture.visitor.requestURL(http.MethodGet, secondReady.PublicURL+"/after", nil)
	if err != nil {
		t.Fatal(err)
	}
	if secondResponse.StatusCode != http.StatusOK || string(body) != "publisher restart" {
		t.Fatalf("second visitor response = %s, %q", secondResponse.Status, body)
	}
	assertIntegrationRouteCertificate(t, secondResponse, fixture.identity.hostname)
	secondSerial := secondResponse.TLS.PeerCertificates[0].SerialNumber.String()
	if secondSerial != firstSerial {
		t.Fatalf("restarted certificate serial = %s, want %s", secondSerial, firstSerial)
	}
	if orderCount := integrationRouteOrderCount(t, fixture.inspect, secondReady.RouteID); orderCount != firstOrderCount {
		t.Fatalf("route ACME order count = %d, want %d", orderCount, firstOrderCount)
	}
}

type standalonePublishFixture struct {
	databaseURL     string
	inspect         *sql.DB
	publicAddress   string
	relayUDPAddress string
	pebble          integrationPebble
	process         *integrationProcess
	identity        *integrationPublishingIdentity
	visitor         *integrationVisitor
}

func newStandalonePublishFixture(t *testing.T, hostnameLabel string) *standalonePublishFixture {
	t.Helper()
	databaseURL, inspect := standaloneTestDatabase(t)
	publicAddress := unusedTCPAddress(t)
	relayUDPAddress := unusedUDPAddress(t)
	dnsAddress := startIntegrationDNS(t)
	pebble := startIntegrationPebble(t, integrationPort(t, publicAddress), dnsAddress)
	cfg := standalonePublishConfig(t, databaseURL, publicAddress, relayUDPAddress, pebble.directoryURL)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	process := startIntegrationProcessWithOptions(t, cfg, integrationProcessOptions{
		acmeHTTPClient: pebble.httpClient, serviceHTTPClient: &http.Client{Timeout: 10 * time.Second},
		relayClientTLS: &tls.Config{RootCAs: pebble.roots, MinVersion: tls.VersionTLS13},
	})
	waitForProcessReady(t, process)
	controlHTTP, _ := newIntegrationHTTPSClient(t, pebble.roots, publicAddress, false)
	controlOrigin := "https://" + cfg.ServerHostname()
	identity := newIntegrationPublishingIdentity(t, controlOrigin, controlHTTP, hostnameLabel)
	visitor := newIntegrationVisitor(t, pebble.roots, publicAddress)
	return &standalonePublishFixture{
		databaseURL: databaseURL, inspect: inspect, publicAddress: publicAddress,
		relayUDPAddress: relayUDPAddress, pebble: pebble, process: process,
		identity: identity, visitor: visitor,
	}
}

func standalonePublishConfig(
	t *testing.T,
	databaseURL, publicAddress, relayUDPAddress, directoryURL string,
) tnldconfig.Config {
	t.Helper()
	const serverDomain = "integration.test"
	return tnldconfig.Config{
		Mode: tnldconfig.RoleStandalone, DatabaseURL: databaseURL, MetricsListen: unusedTCPAddress(t),
		ControlListen: unusedTCPAddress(t), PrivateControlListen: unusedTCPAddress(t), IngressListen: publicAddress,
		RelayTCPListen: unusedTCPAddress(t), RelayUDPListen: relayUDPAddress, InternalRelayListen: unusedTCPAddress(t),
		ServerDomain: serverDomain, ManagedDeploymentDomain: "routes." + serverDomain,
		ACMEDirectoryURL: directoryURL, ACMEEmail: "integration@example.test",
		ACMEAcceptTerms: true, ACMEProfile: "tlsserver", LoginToken: testLoginToken,
		StorageKey:          testStorageKey,
		AccessTokenLifetime: 5 * time.Minute, RefreshTokenLifetime: time.Hour,
		PublicConnectionLimit: 100, RouteConnectionLimit: 100, PublisherConnectionLimit: 10,
		RelayStreamCapacity: 100, QUICMaxIncomingStreams: 100, QUICIdleTimeout: time.Minute,
		TunnelFallbackDelay: 10 * time.Millisecond, IngressLeaseDuration: 5 * time.Second,
		RelayLeaseDuration: 5 * time.Second, LeaseRenewalInterval: time.Second,
		ControlRetryInterval: 10 * time.Millisecond, RoutingTableWait: time.Second, DrainTimeout: 3 * time.Second,
	}
}

func (f *standalonePublishFixture) connectors() (muxsession.Connector, muxsession.Connector) {
	relayTLS := &tls.Config{RootCAs: f.pebble.roots, MinVersion: tls.VersionTLS13}
	return redirectIntegrationConnector(f.relayUDPAddress, muxsession.QUICConnector{TLSConfig: relayTLS}),
		redirectIntegrationConnector(f.publicAddress, muxsession.TLSYamuxConnector{TLSConfig: relayTLS})
}

func (f *standalonePublishFixture) startPublisher(
	t *testing.T,
	target string,
	quicConnector, tcpConnector muxsession.Connector,
) *integrationPublisher {
	t.Helper()
	return startIntegrationPublisher(t, f.identity.publisherConfig(target, quicConnector, tcpConnector), f.diagnostics)
}

func (f *standalonePublishFixture) waitReady(t *testing.T, handle *integrationPublisher) publisher.Event {
	t.Helper()
	ready := waitForPublisherReady(t, handle)
	if ready.Hostname != f.identity.hostname || ready.PublicURL != "https://"+f.identity.hostname {
		t.Fatalf("publisher ready event = %#v", ready)
	}
	waitForReadyPublisherConnections(t, f.inspect, ready.RouteID, ready.RouteVersion, 2)
	waitForIngressRoutingCurrent(t, f.inspect, 1)
	return ready
}

func (f *standalonePublishFixture) diagnostics() string {
	return integrationPublisherDiagnostics(f.inspect, f.pebble.logPath)
}

func integrationRouteOrderCount(t *testing.T, database *sql.DB, routeID string) int {
	t.Helper()
	var count int
	if err := database.QueryRowContext(t.Context(), `
		SELECT count(*) FROM control.acme_orders WHERE route_id = $1
	`, routeID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func assertStandaloneUsage(
	t *testing.T,
	databaseURL string,
	database *sql.DB,
	routeID string,
	routeVersion uint64,
) {
	t.Helper()
	var reportCount int
	var allFinal bool
	var attempts, policyDenials, capacityDenials, publisherFailures, successful, ingressBytes, egressBytes int64
	if err := database.QueryRowContext(t.Context(), `
		WITH latest AS (
			SELECT DISTINCT ON (bucket_start)
				final, connection_attempts, policy_denials, capacity_denials,
				publisher_open_failures, successful_streams, ingress_bytes, egress_bytes
			FROM control.ingress_usage_reports
			WHERE route_id = $1 AND route_version = $2
			ORDER BY bucket_start, report_revision DESC
		)
		SELECT count(*), coalesce(bool_and(final), false),
			coalesce(sum(connection_attempts), 0), coalesce(sum(policy_denials), 0),
			coalesce(sum(capacity_denials), 0), coalesce(sum(publisher_open_failures), 0),
			coalesce(sum(successful_streams), 0), coalesce(sum(ingress_bytes), 0), coalesce(sum(egress_bytes), 0)
		FROM latest
	`, routeID, routeVersion).Scan(
		&reportCount, &allFinal, &attempts, &policyDenials, &capacityDenials,
		&publisherFailures, &successful, &ingressBytes, &egressBytes,
	); err != nil {
		t.Fatal(err)
	}
	if reportCount == 0 || !allFinal || attempts < 1 || successful < 1 || ingressBytes == 0 || egressBytes == 0 ||
		policyDenials != 0 || capacityDenials != 0 || publisherFailures != 0 {
		t.Fatalf(
			"final usage reports = count %d, final %t, attempts/denials/failures/successes %d/%d/%d/%d/%d, bytes %d/%d",
			reportCount, allFinal, attempts, policyDenials, capacityDenials, publisherFailures, successful, ingressBytes, egressBytes,
		)
	}

	var bucketCount int
	var through time.Time
	if err := database.QueryRowContext(t.Context(), `
		SELECT count(*), max(bucket_end)
		FROM control.route_usage_buckets
		WHERE route_id = $1 AND route_version = $2
	`, routeID, routeVersion).Scan(&bucketCount, &through); err != nil {
		t.Fatal(err)
	}
	if bucketCount == 0 {
		t.Fatal("route usage bucket was not created")
	}
	state, err := controlstate.Open(t.Context(), databaseURL, testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	finalized, err := state.FinalizeRouteUsageBuckets(t.Context(), through, through)
	if err != nil || finalized != bucketCount {
		t.Fatalf("route usage finalization = %d, %v; want %d", finalized, err, bucketCount)
	}
	var allFinalized, allComplete bool
	if err := database.QueryRowContext(t.Context(), `
		SELECT coalesce(bool_and(finalized), false), coalesce(bool_and(complete), false)
		FROM control.route_usage_buckets
		WHERE route_id = $1 AND route_version = $2
	`, routeID, routeVersion).Scan(&allFinalized, &allComplete); err != nil {
		t.Fatal(err)
	}
	if !allFinalized || !allComplete {
		t.Fatalf("route usage buckets = finalized %t, complete %t", allFinalized, allComplete)
	}
}
