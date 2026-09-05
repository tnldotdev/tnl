package tnldruntime

import (
	"context"
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
)

func TestIntegrationSplitPublishAndVisit(t *testing.T) {
	fixture := newSplitPublishFixture(t, "split")
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("X-Tnl-Integration", "split")
		_, _ = io.WriteString(response, request.URL.RequestURI())
	}))
	cleanupIntegrationHTTPServer(t, target, fixture.owner)
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
	assertRuntimeOperations(t, []*integrationProcess{fixture.relayA.process, fixture.relayB.process}, map[string]uint64{
		"RelayRegister": 2, "RelayRenewLease": 1, "RelayAdmitPublisherConnection": 2, "RelayOpenVisitorStream": 1,
	})
}

func TestIntegrationSplitRelayLossAndReplenishment(t *testing.T) {
	fixture := newSplitPublishFixture(t, "relay-loss")
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, "relay recovery")
	}))
	cleanupIntegrationHTTPServer(t, target, fixture.owner)
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
	cleanupIntegrationHTTPServer(t, target, fixture.owner)
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
	if err := fixture.inspect.QueryRowContext(integrationOperationContext(t), `
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
	result, err := fixture.inspect.ExecContext(integrationOperationContext(t), `
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
	waitForProcessReady(t, fixture.control)
	release()
	ready := fixture.waitReady(t, handle)
	if ready.RouteID != routeID || ready.RouteVersion != routeVersion {
		t.Fatalf("publisher changed route across issuance restart: %s version %d, want %s version %d",
			ready.RouteID, ready.RouteVersion, routeID, routeVersion)
	}
	waitForIntegrationCondition(t, 10*time.Second, func(ctx context.Context) (bool, error) {
		afterLeases := []splitProcessLease{
			readSplitIngressLeaseResult(ctx, fixture.inspect, fixture.ingressConfig.IngressID),
			readSplitRelayLeaseResult(ctx, fixture.inspect, fixture.relayA.config.RelayID),
			readSplitRelayLeaseResult(ctx, fixture.inspect, fixture.relayB.config.RelayID),
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
	if err := fixture.inspect.QueryRowContext(integrationOperationContext(t), `
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
	cleanupIntegrationHTTPServer(t, target, fixture.owner)
	quicConnector, tcpConnector := fixture.connectors()
	handle := fixture.startPublisher(t, target.URL, quicConnector, tcpConnector)
	ready := fixture.waitReady(t, handle)
	beforeIngress := readSplitIngressLease(t, fixture.inspect, fixture.ingressConfig.IngressID)
	beforeRelayA := readSplitRelayLease(t, fixture.inspect, fixture.relayA.config.RelayID)
	beforeRelayB := readSplitRelayLease(t, fixture.inspect, fixture.relayB.config.RelayID)
	earliestExpiry, latestExpiry := beforeIngress.expiresAt, beforeIngress.expiresAt
	for _, expiresAt := range []time.Time{beforeRelayA.expiresAt, beforeRelayB.expiresAt} {
		if expiresAt.Before(earliestExpiry) {
			earliestExpiry = expiresAt
		}
		if expiresAt.After(latestExpiry) {
			latestExpiry = expiresAt
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
	if !time.Now().Before(earliestExpiry) {
		t.Fatal("control restart did not begin before the earliest existing process lease expired")
	}
	fixture.control = startIntegrationProcessWithOptions(t, fixture.controlConfig, fixture.controlOptions)
	waitForProcessReady(t, fixture.control)
	if !time.Now().Before(earliestExpiry) {
		t.Fatal("control did not become ready before the earliest existing process lease expired")
	}

	waitForIntegrationCondition(t, 10*time.Second, func(ctx context.Context) (bool, error) {
		ingress := readSplitIngressLeaseResult(ctx, fixture.inspect, fixture.ingressConfig.IngressID)
		relayA := readSplitRelayLeaseResult(ctx, fixture.inspect, fixture.relayA.config.RelayID)
		relayB := readSplitRelayLeaseResult(ctx, fixture.inspect, fixture.relayB.config.RelayID)
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
		return ingress.expiresAt.After(latestExpiry) && relayA.expiresAt.After(latestExpiry) &&
			relayB.expiresAt.After(latestExpiry), nil
	})
	waitUntilIntegrationTime(t, latestExpiry.Add(25*time.Millisecond))
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
