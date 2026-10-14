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
	assertSplitRoutePlacement(t, fixture.inspect, ready.PublicURLID, ready.PublishRunNumber)

	response, body, err := fixture.visitor.requestURL(http.MethodGet, ready.PublicURL+"/through-split?source=integration", nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "/through-split?source=integration" ||
		response.Header.Get("X-Tnl-Integration") != "split" {
		t.Fatalf("split visitor response = %s, headers %#v, body %q", response.Status, response.Header, body)
	}
	assertIntegrationPublicURLCertificate(t, response, fixture.identity.hostname)
	assertRuntimeOperations(t, []*integrationProcess{fixture.relayA.process, fixture.relayB.process}, map[string]uint64{
		"RelayRegister": 2, "RelayRenewLease": 1, "RelayAdmitPublisherConnection": 2, "RelayOpenVisitorStream": 1,
	})
}

func TestIntegrationAuthorizedBrowserConnectionsLeavePendingIngressCapacity(t *testing.T) {
	fixture := newSplitPublishFixture(t, "browser-admission")
	entered := make(chan struct{}, 12)
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/hold" {
			response.WriteHeader(http.StatusNoContent)
			return
		}
		entered <- struct{}{}
		select {
		case <-release:
		case <-request.Context().Done():
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	cleanupIntegrationHTTPServer(t, target, fixture.owner)
	quic, tcp := fixture.connectors()
	config := fixture.identity.publisherConfig(target.URL, quic, tcp)
	config.AllowedIPPrefixes = []string{"192.0.2.10/32"} // the visitor comes from 127.0.0.1.
	config.ControlURL = fixture.identity.controlOrigin
	config.BuiltinBrowserHandoffAvailable = true
	handle := startOwnedIntegrationPublisher(t, fixture.owner, config, func() string {
		return integrationPublisherDiagnostics(fixture.inspect, fixture.pebble.logPath)
	})
	ready := fixture.waitReady(t, handle)
	visitor := &http.Client{Transport: fixture.visitor.transport, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	unauthorized, err := visitor.Get(ready.PublicURL + "/hold")
	if err != nil {
		t.Fatal(err)
	}
	unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusForbidden {
		t.Fatalf("unsigned browser reached target: %d", unauthorized.StatusCode)
	}
	admin, found, err := fixture.identity.state.ControlSession(t.Context())
	if err != nil || !found {
		t.Fatalf("saved administrator session = %t, %v", found, err)
	}
	handoff, err := fixture.identity.routes.CreateAdminBrowserHandoff(t.Context(), ready.PublicURLID, admin.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := visitor.Get(handoff.EntryUrl)
	if err != nil {
		t.Fatal(err)
	}
	installed.Body.Close()
	var cookie *http.Cookie
	for _, candidate := range installed.Cookies() {
		if candidate.Name == "__Host-tnl-browser" {
			cookie = candidate
		}
	}
	if installed.StatusCode != http.StatusSeeOther || cookie == nil {
		t.Fatalf("admin handoff did not install a host-bound visitor cookie: %d", installed.StatusCode)
	}
	probe, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ready.PublicURL+"/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	probe.AddCookie(cookie)
	admitted, err := visitor.Do(probe)
	if err != nil {
		t.Fatal(err)
	}
	admissionBody, _ := io.ReadAll(admitted.Body)
	admitted.Body.Close()
	if admitted.StatusCode != http.StatusNoContent {
		t.Fatalf("authorized visitor admission = %d %s", admitted.StatusCode, admissionBody)
	}
	const visitors = 10 // more than the former eight denied slots per public URL.
	results := make(chan error, visitors)
	deadline := time.After(7 * time.Second)
	for index := range visitors {
		go func() {
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ready.PublicURL+"/hold", nil)
			if err != nil {
				results <- err
				return
			}
			request.AddCookie(cookie)
			response, err := visitor.Do(request)
			if err == nil {
				response.Body.Close()
				if response.StatusCode != http.StatusNoContent {
					err = fmt.Errorf("visitor response = %d", response.StatusCode)
				}
			}
			results <- err
		}()
		select {
		case <-entered:
		case err := <-results:
			t.Fatalf("authorized visitor rejected after %d/%d reached target: %v", index, visitors, err)
		case <-deadline:
			t.Fatalf("authorized visitors remained in pending ingress capacity after %d/%d reached target", index, visitors)
		}
	}
	unblock()
	for range visitors {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
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
	beforeConnection := readSplitConnectionState(t, fixture.inspect, ready.PublicURLID, ready.PublishRunNumber, "relay-a")
	beforeLease := readSplitRelayLease(t, fixture.inspect, fixture.relayA.config.RelayID)

	stopIntegrationProcess(t, fixture.relayA.process)
	stoppedLease := readSplitRelayLease(t, fixture.inspect, fixture.relayA.config.RelayID)
	waitForReadyPublisherConnections(t, fixture.inspect, ready.PublicURLID, ready.PublishRunNumber, 1)
	waitForIngressRoutingCurrent(t, fixture.inspect, 1)
	response, body, err := fixture.visitor.requestURL(http.MethodGet, ready.PublicURL+"/during-relay-loss", nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "relay recovery" {
		t.Fatalf("visitor during relay loss = %s, %q", response.Status, body)
	}
	assertPublishRunNumber(t, fixture.inspect, ready.PublicURLID, ready.PublishRunNumber)

	waitUntilIntegrationTime(t, stoppedLease.expiresAt.Add(25*time.Millisecond))
	fixture.relayA.process = fixture.startRelay(t, fixture.relayA.config)
	waitForProcessReady(t, fixture.relayA.process)
	waitForReadyPublisherConnections(t, fixture.inspect, ready.PublicURLID, ready.PublishRunNumber, 2)
	waitForIngressRoutingCurrent(t, fixture.inspect, 1)
	afterConnection := readSplitConnectionState(t, fixture.inspect, ready.PublicURLID, ready.PublishRunNumber, "relay-a")
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
	assertPublishRunNumber(t, fixture.inspect, ready.PublicURLID, ready.PublishRunNumber)
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

	var orderID, orderURL, publishRunID, publicURLID, accountURL, workerID string
	var publishRunNumber uint64
	var pending bool
	if err := fixture.inspect.QueryRowContext(integrationOperationContext(t), `
		SELECT orders.id, orders.order_url, orders.publish_run_id, orders.public_url_id,
			orders.publish_run_number, accounts.account_url, orders.work_owner,
			orders.state = 'authorizing' AND orders.challenge_method = 'tls-alpn-01'
			AND orders.certificate_pem IS NULL AND orders.installed_at IS NULL
			AND sessions.certificate_installed_at IS NULL AND sessions.ready_at IS NULL
		FROM control.acme_orders AS orders
		JOIN control.publish_runs AS sessions ON sessions.id = orders.publish_run_id
		JOIN control.acme_accounts AS accounts ON accounts.id = orders.account_id
		WHERE orders.certificate_identifiers = ARRAY[$1]::text[]
	`, fixture.identity.hostname).Scan(
		&orderID, &orderURL, &publishRunID, &publicURLID, &publishRunNumber, &accountURL, &workerID, &pending,
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
	// the canceled operation retains its work lease. expire only that stopped
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
	if ready.PublicURLID != publicURLID || ready.PublishRunNumber != publishRunNumber {
		t.Fatalf("publisher changed route across issuance restart: %s version %d, want %s version %d",
			ready.PublicURLID, ready.PublishRunNumber, publicURLID, publishRunNumber)
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
		SELECT orders.order_url = $2 AND orders.publish_run_id = $3
			AND orders.state = 'installed' AND orders.certificate_pem IS NOT NULL
			AND orders.not_before IS NOT NULL AND orders.not_after IS NOT NULL
			AND sessions.certificate_issuance_id = orders.id AND sessions.certificate_installed_at IS NOT NULL
			AND sessions.closed_at IS NULL AND accounts.account_url = $4
			AND (SELECT count(*) FROM control.acme_authorizations
				WHERE order_id = orders.id AND challenge_type = 'tls-alpn-01' AND state = 'complete'
				AND presented_at IS NOT NULL AND validated_at IS NOT NULL AND cleanup_completed_at IS NOT NULL) = 1
		FROM control.acme_orders AS orders
		JOIN control.publish_runs AS sessions ON sessions.id = orders.publish_run_id
		JOIN control.acme_accounts AS accounts ON accounts.id = orders.account_id
		WHERE orders.id = $1
	`, orderID, orderURL, publishRunID, accountURL).Scan(&installed); err != nil {
		t.Fatal(err)
	}
	if !installed || integrationRouteOrderCount(t, fixture.inspect, publicURLID) != 1 || newOrders.Load() != 1 {
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
	assertIntegrationPublicURLCertificate(t, response, fixture.identity.hostname)
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
	waitForReadyPublisherConnections(t, fixture.inspect, ready.PublicURLID, ready.PublishRunNumber, 2)
	assertPublishRunNumber(t, fixture.inspect, ready.PublicURLID, ready.PublishRunNumber)
	response, body, err = fixture.visitor.requestURL(http.MethodGet, ready.PublicURL+"/after-control-restart", nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "control restart" {
		t.Fatalf("visitor after control restart = %s, %q", response.Status, body)
	}
}
