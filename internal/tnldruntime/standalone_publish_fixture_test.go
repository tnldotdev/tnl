package tnldruntime

import (
	"bufio"
	"context"
	"crypto/tls"
	"database/sql"
	"net/http"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
	"golang.org/x/net/websocket"
)

type standalonePublishFixture struct {
	owner                          *runtimeTopology
	databaseURL                    string
	inspect                        *sql.DB
	publicAddress, relayUDPAddress string
	pebble                         integrationPebble
	process                        *integrationProcess
	identity                       *integrationPublishingIdentity
	visitor                        *integrationVisitor
}

func newStandalonePublishFixture(t *testing.T, hostnameLabel string) *standalonePublishFixture {
	t.Helper()
	databaseURL, inspect := standaloneTestDatabase(t)
	publicAddress, relayUDPAddress := unusedTCPAddress(t), unusedUDPAddress(t)
	pebble := startIntegrationPebble(t, integrationPort(t, publicAddress), startIntegrationDNS(t))
	cfg := standalonePublishConfig(t, databaseURL, publicAddress, relayUDPAddress, pebble.directoryURL)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	owner := newRuntimeTopology(t)
	process := startIntegrationProcessWithOptions(t, cfg, integrationProcessOptions{
		acmeHTTPClient: pebble.httpClient, serviceHTTPClient: &http.Client{Timeout: 10 * time.Second},
		relayClientTLS: &tls.Config{RootCAs: pebble.roots, MinVersion: tls.VersionTLS13}, owner: owner,
	})
	waitForProcessReady(t, process)
	controlHTTP, _ := newIntegrationHTTPSClient(t, pebble.roots, publicAddress, false, owner)
	identity := newIntegrationPublishingIdentity(t, "https://"+cfg.ServerHostname(), controlHTTP, hostnameLabel, owner)
	return &standalonePublishFixture{owner: owner, databaseURL: databaseURL, inspect: inspect, publicAddress: publicAddress,
		relayUDPAddress: relayUDPAddress, pebble: pebble, process: process, identity: identity,
		visitor: newIntegrationVisitor(t, pebble.roots, publicAddress, owner)}
}

func standalonePublishConfig(t *testing.T, databaseURL, publicAddress, relayUDPAddress, directoryURL string) tnldconfig.Config {
	t.Helper()
	const serverDomain = "integration.test"
	// Standalone uses one public listener and creates its internal listeners on
	// :0 itself. These required but unused split-role addresses need no probes.
	return tnldconfig.Config{
		Role: tnldconfig.RoleStandalone, DatabaseURL: databaseURL, MetricsListen: unusedTCPAddress(t),
		ControlListen: "127.0.0.1:1", PrivateControlListen: "127.0.0.1:1", IngressListen: publicAddress,
		RelayTCPListen: "127.0.0.1:1", RelayUDPListen: relayUDPAddress, InternalRelayListen: "127.0.0.1:1",
		ServerDomain: serverDomain, ManagedDeploymentDomain: "routes." + serverDomain,
		ACMEDirectoryURL: directoryURL, ACMEEmail: "integration@example.test", ACMEAcceptTerms: true, ACMEProfile: "tlsserver",
		LoginToken: testLoginToken, StorageKey: testStorageKey, AccessTokenLifetime: 5 * time.Minute, RefreshTokenLifetime: time.Hour,
		VisitorConnectionLimit: 100, RouteConnectionLimit: 100, PublisherConnectionLimit: 10,
		SourceConnectionRate: 50, SourceConnectionBurst: 200,
		RelayStreamCapacity: 100, QUICMaxIncomingStreams: 100, QUICIdleTimeout: time.Minute,
		IngressLeaseDuration: 5 * time.Second,
		RelayLeaseDuration:   5 * time.Second, LeaseRenewalInterval: time.Second,
		ControlRetryInterval: 10 * time.Millisecond, RoutingTableWait: time.Second, DrainTimeout: 3 * time.Second,
	}
}

func (f *standalonePublishFixture) connectors() (muxsession.Connector, muxsession.Connector) {
	relayTLS := &tls.Config{RootCAs: f.pebble.roots, MinVersion: tls.VersionTLS13}
	return redirectIntegrationConnector(f.relayUDPAddress, muxsession.QUICConnector{TLSConfig: relayTLS}),
		redirectIntegrationConnector(f.publicAddress, muxsession.TLSYamuxConnector{TLSConfig: relayTLS})
}

func (f *standalonePublishFixture) startPublisher(t *testing.T, target string, quicConnector, tcpConnector muxsession.Connector) *integrationPublisher {
	t.Helper()
	return startOwnedIntegrationPublisher(t, f.owner, f.identity.publisherConfig(target, quicConnector, tcpConnector), f.diagnostics)
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

func assertIntegrationStreamingResponse(
	t *testing.T,
	fixture *standalonePublishFixture,
	publicURL string,
	release func(),
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, publicURL+"/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := fixture.visitor.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/plain" {
		t.Fatalf("streaming response = %s, headers %#v", response.Status, response.Header)
	}
	reader := bufio.NewReader(response.Body)
	if chunk, readErr := reader.ReadString('\n'); readErr != nil || chunk != "first\n" {
		t.Fatalf("first streaming chunk = %q, %v", chunk, readErr)
	}
	waitUntilIntegrationTime(t, time.Now().Add(250*time.Millisecond))
	release()
	if chunk, readErr := reader.ReadString('\n'); readErr != nil || chunk != "second\n" {
		t.Fatalf("second streaming chunk = %q, %v", chunk, readErr)
	}
}

func assertIntegrationWebSocketPushes(
	t *testing.T,
	fixture *standalonePublishFixture,
	release func(),
) {
	t.Helper()
	config, err := websocket.NewConfig("wss://"+fixture.identity.hostname+"/websocket", "https://"+fixture.identity.hostname)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	dialer := &tls.Dialer{Config: &tls.Config{
		RootCAs: fixture.pebble.roots, ServerName: fixture.identity.hostname, MinVersion: tls.VersionTLS13,
	}}
	secured, err := dialer.DialContext(ctx, "tcp", fixture.publicAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer secured.Close()
	// Bound the WebSocket upgrade as well as subsequent messages.
	deadline, _ := ctx.Deadline()
	if err := secured.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	connection, err := websocket.NewClient(config, secured)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	var message string
	if err := websocket.Message.Receive(connection, &message); err != nil || message != "connected" {
		t.Fatalf("first WebSocket message = %q, %v", message, err)
	}
	waitUntilIntegrationTime(t, time.Now().Add(250*time.Millisecond))
	release()
	if err := websocket.Message.Receive(connection, &message); err != nil || message != "update" {
		t.Fatalf("second WebSocket message = %q, %v", message, err)
	}
}

func assertIntegrationSSEPushes(
	t *testing.T,
	fixture *standalonePublishFixture,
	publicURL string,
	release func(),
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, publicURL+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := fixture.visitor.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("SSE response = %s, headers %#v", response.Status, response.Header)
	}
	reader := bufio.NewReader(response.Body)
	readEvent := func() string {
		data, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatal(readErr)
		}
		if separator, readErr := reader.ReadString('\n'); readErr != nil || separator != "\n" {
			t.Fatalf("SSE separator = %q, %v", separator, readErr)
		}
		return data
	}
	if event := readEvent(); event != "data: connected\n" {
		t.Fatalf("first SSE event = %q", event)
	}
	waitUntilIntegrationTime(t, time.Now().Add(250*time.Millisecond))
	release()
	if event := readEvent(); event != "data: update\n" {
		t.Fatalf("second SSE event = %q", event)
	}
}
