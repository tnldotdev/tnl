package daemon

import (
	"bufio"
	"context"
	"crypto/tls"
	"database/sql"
	"net"
	"net/http"
	"testing"
	"time"

	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"golang.org/x/net/websocket"
)

type standalonePublishFixture struct {
	relayTransport                 *muxsession.QUICTransport
	owner                          *runtimeTopology
	databaseURL                    string
	inspect                        *sql.DB
	publicAddress, relayUDPAddress string
	pebble                         integrationPebble
	relayTLS                       *tls.Config
	process                        *integrationProcess
	identity                       *integrationPublishingIdentity
	visitor                        *integrationVisitor
	controlHTTP                    *http.Client
}

func newStandalonePublishFixture(t *testing.T, hostnameLabel string, beforeStart ...func(daemonconfig.Config)) *standalonePublishFixture {
	t.Helper()
	return newStandalonePublishFixtureOptions(t, hostnameLabel, nil, nil, beforeStart...)
}

func newStandalonePublishFixtureOptions(t *testing.T, hostnameLabel string, configure func(*daemonconfig.Config), serviceClient *http.Client, beforeStart ...func(daemonconfig.Config)) *standalonePublishFixture {
	t.Helper()
	databaseURL, inspect := standaloneTestDatabase(t)
	owner := newRuntimeTopology(t)
	publicListener := serviceRuntimeListener(t, owner)
	relayUDP := integrationPacketListener(t, owner)
	publicAddress, relayUDPAddress := publicListener.Addr().String(), relayUDP.LocalAddr().String()
	dns := newPrivateFixtureDNS(t, owner)
	pebble := startIntegrationPebble(t, integrationPort(t, publicAddress), dns.address, owner)
	cfg, listeners := standalonePublishConfig(t, databaseURL, publicListener, relayUDP, pebble.directoryURL, owner)
	ca := newIntegrationTestCA(t)
	controlCertificate := ca.issueServer(t, cfg.ServerHostname(), owner)
	// publication fixtures exercise public URL issuance. relay DNS-01 polling
	// belongs to the dedicated automatic relay certificate suite.
	relayCertificate := ca.issueServer(t, cfg.StandaloneRelayHostname(), owner)
	cfg.RelayTLSCertificateFile, cfg.RelayTLSPrivateKeyFile = relayCertificate.certificateFile, relayCertificate.privateKeyFile
	if configure != nil {
		configure(&cfg)
	}
	if serviceClient == nil {
		serviceClient = &http.Client{Timeout: 10 * time.Second}
	}
	relayTLS := &tls.Config{RootCAs: ca.roots, MinVersion: tls.VersionTLS13}
	controlTLS, err := staticServerTLS(controlCertificate.certificateFile, controlCertificate.privateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	controlProxy := serviceRuntimeListener(t, owner)
	publicControl := controlProxy.Addr().String()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	serveIntegrationControlProxy(t, owner, controlProxy, cfg.ControlListen, controlTLS)
	for _, check := range beforeStart {
		check(cfg)
	}
	process := startIntegrationProcessWithOptions(t, cfg, integrationProcessOptions{
		dns: dns, listeners: listeners,
		acmeHTTPClient: pebble.httpClient, serviceHTTPClient: serviceClient,
		relayClientTLS: relayTLS, owner: owner,
	})
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(integrationPublisherDiagnostics(inspect, pebble.logPath))
		}
	})
	waitForProcessReady(t, process)
	controlHTTP, _ := newIntegrationHTTPSClient(t, ca.roots, publicControl, false, owner)
	identity := newIntegrationPublishingIdentity(t, "https://"+cfg.ServerHostname(), controlHTTP, hostnameLabel, owner)
	return &standalonePublishFixture{relayTransport: owner.quicTransport(t), owner: owner, databaseURL: databaseURL, inspect: inspect, publicAddress: publicAddress,
		relayUDPAddress: relayUDPAddress, pebble: pebble, relayTLS: relayTLS, process: process, identity: identity,
		visitor: newIntegrationVisitor(t, pebble.roots, publicAddress, owner), controlHTTP: controlHTTP}
}

func standalonePublishConfig(t *testing.T, databaseURL string, publicListener net.Listener, relayUDP net.PacketConn, directoryURL string, owner *runtimeTopology) (daemonconfig.Config, runtimeListeners) {
	t.Helper()
	const serverDomain = "integration.test"
	// standalone uses one public listener and creates its internal listeners on
	// :0 itself. these required but unused split-role addresses need no probes.
	serviceListeners := newServicePortListeners(t, owner)
	listeners := runtimeListeners{
		control: serviceRuntimeListener(t, owner), metrics: serviceRuntimeListener(t, owner),
		relayUDP: relayUDP,
		ingress:  combineIngressListeners(append([]net.Listener{publicListener}, serviceListeners...)),
	}
	owner.cleanupResource(t, func() { _ = listeners.ingress.Close() })
	return daemonconfig.Config{
		ServicePortRanges: serviceListeners.inventory(),
		Role:              daemonconfig.RoleStandalone, DatabaseURL: databaseURL, MetricsListen: listeners.metrics.Addr().String(),
		ControlListen: listeners.control.Addr().String(), PrivateControlListen: "127.0.0.1:1", IngressListen: publicListener.Addr().String(),
		ControlTrustedProxies: []string{"127.0.0.1/32"}, ControlClientIPHeader: "X-Forwarded-For",
		Route53ManagedZoneID: "fixture-zone", Route53ServerZoneID: "fixture-zone", Route53Region: "us-east-1", IngressIPv4Addresses: []string{"127.0.0.1"},
		RelayTCPListen: "127.0.0.1:1", RelayUDPListen: relayUDP.LocalAddr().String(), InternalRelayListen: "127.0.0.1:1",
		ServerDomain: serverDomain, ManagedDomain: "routes." + serverDomain,
		ManagedURLMode:   naming.ManagedURLModeGenerated,
		ACMEDirectoryURL: directoryURL, ACMEEmail: "integration@example.test", ACMEAcceptTerms: true, ACMEProfile: "tlsserver",
		PublicURLCertificateWorkers: 4,
		OIDCIssuer:                  testOIDCIssuer, OIDCClientID: "server", StorageKey: testStorageKey, AccessTokenLifetime: 5 * time.Minute, RefreshTokenLifetime: time.Hour,
		VisitorConnectionLimit: 100, PublisherConnectionLimit: 10,
		ClientHelloConnectionLimit:       1024,
		StandaloneControlConnectionLimit: 1024, StandaloneRelayConnectionLimit: 4096,
		RelayStreamCapacity: 100, QUICMaxIncomingStreams: 100, QUICIdleTimeout: time.Minute,
		IngressLeaseDuration: 5 * time.Second,
		RelayLeaseDuration:   5 * time.Second, LeaseRenewalInterval: time.Second,
		ControlRetryInterval: 10 * time.Millisecond, RoutingTableWait: time.Second, DrainTimeout: 3 * time.Second,
	}, listeners
}

func (f *standalonePublishFixture) connectors() (muxsession.Connector, muxsession.Connector) {
	return redirectIntegrationConnector(f.relayUDPAddress, muxsession.QUICConnector{TLSConfig: f.relayTLS, Dialer: f.relayTransport}),
		redirectIntegrationConnector(f.publicAddress, muxsession.TLSYamuxConnector{TLSConfig: f.relayTLS})
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
	waitForReadyPublisherConnections(t, f.inspect, ready.PublicURLID, ready.PublishRunNumber, 2)
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
	// bound the WebSocket upgrade as well as subsequent messages.
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
