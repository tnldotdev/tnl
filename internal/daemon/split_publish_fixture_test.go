package daemon

import (
	"context"
	"crypto/tls"
	"database/sql"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
)

type splitRelayFixture struct {
	config    daemonconfig.Config
	process   *integrationProcess
	listeners runtimeListeners
}

type splitPublishFixture struct {
	relayTransport           *muxsession.QUICTransport
	processContext           func(string) context.Context
	owner                    *runtimeTopology
	databaseURL              string
	inspect                  *sql.DB
	pebble                   integrationPebble
	roots                    *tls.Config
	controlConfig            daemonconfig.Config
	controlOptions           integrationProcessOptions
	ingressConfig            daemonconfig.Config
	control, ingress         *integrationProcess
	relayA, relayB           splitRelayFixture
	serviceHTTP, controlHTTP *http.Client
	identity                 *integrationPublishingIdentity
	visitor                  *integrationVisitor
}

type splitPublishOptions struct {
	processContext       func(string) context.Context
	dns                  *integrationRoute53
	proxyIngress         bool
	configureControlHTTP func(*http.Client)
	configureProcess     func(*daemonconfig.Config)
}

func newSplitPublishFixture(t *testing.T, hostnameLabel string) *splitPublishFixture {
	t.Helper()
	return newSplitPublishFixtureWithOptions(t, hostnameLabel, splitPublishOptions{})
}

func newSplitPublishFixtureWithOptions(t *testing.T, hostnameLabel string, options splitPublishOptions, configureACME ...func(*http.Client)) *splitPublishFixture {
	t.Helper()
	databaseURL, inspect := standaloneTestDatabase(t)
	owner := newRuntimeTopology(t)
	const serverDomain = "split.integration.test"
	controlHostname := "control." + serverDomain
	certificateAuthority := newIntegrationTestCA(t)
	controlCertificate := certificateAuthority.issueServer(t, controlHostname, owner)
	var relayACertificate, relayBCertificate integrationCertificate
	if options.dns == nil {
		relayACertificate = certificateAuthority.issueServer(t, "relay-a."+serverDomain, owner)
		relayBCertificate = certificateAuthority.issueServer(t, "relay-b."+serverDomain, owner)
	}
	controlProxyListener, privateControlListener, ingressListener := serviceRuntimeListener(t, owner), serviceRuntimeListener(t, owner), serviceRuntimeListener(t, owner)
	controlAddress, privateControlAddress, ingressAddress := controlProxyListener.Addr().String(), privateControlListener.Addr().String(), ingressListener.Addr().String()
	publicIngressAddress := ingressAddress
	publicIngressListener := ingressListener
	if options.proxyIngress {
		ingressListener = serviceRuntimeListener(t, owner)
		ingressAddress = ingressListener.Addr().String()
	}
	var dnsAddress string
	var localDNS *privateFixtureDNS
	if options.dns != nil {
		dnsAddress = options.dns.address
	} else {
		localDNS = newPrivateFixtureDNS(t, owner)
		dnsAddress = localDNS.address
	}
	pebble := startIntegrationPebble(t, integrationPort(t, publicIngressAddress), dnsAddress, owner)
	for _, configure := range configureACME {
		configure(pebble.httpClient)
	}
	serviceHTTP := splitTestServiceHTTPClient(t, certificateAuthority.roots, privateControlAddress, owner)
	controlConfig := splitPublishConfig(t, daemonconfig.RoleControl)
	controlSockets := runtimeListeners{control: serviceRuntimeListener(t, owner), privateControl: privateControlListener, metrics: serviceRuntimeListener(t, owner)}
	serviceListeners := newServicePortListeners(t, owner)
	controlConfig.ServicePortRanges = serviceListeners.inventory()
	controlConfig.DatabaseURL = databaseURL
	controlConfig.ControlListen = controlSockets.control.Addr().String()
	controlConfig.MetricsListen = controlSockets.metrics.Addr().String()
	controlConfig.PrivateControlListen = privateControlAddress
	controlConfig.ClusterSecret = testClusterSecret
	controlConfig.ServerDomain = serverDomain
	controlConfig.ManagedDomain = "routes." + serverDomain
	controlConfig.ControlTLSCertificateFile = controlCertificate.certificateFile
	controlConfig.ControlTLSPrivateKeyFile = controlCertificate.privateKeyFile
	controlConfig.ACMEDirectoryURL = pebble.directoryURL
	controlConfig.ACMEEmail = "integration@example.test"
	controlConfig.ACMEAcceptTerms = true
	controlConfig.ACMEProfile = "tlsserver"
	controlConfig.OIDCIssuer, controlConfig.OIDCClientID = testOIDCIssuer, "server"
	controlConfig.StorageKey = testStorageKey
	controlConfig.AccessTokenLifetime = 5 * time.Minute
	controlConfig.RefreshTokenLifetime = time.Hour
	controlConfig.Route53ManagedZoneID, controlConfig.Route53Region = "fixture-zone", "us-east-1"
	controlConfig.IngressIPv4Addresses = []string{"127.0.0.1"}
	if options.dns != nil {
		controlConfig.ManagedDomain = serverDomain
		controlConfig.DNSServer = options.dns.address
		controlConfig.Route53Region = "us-east-1"
		controlConfig.Route53ManagedZoneID = options.dns.zoneID
		controlConfig.Route53ServerZoneID = options.dns.zoneID
		controlConfig.IngressIPv4Addresses = []string{"127.0.0.1"}
	}
	if options.configureProcess != nil {
		options.configureProcess(&controlConfig)
	}
	if err := controlConfig.Validate(); err != nil {
		t.Fatal(err)
	}
	ingressConfig := splitPublishConfig(t, daemonconfig.RoleIngress)
	ingressSockets := runtimeListeners{ingress: ingressListener, metrics: serviceRuntimeListener(t, owner)}
	ingressConfig.MetricsListen = ingressSockets.metrics.Addr().String()
	ingressConfig.ServicePortRanges = controlConfig.ServicePortRanges
	ingressConfig.ControlHostname = controlHostname
	ingressConfig.ClusterSecret = testClusterSecret
	ingressConfig.IngressID = "ingress-split"
	ingressConfig.IngressListen = ingressAddress
	relayAConfig, relayASockets := splitPublishRelayConfig(t, controlHostname, serverDomain, "relay-a", "relay-a-1", relayACertificate, owner)
	relayBConfig, relayBSockets := splitPublishRelayConfig(t, controlHostname, serverDomain, "relay-b", "relay-b-1", relayBCertificate, owner)
	if options.dns != nil {
		relayAConfig.ControlRetryInterval = 100 * time.Millisecond
		relayBConfig.ControlRetryInterval = 100 * time.Millisecond
	}
	for _, cfg := range []*daemonconfig.Config{&ingressConfig, &relayAConfig, &relayBConfig} {
		if options.configureProcess != nil {
			options.configureProcess(cfg)
		}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	if !ingressConfig.RequireProxyHeader {
		ingressSockets.ingress = combineIngressListeners(append([]net.Listener{ingressListener}, serviceListeners...))
		owner.cleanupResource(t, func() { _ = ingressSockets.ingress.Close() })
	}
	// dependencies outlive every incarnation of control, ingress, and relay.
	controlTLS, err := staticServerTLS(controlCertificate.certificateFile, controlCertificate.privateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	serveIntegrationControlProxy(t, owner, controlProxyListener, controlConfig.ControlListen, controlTLS)
	if options.proxyIngress {
		startSplitIngressProxy(t, owner, publicIngressListener, ingressAddress)
	}
	controlOptions := integrationProcessOptions{acmeHTTPClient: pebble.httpClient, serviceHTTPClient: serviceHTTP, owner: owner, listeners: controlSockets}
	if options.processContext != nil {
		controlOptions.context = options.processContext("control")
	}
	if localDNS != nil {
		controlOptions.dns = localDNS
	}
	control := startIntegrationProcessWithOptions(t, controlConfig, controlOptions)
	waitForProcessReady(t, control)
	// replacements bind their configured addresses after the previous process stops.
	controlOptions.listeners = runtimeListeners{}
	relayRoots := certificateAuthority.roots
	if options.dns != nil {
		relayRoots = pebble.roots
	}
	f := &splitPublishFixture{
		relayTransport: owner.quicTransport(t),
		processContext: options.processContext,
		owner:          owner, databaseURL: databaseURL, inspect: inspect, pebble: pebble,
		roots:         &tls.Config{RootCAs: relayRoots, MinVersion: tls.VersionTLS13},
		controlConfig: controlConfig, controlOptions: controlOptions, ingressConfig: ingressConfig,
		control: control, serviceHTTP: serviceHTTP,
		relayA: splitRelayFixture{config: relayAConfig, listeners: relayASockets}, relayB: splitRelayFixture{config: relayBConfig, listeners: relayBSockets},
	}
	f.relayA.process = f.startRelay(t, relayAConfig)
	f.relayB.process = f.startRelay(t, relayBConfig)
	f.ingress = startIntegrationProcessWithOptions(t, ingressConfig, integrationProcessOptions{
		context:        f.contextFor("ingress"),
		acmeHTTPClient: pebble.httpClient, serviceHTTPClient: serviceHTTP, relayClientTLS: f.roots, owner: owner, listeners: ingressSockets,
	})
	for _, process := range []*integrationProcess{f.relayA.process, f.relayB.process, f.ingress} {
		waitForProcessReady(t, process)
	}
	assertSplitLeases(t, inspect, 1, 2, 0, 0)
	controlHTTP, _ := newIntegrationHTTPSClient(t, certificateAuthority.roots, controlAddress, false, owner)
	if options.configureControlHTTP != nil {
		options.configureControlHTTP(controlHTTP)
	}
	f.identity = newIntegrationPublishingIdentity(t, "https://"+controlHostname, controlHTTP, hostnameLabel, owner)
	f.controlHTTP = controlHTTP
	f.visitor = newIntegrationVisitor(t, pebble.roots, publicIngressAddress, owner)
	return f
}

// a disposable front address writes trusted PROXY v2 metadata for ordinary
// HTTPS visitors. database test clients supply their own original port
// through the separate private ingress listener.
func startSplitIngressProxy(t *testing.T, owner *runtimeTopology, listener net.Listener, backend string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var active sync.WaitGroup
	var mu sync.Mutex
	connections := make(map[net.Conn]struct{})
	retain := func(connection net.Conn) bool {
		mu.Lock()
		defer mu.Unlock()
		if ctx.Err() != nil {
			_ = connection.Close()
			return false
		}
		connections[connection] = struct{}{}
		return true
	}
	release := func(connection net.Conn) {
		_ = connection.Close()
		mu.Lock()
		delete(connections, connection)
		mu.Unlock()
	}
	acceptDone := make(chan struct{})
	owner.cleanupResource(t, func() {
		cancel()
		_ = listener.Close()
		<-acceptDone
		mu.Lock()
		for connection := range connections {
			_ = connection.Close()
		}
		mu.Unlock()
		active.Wait()
	})
	go func() {
		defer close(acceptDone)
		for {
			visitor, err := listener.Accept()
			if err != nil {
				return
			}
			if !retain(visitor) {
				return
			}
			active.Add(1)
			go func() {
				defer active.Done()
				defer release(visitor)
				dialCtx, cancelDial := context.WithTimeout(ctx, 5*time.Second)
				upstream, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", backend)
				cancelDial()
				if err != nil {
					return
				}
				if !retain(upstream) {
					return
				}
				defer release(upstream)
				source := visitor.RemoteAddr().(*net.TCPAddr).AddrPort()
				meta, err := proxyproto.Encode(proxyproto.Header{Source: netip.AddrPortFrom(source.Addr().Unmap(), source.Port()), Destination: netip.MustParseAddrPort("127.0.0.1:443")})
				if err != nil {
					return
				}
				if _, err := upstream.Write(meta); err != nil {
					return
				}
				finished := make(chan struct{})
				go func() {
					_, _ = io.Copy(visitor, upstream)
					if tcp, ok := visitor.(*net.TCPConn); ok {
						_ = tcp.CloseWrite()
					}
					close(finished)
				}()
				_, _ = io.Copy(upstream, visitor)
				if tcp, ok := upstream.(*net.TCPConn); ok {
					_ = tcp.CloseWrite()
				}
				<-finished
			}()
		}
	}()
}

func splitPublishConfig(t *testing.T, role daemonconfig.Role) daemonconfig.Config {
	t.Helper()
	cfg := splitTestConfig(role, "")
	cfg.IngressLeaseDuration = 5 * time.Second
	cfg.RelayLeaseDuration = 5 * time.Second
	cfg.LeaseRenewalInterval = 500 * time.Millisecond
	cfg.DrainTimeout = 5 * time.Second
	return cfg
}

func splitPublishRelayConfig(t *testing.T, controlHostname, serverDomain, relayServiceID, relayID string, certificate integrationCertificate, owner *runtimeTopology) (daemonconfig.Config, runtimeListeners) {
	t.Helper()
	cfg := splitPublishConfig(t, daemonconfig.RoleRelay)
	cfg.ControlHostname = controlHostname
	cfg.ClusterSecret = testClusterSecret
	cfg.RelayServiceID = relayServiceID
	cfg.RelayID = relayID
	cfg.RelayAddress = relayServiceID + "." + serverDomain + ":443"
	cfg.RelayTLSCertificateFile = certificate.certificateFile
	cfg.RelayTLSPrivateKeyFile = certificate.privateKeyFile
	listeners := runtimeListeners{metrics: serviceRuntimeListener(t, owner), relayTCP: serviceRuntimeListener(t, owner), relayInternal: serviceRuntimeListener(t, owner), relayUDP: integrationPacketListener(t, owner)}
	cfg.MetricsListen = listeners.metrics.Addr().String()
	cfg.RelayTCPListen = listeners.relayTCP.Addr().String()
	cfg.RelayUDPListen = listeners.relayUDP.LocalAddr().String()
	cfg.InternalRelayListen = listeners.relayInternal.Addr().String()
	cfg.InternalRelayAddress = cfg.InternalRelayListen
	return cfg, listeners
}

func (f *splitPublishFixture) startRelay(t *testing.T, cfg daemonconfig.Config) *integrationProcess {
	t.Helper()
	options := integrationProcessOptions{context: f.contextFor("relay"), acmeHTTPClient: f.pebble.httpClient, serviceHTTPClient: f.serviceHTTP, owner: f.owner}
	for _, relay := range []*splitRelayFixture{&f.relayA, &f.relayB} {
		if relay.config.RelayID == cfg.RelayID {
			options.listeners = relay.listeners
			relay.listeners = runtimeListeners{}
			break
		}
	}
	return startIntegrationProcessWithOptions(t, cfg, options)
}

func (f *splitPublishFixture) contextFor(role string) context.Context {
	if f.processContext != nil {
		return f.processContext(role)
	}
	return nil
}

func (f *splitPublishFixture) connectors() (muxsession.Connector, muxsession.Connector) {
	quicAddresses := map[string]string{f.relayA.config.RelayAddress: f.relayA.config.RelayUDPListen, f.relayB.config.RelayAddress: f.relayB.config.RelayUDPListen}
	tcpAddresses := map[string]string{f.relayA.config.RelayAddress: f.relayA.config.RelayTCPListen, f.relayB.config.RelayAddress: f.relayB.config.RelayTCPListen}
	return publicURLIntegrationConnector(quicAddresses, muxsession.QUICConnector{TLSConfig: f.roots, Dialer: f.relayTransport}), publicURLIntegrationConnector(tcpAddresses, muxsession.TLSYamuxConnector{TLSConfig: f.roots})
}

func (f *splitPublishFixture) startPublisher(t *testing.T, target string, quicConnector, tcpConnector muxsession.Connector) *integrationPublisher {
	t.Helper()
	return startOwnedIntegrationPublisher(t, f.owner, f.identity.publisherConfig(target, quicConnector, tcpConnector), func() string { return integrationPublisherDiagnostics(f.inspect, f.pebble.logPath) })
}

func (f *splitPublishFixture) waitReady(t *testing.T, handle *integrationPublisher) publisher.Event {
	t.Helper()
	ready := waitForPublisherReady(t, handle)
	if ready.Hostname != f.identity.hostname || ready.PublicURL != "https://"+f.identity.hostname {
		t.Fatalf("publisher ready event = %#v", ready)
	}
	waitForReadyPublisherConnections(t, f.inspect, ready.PublicURLID, ready.PublishRunNumber, 2)
	waitForIngressRoutingCurrent(t, f.inspect, 1)
	return ready
}
