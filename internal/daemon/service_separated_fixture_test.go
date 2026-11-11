package daemon

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/client/auth"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/observability"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/transporttest"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

const serviceRuntimeClusterSecret = "0123456789abcdef0123456789abcdef"
const serviceRuntimeStorageKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type serviceRuntimeIdentity struct {
	teamID    string
	state     *clientstate.Store
	routes    *clientcontrol.Client
	authority *clientauthority.Client
}

type privateSeparatedFixture struct {
	relayTransport              *muxsession.QUICTransport
	publicControlAddress        string
	publicHTTP                  *http.Client
	databaseURL                 string
	database                    *controlstate.Database
	certificateAuthority        *testCertificateAuthority
	inspect                     *sql.DB
	roots                       *tls.Config
	controlConfig               daemonconfig.Config
	serviceHTTP                 *http.Client
	identity                    serviceRuntimeIdentity
	tcpAddresses, quicAddresses map[string]string
	composed                    *daemon
	sharedTCP, sharedQUIC       string
	defaultTiming               bool
	configurePublicServices     func(*ingress.PublicServicesConfig)
	visitorRoots                *tls.Config
	visitorRootPEM              []byte
	processContext              func(string) context.Context
	publisherConnections        chan<- *publisherservice.Claimed
	publisherTCPOnly            bool
	relayProcesses              map[string]*privateRelayFixture
}

type privateRelayFixture struct {
	process  *daemon
	settings relayProcessSettings
	stop     func() error
}

// the topology has one real control database/API and two relay runtimes. tests
// that exercise public/direct serving add ingress; native traffic never does.
// infrastructure TLS uses the local test CA and visitor TLS uses local ACME.
func newServiceRuntimeFixture(t *testing.T, standalone bool, opened chan<- privateObservation) *privateSeparatedFixture {
	return newServiceRuntimeFixtureTiming(t, standalone, opened, false)
}

func newServiceRuntimeFixtureTiming(t *testing.T, standalone bool, opened chan<- privateObservation, defaults bool, configure ...func(*daemonconfig.Config, *http.Transport, *testCertificateAuthority)) *privateSeparatedFixture {
	return newServiceRuntimeFixtureContext(t, standalone, opened, defaults, nil, configure...)
}

func newServiceRuntimeFixtureContext(t *testing.T, standalone bool, opened chan<- privateObservation, defaults bool, processContext func(string) context.Context, configure ...func(*daemonconfig.Config, *http.Transport, *testCertificateAuthority)) *privateSeparatedFixture {
	t.Helper()
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "service-runtime")
	if err := controlstate.Migrate(t.Context(), databaseURL); err != nil {
		t.Fatal(err)
	}
	database, err := controlstate.Open(t.Context(), databaseURL, serviceRuntimeStorageKey, "", naming.ManagedURLModeSimple)
	if err != nil {
		t.Fatal(err)
	}
	inspect, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inspect.Close() })
	ca := newTestCertificateAuthority(t)
	const hostname = "control.private.integration.test"
	controlTLS := serviceRuntimeTLS(t, ca, hostname)
	config := daemonconfig.Config{Role: daemonconfig.RoleControl, ServerDomain: "private.integration.test", ManagedDomain: "apps.private.integration.test", ManagedURLMode: naming.ManagedURLModeSimple,
		OIDCIssuer: testOIDCIssuer, OIDCClientID: "server", StorageKey: serviceRuntimeStorageKey, AccessTokenLifetime: 5 * time.Minute, RefreshTokenLifetime: time.Hour,
		IngressLeaseDuration: 5 * time.Second, RelayLeaseDuration: 5 * time.Second, LeaseRenewalInterval: 500 * time.Millisecond, ControlRetryInterval: 50 * time.Millisecond, RoutingTableWait: time.Second,
		VisitorConnectionLimit: 128, PublisherConnectionLimit: 64, RelayStreamCapacity: 128, QUICMaxIncomingStreams: 128, QUICIdleTimeout: time.Minute, DrainTimeout: time.Second,
		ClientHelloConnectionLimit: 128}
	controlListener, privateControlListener := serviceRuntimeListener(t), serviceRuntimeListener(t)
	config.ControlListen, config.PrivateControlListen = controlListener.Addr().String(), privateControlListener.Addr().String()
	var serviceListeners []net.Listener
	if standalone {
		config.ServicePortRanges, serviceListeners = reserveIntegrationServicePorts(t)
	} else {
		config.ServicePortRanges = integrationServicePorts(t)
	}
	ports, err := config.ServicePortInventory()
	if err != nil {
		t.Fatal(err)
	}
	if err := database.ConfigureIngressServicePorts(t.Context(), controlstate.PrimaryIngressPoolID, ports.Ranges()); err != nil {
		t.Fatal(err)
	}
	config.ControlTrustedProxies, config.ControlClientIPHeader = []string{"127.0.0.1/32"}, "X-Forwarded-For"
	publicControlListener := serviceRuntimeListener(t)
	publicControlAddress := publicControlListener.Addr().String()
	serveIntegrationControlProxy(t, nil, publicControlListener, config.ControlListen, controlTLS)
	pebble, dnsProvider := privateFixtureACME(t, database, &config)
	if defaults {
		config.IngressLeaseDuration, config.RelayLeaseDuration = 30*time.Second, 30*time.Second
		config.LeaseRenewalInterval, config.ControlRetryInterval = 10*time.Second, time.Second
	}
	var publicListener net.Listener
	if standalone {
		config.Role = daemonconfig.RoleStandalone
		publicListener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = publicListener.Close() })
		config.IngressListen = publicListener.Addr().String()
		config.RelayUDPListen = "127.0.0.1:0"
	}
	serviceTransport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.roots, MinVersion: tls.VersionTLS13}}
	for _, setup := range configure {
		setup(&config, serviceTransport, ca)
	}
	if err := database.PrepareVisitorSigningKeys(t.Context(), config.ControlOrigin(), time.Now()); err != nil {
		t.Fatal(err)
	}
	serviceHTTP := &http.Client{Transport: serviceTransport, Timeout: 10 * time.Second}
	t.Cleanup(serviceTransport.CloseIdleConnections)
	secrets, err := serviceapi.NewBearerSecrets(serviceRuntimeClusterSecret, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	control := &daemon{database: database, controlTLS: controlTLS, serviceHTTP: serviceHTTP, clusterSecret: serviceRuntimeClusterSecret, clusterSecrets: secrets, cancel: cancel, componentDone: make(chan error, 1), startedAt: time.Now(), relayClientTLS: &tls.Config{RootCAs: ca.roots, MinVersion: tls.VersionTLS13}}
	metrics := observability.New("control")
	if processContext != nil {
		ctx = observability.WithMetrics(ctx, observability.FromContext(processContext("control")))
		metrics = observability.FromContext(ctx)
	}
	handler, err := newPublicAPIHandler(config, time.Now(), serviceHTTP, database, metrics, control, nil)
	if err != nil {
		cancel()
		database.Close()
		t.Fatal(err)
	}
	startPrivateFixtureWorkers(t, ctx, control, database, config, pebble, dnsProvider)
	if standalone {
		settings := standaloneSettingsFrom(config)
		settings.control.listener = controlListener
		settings.publicListener = publicListener
		if !config.RequireProxyHeader {
			settings.publicListener = combineIngressListeners(append([]net.Listener{publicListener}, serviceListeners...))
		}
		t.Cleanup(func() { _ = settings.publicListener.Close() })
		settings.relayTransportTLS = serviceRuntimeTLS(t, ca, settings.relayHostname)
		settings.configurePublicServices = func(config *ingress.PublicServicesConfig) {
			if !defaults {
				config.RecheckInterval, config.RecheckTimeout, config.HardAuthorizationTTL = 500*time.Millisecond, 500*time.Millisecond, 3*time.Second
			}
			config.Forwarder = observingServiceForwarder{ServiceForwarder: config.Forwarder, id: standaloneIngressID, opened: opened}
		}
		if err := control.startStandalone(ctx, settings, metrics, handler); err != nil {
			cancel()
			database.Close()
			t.Fatal(err)
		}
		privateWait(t, 10*time.Second, func(ctx context.Context) (bool, error) {
			return control.ready(ctx, daemonconfig.RoleStandalone, time.Now()) == nil, nil
		})
	} else {
		settings := controlSettingsFrom(config)
		settings.listener = controlListener
		if err := control.startControl(settings, handler); err != nil {
			cancel()
			database.Close()
			t.Fatal(err)
		}
		privateSettings := privateControlSettingsFrom(config)
		privateSettings.listener = privateControlListener
		if err := control.startPrivateControlAPIs(ctx, privateSettings, metrics); err != nil {
			cancel()
			database.Close()
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		if err := control.shutdown(time.Second); err != nil {
			t.Errorf("private control shutdown: %v", err)
		}
	})
	publicTransport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.roots, MinVersion: tls.VersionTLS13}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, publicControlAddress)
	}}
	t.Cleanup(publicTransport.CloseIdleConnections)
	// runtime fixtures keep credentials in private temporary files, never the
	// machine's login keychain; key protection is tested by the state owner.
	state, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	saveRuntimeOIDCSession(t, state, "https://"+hostname, databaseURL, config.ManagedDomain)
	authenticated, err := auth.Authenticate(t.Context(), auth.Config{ServerEndpoint: "https://" + hostname, State: state, HTTPClient: &http.Client{Transport: publicTransport, Timeout: 10 * time.Second}, Diagnostics: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := authenticated.Authority.IdentityContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	profile, err := state.Server(t.Context(), "https://"+hostname)
	if err != nil {
		t.Fatal(err)
	}
	f := &privateSeparatedFixture{relayTransport: transporttest.QUICTransport(t), publicControlAddress: publicControlAddress, publicHTTP: &http.Client{Transport: publicTransport, Timeout: 10 * time.Second}, databaseURL: databaseURL, inspect: inspect, roots: &tls.Config{RootCAs: ca.roots, MinVersion: tls.VersionTLS13}, controlConfig: config, serviceHTTP: serviceHTTP,
		database: database, certificateAuthority: ca,
		identity: serviceRuntimeIdentity{teamID: identity.PersonalTeamId, state: profile, routes: authenticated.Control, authority: authenticated.Authority}, tcpAddresses: make(map[string]string), quicAddresses: make(map[string]string)}
	f.defaultTiming = defaults
	f.processContext = processContext
	f.visitorRoots = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pebble.roots}
	f.visitorRootPEM = pebble.rootPEM
	if standalone {
		f.composed = control
		f.sharedTCP = config.IngressListen
		f.sharedQUIC = control.relays[0].udpListener.Addr().String()
		address := net.JoinHostPort(config.StandaloneRelayHostname(), "443")
		f.tcpAddresses[address], f.quicAddresses[address] = f.sharedTCP, f.sharedQUIC
		return f
	}
	for index := 0; index < 2; index++ {
		f.startFixtureRelay(t, fmt.Sprintf("private-relay-%d", index))
	}
	return f
}

func (f *privateSeparatedFixture) startFixtureRelay(t *testing.T, id string) *privateRelayFixture {
	t.Helper()
	name := id + ".private.integration.test"
	internal := serviceRuntimeListener(t)
	publisher := serviceRuntimeListener(t)
	// relay discovery uses the same advertised address for TCP, QUIC and STUN.
	packet, err := net.ListenPacket("udp4", publisher.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packet.Close() })
	settings := relayProcessSettings{controlEndpoint: f.controlConfig.PrivateControlEndpoint(), controlAddress: f.controlConfig.PrivateControlListen, clusterSecret: serviceRuntimeClusterSecret,
		relayServiceID: id, relayID: id, relayAddress: publisher.Addr().String(), tlsServerName: name, transportTLS: serviceRuntimeTLS(t, f.certificateAuthority, name), internalListener: internal, internalAddress: internal.Addr().String(),
		tcpListener: publisher, udpPacket: packet, udpListen: packet.LocalAddr().String(), quic: f.controlConfig.RelayQUICConfig(), runtime: relaySettingsFrom(f.controlConfig)}
	return f.runFixtureRelay(t, settings)
}

func (f *privateSeparatedFixture) runFixtureRelay(t *testing.T, settings relayProcessSettings) *privateRelayFixture {
	t.Helper()
	lifetime, cancel := context.WithCancel(context.Background())
	metrics := observability.New("relay")
	if f.processContext != nil {
		lifetime = observability.WithMetrics(lifetime, observability.FromContext(f.processContext("relay")))
		metrics = observability.FromContext(lifetime)
	}
	secrets, err := serviceapi.NewBearerSecrets(serviceRuntimeClusterSecret, "")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	relay := &daemon{serviceHTTP: f.serviceHTTP, clusterSecret: serviceRuntimeClusterSecret, clusterSecrets: secrets, cancel: cancel, componentDone: make(chan error, 1), startedAt: time.Now()}
	if err := relay.startRelay(lifetime, settings, metrics); err != nil {
		cancel()
		t.Fatal(err)
	}
	fixture := &privateRelayFixture{process: relay, settings: settings, stop: sync.OnceValue(func() error { return relay.shutdown(time.Second) })}
	t.Cleanup(func() {
		if err := fixture.stop(); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("private relay shutdown: %v", err)
		}
	})
	privateWait(t, 10*time.Second, func(context.Context) (bool, error) {
		return relay.readyRelays(daemonconfig.RoleRelay, time.Now()) == nil, nil
	})
	if f.relayProcesses == nil {
		f.relayProcesses = make(map[string]*privateRelayFixture)
	}
	f.relayProcesses[settings.relayID] = fixture
	// address maps are immutable once publisher workers begin. process restarts
	// retain their listeners' addresses and do not race those workers with writes.
	if _, exists := f.tcpAddresses[settings.relayAddress]; !exists {
		f.tcpAddresses[settings.relayAddress] = relay.relays[0].tcpListener.Addr().String()
		f.quicAddresses[settings.relayAddress] = relay.relays[0].udpListener.Addr().String()
	}
	return fixture
}

func (f *privateSeparatedFixture) connectors() (muxsession.Connector, muxsession.Connector) {
	redirect := func(addresses map[string]string, connector muxsession.Connector) muxsession.Connector {
		return muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
			address := addresses[endpoint.Address]
			if address == "" {
				return nil, errors.New("missing infrastructure address")
			}
			endpoint.Address = address
			return connector.Connect(ctx, endpoint)
		})
	}
	return redirect(f.quicAddresses, muxsession.QUICConnector{TLSConfig: f.roots, Config: muxsession.QUICConfig{Config: &quic.Config{EnableDatagrams: true}}, Dialer: f.relayTransport}), redirect(f.tcpAddresses, muxsession.TLSYamuxConnector{TLSConfig: f.roots})
}

func privateDisabledConnector() muxsession.Connector {
	return muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
		return nil, errors.New("transport disabled by private runtime workload")
	})
}

func serviceRuntimeTLS(t *testing.T, ca *testCertificateAuthority, hostname string) *tls.Config {
	t.Helper()
	material := ca.issue(t, hostname)
	certificate, err := tls.X509KeyPair(material.certificatePEM, material.privateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
}

func serviceRuntimeListener(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func privateWait(t *testing.T, timeout time.Duration, condition func(context.Context) (bool, error)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	var last error
	for {
		ready, err := condition(ctx)
		if ready && err == nil {
			return
		}
		last = err
		select {
		case <-ctx.Done():
			t.Fatalf("private runtime condition did not become ready: %v (%v)", ctx.Err(), last)
		case <-time.After(10 * time.Millisecond):
		}
	}
}
