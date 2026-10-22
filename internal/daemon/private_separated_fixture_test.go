package tnldruntime

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
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	clientauth "github.com/tnldotdev/tnl/internal/client/auth"
	authorityclient "github.com/tnldotdev/tnl/internal/client/authority"
	controlclient "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	tnldconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

const privateRuntimeClusterSecret = "0123456789abcdef0123456789abcdef"
const privateRuntimeStorageKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type privateRuntimeIdentity struct {
	teamID    string
	state     *clientstate.Store
	routes    *controlclient.Client
	authority *authorityclient.Client
}

type privateSeparatedFixture struct {
	publicControlAddress        string
	publicHTTP                  *http.Client
	databaseURL                 string
	database                    *controlstate.Database
	certificateAuthority        *testCertificateAuthority
	inspect                     *sql.DB
	roots                       *tls.Config
	controlConfig               tnldconfig.Config
	serviceHTTP                 *http.Client
	identity                    privateRuntimeIdentity
	tcpAddresses, quicAddresses map[string]string
	composed                    *daemon
	sharedTCP, sharedQUIC       string
	defaultTiming               bool
	configurePrivate            func(*ingress.PrivateConnectorConfig)
	visitorRoots                *tls.Config
	visitorRootPEM              []byte
	processContext              func(string) context.Context
}

// the topology has one real control database/API, two ingress runtimes and two
// relay runtimes. only infrastructure TLS uses the local test CA; private
// ingress keys and trust are fetched from control's production issuer API.
func newPrivateRuntimeFixture(t *testing.T, standalone bool, opened chan<- privateObservation) *privateSeparatedFixture {
	return newPrivateRuntimeFixtureTiming(t, standalone, opened, false)
}

func newPrivateRuntimeFixtureTiming(t *testing.T, standalone bool, opened chan<- privateObservation, defaults bool, configure ...func(*tnldconfig.Config, *http.Transport, *testCertificateAuthority)) *privateSeparatedFixture {
	return newPrivateRuntimeFixtureContext(t, standalone, opened, defaults, nil, configure...)
}

func newPrivateRuntimeFixtureContext(t *testing.T, standalone bool, opened chan<- privateObservation, defaults bool, processContext func(string) context.Context, configure ...func(*tnldconfig.Config, *http.Transport, *testCertificateAuthority)) *privateSeparatedFixture {
	t.Helper()
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "private-runtime")
	if err := controlstate.Migrate(t.Context(), databaseURL); err != nil {
		t.Fatal(err)
	}
	database, err := controlstate.Open(t.Context(), databaseURL, privateRuntimeStorageKey, "", naming.ManagedURLModeSimple)
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
	controlTLS := privateRuntimeTLS(t, ca, hostname)
	config := tnldconfig.Config{Role: tnldconfig.RoleControl, ServerDomain: "private.integration.test", ManagedDomain: "apps.private.integration.test", ManagedURLMode: naming.ManagedURLModeSimple,
		OIDCIssuer: testOIDCIssuer, OIDCClientID: "server", StorageKey: privateRuntimeStorageKey, AccessTokenLifetime: 5 * time.Minute, RefreshTokenLifetime: time.Hour,
		IngressLeaseDuration: 5 * time.Second, RelayLeaseDuration: 5 * time.Second, LeaseRenewalInterval: 500 * time.Millisecond, ControlRetryInterval: 50 * time.Millisecond, RoutingTableWait: time.Second,
		VisitorConnectionLimit: 128, PublisherConnectionLimit: 64, RelayStreamCapacity: 128, QUICMaxIncomingStreams: 128, QUICIdleTimeout: time.Minute, DrainTimeout: time.Second,
		ClientHelloConnectionLimit: 128}
	controlListener, privateControlListener := privateRuntimeListener(t), privateRuntimeListener(t)
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
	publicControlAddress := unusedTCPAddress(t)
	startIntegrationControlProxy(t, nil, publicControlAddress, config.ControlListen, controlTLS)
	pebble, dnsProvider := privateFixtureACME(t, database, &config)
	if defaults {
		config.IngressLeaseDuration, config.RelayLeaseDuration = 30*time.Second, 30*time.Second
		config.LeaseRenewalInterval, config.ControlRetryInterval = 10*time.Second, time.Second
	}
	var publicListener net.Listener
	if standalone {
		config.Role = tnldconfig.RoleStandalone
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
	serviceHTTP := &http.Client{Transport: serviceTransport, Timeout: 10 * time.Second}
	t.Cleanup(serviceTransport.CloseIdleConnections)
	secrets, err := serviceapi.NewBearerSecrets(privateRuntimeClusterSecret, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	control := &daemon{database: database, controlTLS: controlTLS, serviceHTTP: serviceHTTP, clusterSecret: privateRuntimeClusterSecret, clusterSecrets: secrets, cancel: cancel, componentDone: make(chan error, 1), startedAt: time.Now(), relayClientTLS: &tls.Config{RootCAs: ca.roots, MinVersion: tls.VersionTLS13}}
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
		settings.relayTransportTLS = privateRuntimeTLS(t, ca, settings.relayHostname)
		settings.configurePrivate = func(id string, config *ingress.PrivateConnectorConfig) {
			if !defaults {
				config.RecheckInterval, config.RecheckTimeout, config.HardAuthorizationTTL = 500*time.Millisecond, 500*time.Millisecond, 3*time.Second
				config.Control = acceleratedPrivateRecheck{config.Control}
			}
			config.Forwarder = observingPrivateForwarder{PrivateForwarder: config.Forwarder, id: id, opened: opened}
		}
		if err := control.startStandalone(ctx, settings, metrics, handler); err != nil {
			cancel()
			database.Close()
			t.Fatal(err)
		}
		privateWait(t, 10*time.Second, func(ctx context.Context) (bool, error) {
			return control.ready(ctx, tnldconfig.RoleStandalone, time.Now()) == nil, nil
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
	state, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	saveRuntimeOIDCSession(t, state, "https://"+hostname, databaseURL, config.ManagedDomain)
	authenticated, err := clientauth.Authenticate(t.Context(), clientauth.Config{ServerEndpoint: "https://" + hostname, State: state, HTTPClient: &http.Client{Transport: publicTransport, Timeout: 10 * time.Second}, Diagnostics: io.Discard})
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
	f := &privateSeparatedFixture{publicControlAddress: publicControlAddress, publicHTTP: &http.Client{Transport: publicTransport, Timeout: 10 * time.Second}, databaseURL: databaseURL, inspect: inspect, roots: &tls.Config{RootCAs: ca.roots, MinVersion: tls.VersionTLS13}, controlConfig: config, serviceHTTP: serviceHTTP,
		database: database, certificateAuthority: ca,
		identity: privateRuntimeIdentity{teamID: identity.PersonalTeamId, state: profile, routes: authenticated.Control, authority: authenticated.Authority}, tcpAddresses: make(map[string]string), quicAddresses: make(map[string]string)}
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
		id := fmt.Sprintf("private-relay-%d", index)
		name := id + ".private.integration.test"
		lifetime, stop := context.WithCancel(context.Background())
		relayMetrics := observability.New("relay")
		if processContext != nil {
			lifetime = observability.WithMetrics(lifetime, observability.FromContext(processContext("relay")))
			relayMetrics = observability.FromContext(lifetime)
		}
		relay := &daemon{serviceHTTP: serviceHTTP, clusterSecret: privateRuntimeClusterSecret, clusterSecrets: secrets, cancel: stop, componentDone: make(chan error, 1), startedAt: time.Now()}
		internalListener := privateRuntimeListener(t)
		internal := internalListener.Addr().String()
		if err := relay.startRelay(lifetime, relayProcessSettings{controlEndpoint: config.PrivateControlEndpoint(), controlAddress: config.PrivateControlListen, clusterSecret: privateRuntimeClusterSecret,
			relayServiceID: id, relayID: id, relayAddress: net.JoinHostPort(name, "443"), tlsServerName: name, transportTLS: privateRuntimeTLS(t, ca, name), internalListener: internalListener, internalAddress: internal,
			tcpListen: "127.0.0.1:0", udpListen: "127.0.0.1:0", quicIdleTimeout: time.Minute, quicMaxIncomingStreams: 128, runtime: relaySettingsFrom(config)}, relayMetrics); err != nil {
			stop()
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := relay.shutdown(time.Second); err != nil && !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("private relay shutdown: %v", err)
			}
		})
		privateWait(t, 10*time.Second, func(context.Context) (bool, error) {
			return relay.readyRelays(tnldconfig.RoleRelay, time.Now()) == nil, nil
		})
		f.tcpAddresses[net.JoinHostPort(name, "443")] = relay.relays[0].tcpListener.Addr().String()
		f.quicAddresses[net.JoinHostPort(name, "443")] = relay.relays[0].udpListener.Addr().String()
	}
	return f
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
	return redirect(f.quicAddresses, muxsession.QUICConnector{TLSConfig: f.roots}), redirect(f.tcpAddresses, muxsession.TLSYamuxConnector{TLSConfig: f.roots})
}

func privateDisabledConnector() muxsession.Connector {
	return muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
		return nil, errors.New("transport disabled by private runtime workload")
	})
}

func privateRuntimeTLS(t *testing.T, ca *testCertificateAuthority, hostname string) *tls.Config {
	t.Helper()
	material := ca.issue(t, hostname)
	certificate, err := tls.X509KeyPair(material.certificatePEM, material.privateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
}

func privateRuntimeListener(t *testing.T) net.Listener {
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
