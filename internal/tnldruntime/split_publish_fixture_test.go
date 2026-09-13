package tnldruntime

import (
	"crypto/tls"
	"database/sql"
	"net/http"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
)

type splitRelayFixture struct {
	config  tnldconfig.Config
	process *integrationProcess
}

type splitPublishFixture struct {
	owner                    *runtimeTopology
	databaseURL              string
	inspect                  *sql.DB
	pebble                   integrationPebble
	roots                    *tls.Config
	controlConfig            tnldconfig.Config
	controlOptions           integrationProcessOptions
	ingressConfig            tnldconfig.Config
	control, ingress         *integrationProcess
	relayA, relayB           splitRelayFixture
	serviceHTTP, controlHTTP *http.Client
	identity                 *integrationPublishingIdentity
	visitor                  *integrationVisitor
}

type splitPublishOptions struct {
	dns                  *integrationRoute53
	configureControlHTTP func(*http.Client)
	configureProcess     func(*tnldconfig.Config)
}

func newSplitPublishFixture(t *testing.T, hostnameLabel string) *splitPublishFixture {
	t.Helper()
	return newSplitPublishFixtureWithOptions(t, hostnameLabel, splitPublishOptions{})
}

func newSplitPublishFixtureWithOptions(t *testing.T, hostnameLabel string, options splitPublishOptions, configureACME ...func(*http.Client)) *splitPublishFixture {
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
	controlAddress, privateControlAddress, ingressAddress := unusedTCPAddress(t), unusedTCPAddress(t), unusedTCPAddress(t)
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
	if options.configureProcess != nil {
		options.configureProcess(&controlConfig)
	}
	if err := controlConfig.Validate(); err != nil {
		t.Fatal(err)
	}
	// Dependencies outlive every incarnation of control, ingress, and relay.
	owner := newRuntimeTopology(t)
	controlOptions := integrationProcessOptions{acmeHTTPClient: pebble.httpClient, serviceHTTPClient: serviceHTTP, owner: owner}
	control := startIntegrationProcessWithOptions(t, controlConfig, controlOptions)
	waitForProcessReady(t, control)
	ingressConfig := splitPublishConfig(t, tnldconfig.RoleIngress)
	ingressConfig.ControlHostname = controlHostname
	ingressConfig.ClusterSecret = testClusterSecret
	ingressConfig.IngressID = "ingress-split"
	ingressConfig.IngressListen = ingressAddress
	relayAConfig := splitPublishRelayConfig(t, controlHostname, serverDomain, "relay-a", "relay-a-1", relayACertificate)
	relayBConfig := splitPublishRelayConfig(t, controlHostname, serverDomain, "relay-b", "relay-b-1", relayBCertificate)
	if options.dns != nil {
		relayAConfig.ControlRetryInterval = 100 * time.Millisecond
		relayBConfig.ControlRetryInterval = 100 * time.Millisecond
	}
	for _, cfg := range []*tnldconfig.Config{&ingressConfig, &relayAConfig, &relayBConfig} {
		if options.configureProcess != nil {
			options.configureProcess(cfg)
		}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	relayRoots := certificateAuthority.roots
	if options.dns != nil {
		relayRoots = pebble.roots
	}
	f := &splitPublishFixture{
		owner: owner, databaseURL: databaseURL, inspect: inspect, pebble: pebble,
		roots:         &tls.Config{RootCAs: relayRoots, MinVersion: tls.VersionTLS13},
		controlConfig: controlConfig, controlOptions: controlOptions, ingressConfig: ingressConfig,
		control: control, serviceHTTP: serviceHTTP,
		relayA: splitRelayFixture{config: relayAConfig}, relayB: splitRelayFixture{config: relayBConfig},
	}
	f.relayA.process = f.startRelay(t, relayAConfig)
	f.relayB.process = f.startRelay(t, relayBConfig)
	f.ingress = startIntegrationProcessWithOptions(t, ingressConfig, integrationProcessOptions{
		acmeHTTPClient: pebble.httpClient, serviceHTTPClient: serviceHTTP, relayClientTLS: f.roots, owner: owner,
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
	f.visitor = newIntegrationVisitor(t, pebble.roots, ingressAddress, owner)
	return f
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

func splitPublishRelayConfig(t *testing.T, controlHostname, serverDomain, relayServiceID, relayID string, certificate integrationCertificate) tnldconfig.Config {
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
	return startIntegrationProcessWithOptions(t, cfg, integrationProcessOptions{acmeHTTPClient: f.pebble.httpClient, serviceHTTPClient: f.serviceHTTP, owner: f.owner})
}

func (f *splitPublishFixture) connectors() (muxsession.Connector, muxsession.Connector) {
	quicAddresses := map[string]string{f.relayA.config.RelayAddress: f.relayA.config.RelayUDPListen, f.relayB.config.RelayAddress: f.relayB.config.RelayUDPListen}
	tcpAddresses := map[string]string{f.relayA.config.RelayAddress: f.relayA.config.RelayTCPListen, f.relayB.config.RelayAddress: f.relayB.config.RelayTCPListen}
	return routeIntegrationConnector(quicAddresses, muxsession.QUICConnector{TLSConfig: f.roots}), routeIntegrationConnector(tcpAddresses, muxsession.TLSYamuxConnector{TLSConfig: f.roots})
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
	waitForReadyPublisherConnections(t, f.inspect, ready.RouteID, ready.RouteVersion, 2)
	waitForIngressRoutingCurrent(t, f.inspect, 1)
	return ready
}
