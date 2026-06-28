package tnldruntime

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/certificateworker"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlapi"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/controltls"
	"github.com/tnldotdev/tnl/internal/dnscontroller"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/ingressapi"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/relay"
	"github.com/tnldotdev/tnl/internal/relayapi"
	"github.com/tnldotdev/tnl/internal/relaycertificateworker"
	"github.com/tnldotdev/tnl/internal/routebackend"
	"github.com/tnldotdev/tnl/internal/routeusageworker"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
	"github.com/tnldotdev/tnl/pkg/api/relayv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const (
	publisherLeaseDuration                = 45 * time.Second
	publisherConnectionCredentialDuration = 2 * time.Minute
	standaloneIngressID                   = "standalone-ingress"
)

var standaloneRelays = [...]struct {
	serviceID string
	relayID   string
}{
	{serviceID: "standalone-a", relayID: "standalone-relay-a"},
	{serviceID: "standalone-b", relayID: "standalone-relay-b"},
}

type daemon struct {
	database               *controlstate.Database
	metricsServer          *observability.Server
	controlServer          *http.Server
	controlListener        net.Listener
	privateControlServer   *http.Server
	privateControlListener net.Listener
	ingresses              []*ingressRuntime
	relays                 []*relayRuntime
	controlTLS             *tls.Config
	controlTLSManager      *controltls.Source
	serviceHTTP            *http.Client
	clusterSecret          string
	clusterSecrets         serviceapi.BearerSecrets
	relayClientTLS         *tls.Config
	cancel                 context.CancelFunc
	done                   chan error
	forwarded              sync.WaitGroup
}

type ingressRuntime struct {
	controller *ingress.Controller
	server     *ingress.Server
	forwarder  *ingress.Forwarder
	usage      *ingress.UsageReporter
	recovery   *ingress.RecoveryReporter
}

type relayRuntime struct {
	controller       *relay.Controller
	registry         *relay.Registry
	publisher        *relay.PublisherAcceptor
	transportTLS     *tls.Config
	tcpListener      net.Listener
	udpListener      *muxsession.QUICListener
	internalListener net.Listener
}

// Serve runs one configured tnld process until its context is canceled.
func Serve(ctx context.Context, cfg config.TNLD) error {
	return serveWithHTTPClients(
		ctx, cfg, &http.Client{Timeout: 30 * time.Second}, &http.Client{Timeout: 30 * time.Second},
	)
}

func serveWithHTTPClients(
	ctx context.Context,
	cfg config.TNLD,
	acmeHTTPClient, serviceHTTPClient *http.Client,
) (retErr error) {
	return serveWithRelayClientTLS(ctx, cfg, acmeHTTPClient, serviceHTTPClient, nil)
}

func serveWithRelayClientTLS(
	ctx context.Context,
	cfg config.TNLD,
	acmeHTTPClient, serviceHTTPClient *http.Client,
	relayClientTLS *tls.Config,
) (retErr error) {
	if acmeHTTPClient == nil || serviceHTTPClient == nil {
		return errors.New("ACME and service HTTP clients are required")
	}
	clusterSecret := cfg.ClusterSecret
	if cfg.Mode == config.TNLDModeStandalone {
		random := make([]byte, 32)
		if _, err := rand.Read(random); err != nil {
			return fmt.Errorf("generate standalone cluster secret: %w", err)
		}
		clusterSecret = base64.RawURLEncoding.EncodeToString(random)
	}
	clusterSecrets, err := serviceapi.NewBearerSecrets(clusterSecret, cfg.ClusterSecretPrevious)
	if err != nil {
		return err
	}
	lifetime, cancel := context.WithCancel(ctx)
	d := &daemon{
		serviceHTTP: serviceHTTPClient, clusterSecret: clusterSecret, clusterSecrets: clusterSecrets,
		relayClientTLS: relayClientTLS, cancel: cancel, done: make(chan error, 32),
	}
	defer func() { retErr = errors.Join(retErr, d.shutdown(cfg.DrainTimeout)) }()

	metrics := observability.New(string(cfg.Mode))

	if cfg.Mode.RunsControl() {
		database, err := controlstate.Open(ctx, cfg.DatabaseURL, cfg.StorageKey, cfg.StorageKeyPrevious)
		if err != nil {
			return err
		}
		d.database = database
		if err := database.CompleteStorageKeyRotation(ctx); err != nil {
			return fmt.Errorf("rotate stored secrets: %w", err)
		}
		if cfg.StorageKeyPrevious != "" {
			log.Printf("stored secrets re-encrypted with the current storage key")
		}
		var dnsProvider *dnscontroller.Route53Provider
		var dnsVerifier *dnscontroller.AuthoritativeVerifier
		var dnsChallenges *dnscontroller.ChallengeManager
		var relayDNSChallenges *dnscontroller.RelayChallengeManager
		dnsConfig := dnscontroller.Config{
			ManagedDomain: cfg.ManagedDomain(), ManagedZoneID: cfg.Route53ManagedZoneID,
			IngressIPv4Addresses: cfg.IngressIPv4Addresses, IngressIPv6Addresses: cfg.IngressIPv6Addresses,
		}
		if cfg.DNSProviderEnabled() {
			awsConfig, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Route53Region))
			if err != nil {
				return fmt.Errorf("load Route 53 configuration: %w", err)
			}
			dnsProvider, err = dnscontroller.NewRoute53Provider(route53.NewFromConfig(awsConfig))
			if err != nil {
				return err
			}
			dnsVerifier, err = dnscontroller.NewAuthoritativeVerifier(cfg.DNSServer)
			if err != nil {
				return err
			}
			if cfg.DNSAutomationEnabled() {
				dnsChallenges, err = dnscontroller.NewChallengeManager(database, dnsProvider, dnsVerifier, dnsConfig)
				if err != nil {
					return err
				}
			}
			if cfg.RelayCertificateAutomationEnabled() {
				relayDNSChallenges, err = dnscontroller.NewRelayChallengeManager(
					database, dnsProvider, dnsVerifier, cfg.ServerDomain, cfg.Route53ServerZoneID,
				)
				if err != nil {
					return err
				}
			}
		}
		if cfg.ACMEEnabled() {
			account, err := database.EnsureACMEAccount(ctx, cfg.ACMEDirectoryURL, cfg.ACMEEmail, time.Now())
			if err != nil {
				return err
			}
			account, err = certificateworker.ReconcileAccount(
				ctx, database, acmeHTTPClient, account, cfg.ACMEAcceptTerms, time.Now(),
			)
			if err != nil {
				return err
			}
			workerID, err := opaqueid.New("certificate_worker_")
			if err != nil {
				return fmt.Errorf("create certificate worker identity: %w", err)
			}
			worker, err := certificateworker.New(database, certificateworker.Config{
				WorkerID: workerID, Profile: cfg.ACMEProfile,
				HTTPClient: acmeHTTPClient, DNSChallenges: dnsChallenges,
			})
			if err != nil {
				return err
			}
			d.forward("run certificate worker", runAsync(func() error { return worker.Run(lifetime) }))
			if relayDNSChallenges != nil {
				relayWorkerID, err := opaqueid.New("relay_certificate_worker_")
				if err != nil {
					return fmt.Errorf("create relay certificate worker identity: %w", err)
				}
				relayWorker, err := relaycertificateworker.New(database, relaycertificateworker.Config{
					WorkerID: relayWorkerID, AccountID: account.ID, Profile: cfg.ACMEProfile,
					HTTPClient: acmeHTTPClient, DNSChallenges: relayDNSChallenges,
				})
				if err != nil {
					return err
				}
				d.forward("run relay certificate worker", runAsync(func() error { return relayWorker.Run(lifetime) }))
			}
			d.controlTLS, d.controlTLSManager, err = controlTLSConfig(controlTLSSettingsFrom(cfg), database, account, acmeHTTPClient)
			if err != nil {
				return err
			}
		}
		if cfg.RouteUsageURL != "" {
			workerID, err := opaqueid.New("route_usage_worker_")
			if err != nil {
				return fmt.Errorf("create route usage worker identity: %w", err)
			}
			worker, err := routeusageworker.New(database, routeusageworker.Config{
				WorkerID: workerID, Endpoint: cfg.RouteUsageURL, Token: cfg.RouteUsageToken,
			})
			if err != nil {
				return err
			}
			d.forward("run route usage worker", runAsync(func() error { return worker.Run(lifetime) }))
		}
		if cfg.DNSAutomationEnabled() {
			workerID, err := opaqueid.New("dns_worker_")
			if err != nil {
				return fmt.Errorf("create DNS worker identity: %w", err)
			}
			dnsConfig.WorkerID = workerID
			worker, err := dnscontroller.New(database, dnsProvider, dnsVerifier, dnsConfig)
			if err != nil {
				return err
			}
			d.forward("run DNS controller", runAsync(func() error { return worker.Run(lifetime) }))
		}
	}

	controlHandler := http.Handler(nil)
	if d.database != nil {
		controlHandler = controlapi.NewHandler(controlAPIConfigFrom(cfg, d.serviceHTTP), d.database, d.database.Readiness)
	}

	switch cfg.Mode {
	case config.TNLDModeRelay:
		settings := relayProcessSettingsFrom(cfg)
		settings.transportTLS, err = relayTLSConfig(cfg, nil)
		if err != nil {
			return err
		}
		if err := d.startRelay(lifetime, settings, metrics); err != nil {
			return err
		}
	case config.TNLDModeIngress:
		if err := d.startIngress(lifetime, ingressProcessSettingsFrom(cfg), metrics); err != nil {
			return err
		}
	case config.TNLDModeStandalone:
		settings := standaloneSettingsFrom(cfg)
		var automaticTLS *tls.Config
		if d.controlTLSManager != nil && !cfg.RelayCertificateAutomationEnabled() {
			automaticTLS = d.controlTLS
		}
		settings.relayTransportTLS, err = relayTLSConfig(cfg, automaticTLS)
		if err != nil {
			return err
		}
		if err := d.startStandalone(lifetime, settings, metrics, controlHandler); err != nil {
			return err
		}
	case config.TNLDModeControl:
		if err := d.startControl(cfg.ControlListen, controlHandler); err != nil {
			return err
		}
		if err := d.startPrivateControlAPIs(lifetime, privateControlSettingsFrom(cfg)); err != nil {
			return err
		}
	}
	if d.controlTLSManager != nil {
		d.forward("manage public control certificate", runAsync(func() error {
			return d.controlTLSManager.Run(lifetime)
		}))
	}
	if cfg.MetricsListen != "" {
		handler := observability.ProcessHandler(metrics.Handler(), func() bool {
			readyCtx, cancel := context.WithTimeout(lifetime, 2*time.Second)
			defer cancel()
			return d.ready(readyCtx, cfg.Mode, time.Now()) == nil
		})
		server, err := observability.Listen(cfg.MetricsListen, handler)
		if err != nil {
			return fmt.Errorf("listen for observability: %w", err)
		}
		d.metricsServer = server
		d.forward("serve observability", server.Done())
	}

	select {
	case <-ctx.Done():
		return nil
	case err := <-d.done:
		return err
	}
}

func controlAPIConfigFrom(cfg config.TNLD, httpClient *http.Client) controlapi.Config {
	return controlapi.Config{
		ManagedDeploymentDomain: cfg.ManagedDomain(),
		AuthorityEndpoint:       cfg.AuthorityOrigin(),
		LoginToken:              cfg.LoginToken,
		AccessTokenLifetime:     cfg.AccessTokenLifetime,
		RefreshTokenLifetime:    cfg.RefreshTokenLifetime,
		OIDCIssuer:              cfg.OIDCIssuer,
		OIDCClientID:            cfg.OIDCClientID,
		OIDCLoginFlow:           string(cfg.OIDCLoginFlow),
		OIDCScopes:              cfg.EffectiveOIDCScopes(),
		CertificateIssuance:     cfg.ACMEEnabled(),
		ACMEDirectoryURL:        cfg.ACMEDirectoryURL,
		ServerDomain:            cfg.ServerDomain,
		HostedSecret:            cfg.HostedSecret,
		HostedSecretPrevious:    cfg.HostedSecretPrevious,
		HTTPClient:              httpClient,
		DNSAutomation:           cfg.DNSAutomationEnabled(),
	}
}

func (d *daemon) ready(ctx context.Context, mode config.TNLDMode, now time.Time) error {
	if mode.RunsControl() {
		if d.database == nil || d.controlServer == nil || d.controlListener == nil {
			return errors.New("control listeners are not ready")
		}
		if mode == config.TNLDModeControl && (d.privateControlServer == nil || d.privateControlListener == nil) {
			return errors.New("private control listener is not ready")
		}
		if err := d.database.Readiness(ctx); err != nil {
			return err
		}
		if d.controlTLSManager != nil && !d.controlTLSManager.Ready(now) {
			return errors.New("public control certificate is not ready")
		}
	}
	if mode.RunsIngress() {
		if len(d.ingresses) != 1 {
			return errors.New("ingress runtime is not ready")
		}
		runtime := d.ingresses[0]
		if runtime.controller == nil || !runtime.controller.Ready(now) || runtime.server == nil || !runtime.server.Ready() {
			return errors.New("ingress lease, routing table, certificate, or listener is not ready")
		}
	}
	if mode.RunsRelay() {
		expected := 1
		if mode == config.TNLDModeStandalone {
			expected = len(standaloneRelays)
		}
		if len(d.relays) != expected {
			return errors.New("relay runtimes are not ready")
		}
		for _, runtime := range d.relays {
			if runtime.controller == nil || !runtime.controller.Ready(now) || runtime.registry == nil || runtime.internalListener == nil {
				return errors.New("relay lease, certificate, or internal listener is not ready")
			}
		}
		physical := d.relays[0]
		if physical.tcpListener == nil || physical.udpListener == nil {
			return errors.New("relay publisher listeners are not ready")
		}
	}
	return nil
}

type ingressProcessSettings struct {
	controlEndpoint string
	clusterSecret   string
	ingressID       string
	listen          string
	runtime         ingressSettings
}

func ingressProcessSettingsFrom(cfg config.TNLD) ingressProcessSettings {
	return ingressProcessSettings{
		controlEndpoint: cfg.PrivateControlEndpoint(), clusterSecret: cfg.ClusterSecret,
		ingressID: cfg.IngressID, listen: cfg.IngressListen, runtime: ingressSettingsFrom(cfg),
	}
}

func (d *daemon) startIngress(ctx context.Context, settings ingressProcessSettings, metrics *observability.Metrics) error {
	privateClient, err := newIngressControlClient(settings.controlEndpoint, settings.clusterSecret, d.serviceHTTP, "")
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", settings.listen)
	if err != nil {
		return fmt.Errorf("listen for public ingress: %w", err)
	}
	if err := d.startIngressRuntime(ctx, settings.runtime, metrics, ingressRuntimeConfig{
		client: privateClient, ingressID: settings.ingressID, listener: listener, clusterSecret: settings.clusterSecret,
	}); err != nil {
		_ = listener.Close()
		return err
	}
	return nil
}

type ingressRuntimeConfig struct {
	client        ingress.ControlClient
	ingressID     string
	listener      net.Listener
	clusterSecret string
	configure     func(*ingress.Config)
}

type ingressSettings struct {
	publicConnectionLimit int64
	routeConnectionLimit  int64
	requireProxyHeader    bool
	leaseRenewalInterval  time.Duration
	controlRetryInterval  time.Duration
	routingTableWait      time.Duration
}

func ingressSettingsFrom(cfg config.TNLD) ingressSettings {
	return ingressSettings{
		publicConnectionLimit: cfg.PublicConnectionLimit,
		routeConnectionLimit:  cfg.RouteConnectionLimit,
		requireProxyHeader:    cfg.RequireProxyHeader,
		leaseRenewalInterval:  cfg.LeaseRenewalInterval,
		controlRetryInterval:  cfg.ControlRetryInterval,
		routingTableWait:      cfg.RoutingTableWait,
	}
}

func (d *daemon) startIngressRuntime(
	ctx context.Context,
	settings ingressSettings,
	metrics *observability.Metrics,
	runtimeConfig ingressRuntimeConfig,
) error {
	runtime := &ingressRuntime{}
	runID, err := opaqueid.New("ingress_run_")
	if err != nil {
		return fmt.Errorf("create ingress process run ID: %w", err)
	}
	routingTable := new(ingress.RoutingTable)
	var publicServer *ingress.Server
	controller, err := ingress.NewController(ingress.ControllerConfig{
		Client: runtimeConfig.client, RoutingTable: routingTable,
		Registration: ingressv1.IngressRegistration{
			IngressId: runtimeConfig.ingressID, IngressRunId: runID, ProtocolVersion: tunnelv1.Version,
			ConnectionCapacity: settings.publicConnectionLimit,
		},
		RenewalInterval: settings.leaseRenewalInterval, RetryInterval: settings.controlRetryInterval,
		RoutingWait: settings.routingTableWait,
		Load: func() int64 {
			if publicServer == nil {
				return 0
			}
			return publicServer.Load()
		},
	})
	if err != nil {
		return err
	}
	runtime.controller = controller
	usage, err := ingress.NewUsageReporter(controller, 0, func(err error) { log.Printf("ingress usage: %v", err) })
	if err != nil {
		return err
	}
	runtime.usage = usage
	recovery, err := ingress.NewRecoveryReporter(ctx, controller, settings.controlRetryInterval, func(err error) {
		log.Printf("ingress recovery: %v", err)
	})
	if err != nil {
		return err
	}
	runtime.recovery = recovery
	forwardingTLS := d.relayClientTLS
	if forwardingTLS == nil {
		forwardingTLS = &tls.Config{MinVersion: tls.VersionTLS13}
	} else {
		forwardingTLS = forwardingTLS.Clone()
		forwardingTLS.MinVersion = tls.VersionTLS13
	}
	forwarder, err := ingress.NewForwarder(ingress.ForwarderConfig{
		TLSConfig: forwardingTLS, ClusterSecret: runtimeConfig.clusterSecret,
	})
	if err != nil {
		return err
	}
	runtime.forwarder = forwarder
	publicCapacity, err := runtimeCapacity("public connection", settings.publicConnectionLimit)
	if err != nil {
		return err
	}
	routeCapacity, err := runtimeCapacity("route connection", settings.routeConnectionLimit)
	if err != nil {
		return err
	}
	ingressConfig := ingress.Config{
		Lookup: func(hostname string) (ingress.Route, bool) {
			entry, ok := controller.Lookup(hostname, time.Now())
			if !ok {
				return ingress.Route{}, false
			}
			route, err := forwarder.Route(entry)
			if err != nil {
				log.Printf("ingress route %q: %v", hostname, err)
				return ingress.Route{}, false
			}
			return route, true
		},
		LookupChallenge: func(hostname string) ([]routebackend.Backend, bool) {
			entry, ok := controller.LookupChallenge(hostname, time.Now())
			if !ok {
				return nil, false
			}
			backends, err := forwarder.Backends(entry)
			if err != nil {
				log.Printf("ingress challenge route %q: %v", hostname, err)
				return nil, false
			}
			return backends, true
		},
		RequireProxyHeader: settings.requireProxyHeader, MaxConnections: publicCapacity,
		MaxRouteConnections: routeCapacity, Metrics: metrics,
		OpenUsage:       usage.Open,
		ObserveRecovery: recovery.Observe,
		OnError:         func(err error) { log.Printf("ingress connection: %v", err) },
	}
	if runtimeConfig.configure != nil {
		runtimeConfig.configure(&ingressConfig)
	}
	server, err := ingress.New(runtimeConfig.listener, ingressConfig)
	if err != nil {
		_ = forwarder.Close()
		return err
	}
	runtime.server = server
	publicServer = server
	d.ingresses = append(d.ingresses, runtime)
	d.forward("run ingress control", runAsync(func() error { return controller.Run(ctx) }))
	d.forward("report ingress usage", runAsync(func() error { return usage.Run(ctx) }))
	d.forward("serve public ingress", runAsync(server.Serve))
	log.Printf("public ingress listening on %s", runtimeConfig.listener.Addr())
	return nil
}

type relayProcessSettings struct {
	controlEndpoint        string
	clusterSecret          string
	relayServiceID         string
	relayID                string
	relayAddress           string
	tlsServerName          string
	transportTLS           *tls.Config
	internalListen         string
	internalAddress        string
	tcpListen              string
	udpListen              string
	quicIdleTimeout        time.Duration
	quicMaxIncomingStreams int64
	runtime                relaySettings
}

func relayProcessSettingsFrom(cfg config.TNLD) relayProcessSettings {
	tlsServerName, _, _ := net.SplitHostPort(cfg.RelayAddress)
	return relayProcessSettings{
		controlEndpoint: cfg.PrivateControlEndpoint(), clusterSecret: cfg.ClusterSecret,
		relayServiceID: cfg.RelayServiceID, relayID: cfg.RelayID,
		relayAddress: cfg.RelayAddress, tlsServerName: tlsServerName,
		internalListen:         cfg.InternalRelayListen,
		internalAddress:        cfg.InternalRelayAddress,
		tcpListen:              cfg.RelayTCPListen,
		udpListen:              cfg.RelayUDPListen,
		quicIdleTimeout:        cfg.QUICIdleTimeout,
		quicMaxIncomingStreams: cfg.QUICMaxIncomingStreams,
		runtime:                relaySettingsFrom(cfg),
	}
}

func (d *daemon) startRelay(ctx context.Context, settings relayProcessSettings, metrics *observability.Metrics) error {
	privateClient, err := newRelayControlClient(settings.controlEndpoint, settings.clusterSecret, d.serviceHTTP, "")
	if err != nil {
		return err
	}
	internalListener, err := net.Listen("tcp", settings.internalListen)
	if err != nil {
		return fmt.Errorf("listen for internal forwarding: %w", err)
	}
	transportTLS := settings.transportTLS
	var certificateChanged func(relayv1.RelayServiceCertificate) error
	if transportTLS == nil {
		certificateSource, err := newRelayCertificateSource(settings.relayServiceID, settings.tlsServerName)
		if err != nil {
			_ = internalListener.Close()
			return err
		}
		transportTLS = certificateSource.TLSConfig()
		certificateChanged = certificateSource.Install
	}
	runtime, err := d.startRelayRuntime(ctx, settings.runtime, relayRuntimeConfig{
		client: privateClient, relayServiceID: settings.relayServiceID, relayID: settings.relayID,
		relayAddress: settings.relayAddress, tlsServerName: settings.tlsServerName,
		transportTLS: transportTLS, certificateChanged: certificateChanged, clusterSecrets: d.clusterSecrets,
		internalAddress: settings.internalAddress, internalListener: internalListener, metrics: metrics,
	})
	if err != nil {
		_ = internalListener.Close()
		return err
	}
	tcpListener, err := net.Listen("tcp", settings.tcpListen)
	if err != nil {
		return fmt.Errorf("listen for TLS/TCP publisher connections: %w", err)
	}
	runtime.tcpListener = tcpListener
	udpListener, err := muxsession.ListenQUIC(settings.udpListen, runtime.transportTLS, muxsession.QUICConfig{Config: &quic.Config{
		MaxIdleTimeout: settings.quicIdleTimeout, MaxIncomingStreams: settings.quicMaxIncomingStreams,
	}})
	if err != nil {
		return fmt.Errorf("listen for QUIC publisher connections: %w", err)
	}
	runtime.udpListener = udpListener
	maxStreams, err := runtimeCapacity("publisher connection stream", settings.quicMaxIncomingStreams)
	if err != nil {
		return err
	}
	d.forward("serve TLS/TCP publisher connections", serveTLSYamuxSessions(
		ctx, tcpListener, runtime.transportTLS,
		muxsession.TLSYamuxConfig{MaxIncomingStreams: maxStreams}, runtime.publisher.Accept,
	))
	d.forward("serve QUIC publisher connections", serveQUICSessions(ctx, udpListener, runtime.publisher.Accept))
	log.Printf("relay publisher TCP listening on %s", tcpListener.Addr())
	log.Printf("relay publisher UDP listening on %s", udpListener.Addr())
	return nil
}

type relayRuntimeConfig struct {
	client             relay.ControlClient
	relayServiceID     string
	relayID            string
	relayAddress       string
	tlsServerName      string
	transportTLS       *tls.Config
	certificateChanged func(relayv1.RelayServiceCertificate) error
	clusterSecrets     serviceapi.BearerSecrets
	internalAddress    string
	internalListener   net.Listener
	metrics            *observability.Metrics
}

type relaySettings struct {
	publisherConnectionLimit int64
	streamCapacity           int64
	leaseRenewalInterval     time.Duration
	controlRetryInterval     time.Duration
}

func relaySettingsFrom(cfg config.TNLD) relaySettings {
	return relaySettings{
		publisherConnectionLimit: cfg.PublisherConnectionLimit,
		streamCapacity:           cfg.RelayStreamCapacity,
		leaseRenewalInterval:     cfg.LeaseRenewalInterval,
		controlRetryInterval:     cfg.ControlRetryInterval,
	}
}

func (d *daemon) startRelayRuntime(
	ctx context.Context,
	settings relaySettings,
	runtimeConfig relayRuntimeConfig,
) (*relayRuntime, error) {
	if runtimeConfig.transportTLS == nil {
		return nil, errors.New("relay TLS certificate is not configured")
	}
	runtime := &relayRuntime{internalListener: runtimeConfig.internalListener}
	if runtimeConfig.metrics != nil {
		runtimeConfig.metrics.AddRelayLeases("active", 0)
		runtimeConfig.metrics.AddRelayLeases("draining", 0)
		runtimeConfig.metrics.AddPublisherConnections("ready", 0)
	}
	runID, err := opaqueid.New("relay_run_")
	if err != nil {
		return nil, fmt.Errorf("create relay process run ID: %w", err)
	}
	registry := relay.NewRegistry()
	runtime.registry = registry
	controller, err := relay.NewController(relay.ControllerConfig{
		Client: runtimeConfig.client,
		Registration: relayv1.RelayRegistration{
			RelayServiceId: runtimeConfig.relayServiceID, RelayId: runtimeConfig.relayID, RelayRunId: runID,
			ProtocolVersion: tunnelv1.Version, RelayAddress: runtimeConfig.relayAddress,
			TlsServerName: runtimeConfig.tlsServerName, InternalRelayAddress: runtimeConfig.internalAddress,
			InternalNetworks: []string{}, ConnectionCapacity: settings.publisherConnectionLimit,
			StreamCapacity: settings.streamCapacity,
		},
		RenewalInterval: settings.leaseRenewalInterval, RetryInterval: settings.controlRetryInterval,
		CertificateChanged: runtimeConfig.certificateChanged,
		Load:               registry.Load, LeaseChanged: func(previous, current relayv1.RelayLease) {
			previousState, currentState := relayLeaseMetricState(previous), relayLeaseMetricState(current)
			if previousState == currentState || runtimeConfig.metrics == nil {
				return
			}
			if previousState != "" {
				runtimeConfig.metrics.AddRelayLeases(previousState, -1)
			}
			if currentState != "" {
				runtimeConfig.metrics.AddRelayLeases(currentState, 1)
			}
		},
	})
	if err != nil {
		return nil, err
	}
	runtime.controller = controller
	publisherAcceptor, err := relay.NewPublisherAcceptor(relay.PublisherAcceptorConfig{
		Control: controller, Registry: registry,
		ReadyConnectionsDelta: func(delta int) {
			if runtimeConfig.metrics != nil {
				runtimeConfig.metrics.AddPublisherConnections("ready", delta)
			}
		},
		Report: func(err error) { log.Printf("relay publisher: %v", err) },
	})
	if err != nil {
		return nil, err
	}
	runtime.publisher = publisherAcceptor
	streamCapacity, err := runtimeCapacity("relay stream", settings.streamCapacity)
	if err != nil {
		return nil, err
	}
	forwardingAcceptor, err := relay.NewForwardingAcceptor(relay.ForwardingAcceptorConfig{
		Registry: registry, ClusterSecrets: runtimeConfig.clusterSecrets, StreamCapacity: streamCapacity,
		Report: func(err error) { log.Printf("relay forwarding: %v", err) },
	})
	if err != nil {
		return nil, err
	}
	runtime.transportTLS = runtimeConfig.transportTLS
	d.relays = append(d.relays, runtime)

	d.forward("run relay control", runAsync(func() error { return controller.Run(ctx) }))
	d.forward("serve internal forwarding", serveTLSYamuxSessions(
		ctx, runtimeConfig.internalListener, runtimeConfig.transportTLS,
		muxsession.TLSYamuxConfig{MaxIncomingStreams: streamCapacity}, forwardingAcceptor.Accept,
	))
	log.Printf("relay internal forwarding listening on %s", runtimeConfig.internalListener.Addr())
	return runtime, nil
}

type standaloneSettings struct {
	publicListen           string
	relayUDPListen         string
	quicIdleTimeout        time.Duration
	quicMaxIncomingStreams int64
	serverHostname         string
	relayHostname          string
	relayTransportTLS      *tls.Config
	ingressLeaseDuration   time.Duration
	relayLeaseDuration     time.Duration
	ingress                ingressSettings
	relay                  relaySettings
}

func standaloneSettingsFrom(cfg config.TNLD) standaloneSettings {
	return standaloneSettings{
		publicListen:           cfg.IngressListen,
		relayUDPListen:         cfg.RelayUDPListen,
		quicIdleTimeout:        cfg.QUICIdleTimeout,
		quicMaxIncomingStreams: cfg.QUICMaxIncomingStreams,
		serverHostname:         cfg.ServerHostname(),
		relayHostname:          cfg.StandaloneRelayHostname(),
		ingressLeaseDuration:   cfg.IngressLeaseDuration,
		relayLeaseDuration:     cfg.RelayLeaseDuration,
		ingress:                ingressSettingsFrom(cfg),
		relay:                  relaySettingsFrom(cfg),
	}
}

func (d *daemon) startStandalone(
	ctx context.Context,
	settings standaloneSettings,
	metrics *observability.Metrics,
	controlHandler http.Handler,
) error {
	publicListener, err := net.Listen("tcp", settings.publicListen)
	if err != nil {
		return fmt.Errorf("listen for standalone public traffic: %w", err)
	}
	publicOwned := false
	defer func() {
		if !publicOwned {
			_ = publicListener.Close()
		}
	}()

	controlListener := newConnectionListener(publicListener.Addr())
	relayListener := newConnectionListener(publicListener.Addr())
	d.controlListener = controlListener
	d.controlServer = controlHTTPServer(controlHandler, d.controlTLS)
	d.forward("serve control API", serveTLS(d.controlServer, controlListener))

	transportTLS := settings.relayTransportTLS
	var certificateChanged func(relayv1.RelayServiceCertificate) error
	if transportTLS == nil {
		serviceIDs := make([]string, len(standaloneRelays))
		for index, identity := range standaloneRelays {
			serviceIDs[index] = identity.serviceID
		}
		certificateSource, err := newSharedRelayCertificateSource(serviceIDs, settings.relayHostname)
		if err != nil {
			return err
		}
		transportTLS = certificateSource.TLSConfig()
		certificateChanged = certificateSource.Install
	}
	targets := make(map[string]*relayRuntime, len(standaloneRelays))
	relayClient, err := relayapi.NewDirectClient(d.database, settings.relayLeaseDuration)
	if err != nil {
		return err
	}
	for _, identity := range standaloneRelays {
		internalListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("listen for standalone internal forwarding: %w", err)
		}
		runtime, err := d.startRelayRuntime(ctx, settings.relay, relayRuntimeConfig{
			client: relayClient, relayServiceID: identity.serviceID, relayID: identity.relayID,
			relayAddress: net.JoinHostPort(settings.relayHostname, "443"), tlsServerName: settings.relayHostname,
			transportTLS: transportTLS, certificateChanged: certificateChanged, clusterSecrets: d.clusterSecrets,
			internalAddress: internalListener.Addr().String(), internalListener: internalListener, metrics: metrics,
		})
		if err != nil {
			_ = internalListener.Close()
			return err
		}
		targets[identity.serviceID] = runtime
	}
	publisher, err := relay.NewPublisherAcceptor(relay.PublisherAcceptorConfig{
		Select: func(relayServiceID string) (relay.PublisherConnectionController, *relay.Registry, bool) {
			runtime, ok := targets[relayServiceID]
			if !ok {
				return nil, nil, false
			}
			return runtime.controller, runtime.registry, true
		},
		ReadyConnectionsDelta: func(delta int) { metrics.AddPublisherConnections("ready", delta) },
		Report:                func(err error) { log.Printf("relay publisher: %v", err) },
	})
	if err != nil {
		return err
	}
	maxStreams, err := runtimeCapacity("publisher connection stream", settings.quicMaxIncomingStreams)
	if err != nil {
		return err
	}
	udpListener, err := muxsession.ListenQUIC(settings.relayUDPListen, transportTLS, muxsession.QUICConfig{Config: &quic.Config{
		MaxIdleTimeout: settings.quicIdleTimeout, MaxIncomingStreams: settings.quicMaxIncomingStreams,
	}})
	if err != nil {
		return fmt.Errorf("listen for standalone QUIC publisher connections: %w", err)
	}
	d.relays[0].tcpListener = relayListener
	d.relays[0].udpListener = udpListener
	d.forward("serve TLS/TCP publisher connections", serveTLSYamuxSessions(
		ctx, relayListener, transportTLS,
		muxsession.TLSYamuxConfig{MaxIncomingStreams: maxStreams}, publisher.Accept,
	))
	d.forward("serve QUIC publisher connections", serveQUICSessions(ctx, udpListener, publisher.Accept))

	ingressClient, err := ingressapi.NewDirectClient(ingressapi.DirectConfig{
		Store: d.database, LeaseDuration: settings.ingressLeaseDuration,
	})
	if err != nil {
		return err
	}
	if err := d.startIngressRuntime(ctx, settings.ingress, metrics, ingressRuntimeConfig{
		client: ingressClient, ingressID: standaloneIngressID, listener: publicListener,
		clusterSecret: d.clusterSecret,
		configure: func(ingressConfig *ingress.Config) {
			ingressConfig.ServerHostname = settings.serverHostname
			ingressConfig.HandleControl = controlListener.Enqueue
			ingressConfig.RelayHostname = settings.relayHostname
			ingressConfig.HandleRelay = relayListener.Enqueue
			ingressConfig.HandleRelayChallenge = controlListener.Enqueue
		},
	}); err != nil {
		return err
	}
	publicOwned = true
	log.Printf("control API listening on %s for %s", publicListener.Addr(), settings.serverHostname)
	log.Printf("relay publisher TCP listening on %s for %s", publicListener.Addr(), settings.relayHostname)
	log.Printf("relay publisher UDP listening on %s", udpListener.Addr())
	return nil
}

func relayLeaseMetricState(lease relayv1.RelayLease) string {
	if lease.RelayLeaseRevision == 0 {
		return ""
	}
	if lease.Draining {
		return "draining"
	}
	return "active"
}

func newRelayControlClient(endpoint, clusterSecret string, base *http.Client, dialAddress string) (*relayv1.ClientWithResponses, error) {
	client, err := newPrivateServiceHTTPClient(base, clusterSecret, dialAddress)
	if err != nil {
		return nil, err
	}
	return relayv1.NewClientWithResponses(endpoint, relayv1.WithHTTPClient(client))
}

func newIngressControlClient(endpoint, clusterSecret string, base *http.Client, dialAddress string) (*ingressv1.ClientWithResponses, error) {
	client, err := newPrivateServiceHTTPClient(base, clusterSecret, dialAddress)
	if err != nil {
		return nil, err
	}
	return ingressv1.NewClientWithResponses(endpoint, ingressv1.WithHTTPClient(client))
}

func newPrivateServiceHTTPClient(base *http.Client, clusterSecret, dialAddress string) (*http.Client, error) {
	if base == nil || clusterSecret == "" {
		return nil, errors.New("private service HTTP client and cluster secret are required")
	}
	baseTransport := base.Transport
	if baseTransport == nil {
		baseTransport = http.DefaultTransport
	}
	if dialAddress != "" {
		configured, ok := baseTransport.(*http.Transport)
		if !ok {
			return nil, errors.New("private service dial override requires an HTTP transport")
		}
		transport := configured.Clone()
		dialer := new(net.Dialer)
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, dialAddress)
		}
		baseTransport = transport
	}
	client := *base
	client.Transport = serviceBearerRoundTripper{secret: clusterSecret, base: baseTransport}
	client.Timeout = 30 * time.Second
	return &client, nil
}

type serviceBearerRoundTripper struct {
	secret string
	base   http.RoundTripper
}

func (t serviceBearerRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	copy.Header = request.Header.Clone()
	copy.Header.Set("Authorization", "Bearer "+t.secret)
	return t.base.RoundTrip(copy)
}

func runtimeCapacity(name string, value int64) (int, error) {
	converted := int(value)
	if value <= 0 || int64(converted) != value {
		return 0, fmt.Errorf("%s capacity is out of range", name)
	}
	return converted, nil
}

type sessionAcceptFunc func(context.Context, muxsession.Session) error

func serveTLSYamuxSessions(
	ctx context.Context,
	listener net.Listener,
	tlsConfig *tls.Config,
	transportConfig muxsession.TLSYamuxConfig,
	accept sessionAcceptFunc,
) <-chan error {
	return runAsync(func() error {
		var active sync.WaitGroup
		defer active.Wait()
		for {
			connection, err := listener.Accept()
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return nil
				}
				return err
			}
			active.Go(func() {
				transport, err := muxsession.AcceptTLSYamux(ctx, connection, tlsConfig, transportConfig)
				if err == nil {
					err = accept(ctx, transport)
				}
				if err != nil && ctx.Err() == nil {
					log.Printf("relay TLS/TCP session: %v", err)
				}
			})
		}
	})
}

func serveQUICSessions(
	ctx context.Context,
	listener *muxsession.QUICListener,
	accept sessionAcceptFunc,
) <-chan error {
	return runAsync(func() error {
		var active sync.WaitGroup
		defer active.Wait()
		for {
			transport, err := listener.Accept(ctx)
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || errors.Is(err, muxsession.ErrClosed) {
					return nil
				}
				return err
			}
			active.Go(func() {
				if err := accept(ctx, transport); err != nil && ctx.Err() == nil {
					log.Printf("relay QUIC session: %v", err)
				}
			})
		}
	})
}

func (d *daemon) startControl(listenAddress string, handler http.Handler) error {
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return fmt.Errorf("listen for control API: %w", err)
	}
	d.controlListener = listener
	d.controlServer = controlHTTPServer(handler, d.controlTLS)
	d.forward("serve control API", serveTLS(d.controlServer, listener))
	log.Printf("control API listening on %s", listener.Addr())
	return nil
}

type privateControlSettings struct {
	ingressLeaseDuration time.Duration
	relayLeaseDuration   time.Duration
	listen               string
}

func privateControlSettingsFrom(cfg config.TNLD) privateControlSettings {
	return privateControlSettings{
		ingressLeaseDuration: cfg.IngressLeaseDuration,
		relayLeaseDuration:   cfg.RelayLeaseDuration,
		listen:               cfg.PrivateControlListen,
	}
}

func (d *daemon) startPrivateControlAPIs(_ context.Context, settings privateControlSettings) error {
	ingressHandler, err := ingressapi.NewHandler(ingressapi.Config{
		Store: d.database, ClusterSecrets: d.clusterSecrets,
		LeaseDuration: settings.ingressLeaseDuration,
	})
	if err != nil {
		return err
	}
	relayHandler, err := relayapi.NewHandler(relayapi.Config{
		Store: d.database, ClusterSecrets: d.clusterSecrets,
		LeaseDuration: settings.relayLeaseDuration,
	})
	if err != nil {
		return err
	}
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch {
		case strings.HasPrefix(request.URL.Path, "/internal/v1/ingresses/"):
			ingressHandler.ServeHTTP(response, request)
		case strings.HasPrefix(request.URL.Path, "/internal/v1/relays/"),
			strings.HasPrefix(request.URL.Path, "/internal/v1/relay-services/"),
			strings.HasPrefix(request.URL.Path, "/internal/v1/publisher-connections/"):
			relayHandler.ServeHTTP(response, request)
		default:
			serviceapi.WriteProblem(response, http.StatusNotFound, "not_found", "Private control endpoint not found")
		}
	})
	listener, err := net.Listen("tcp", settings.listen)
	if err != nil {
		return fmt.Errorf("listen for private control API: %w", err)
	}
	d.privateControlListener = listener
	d.privateControlServer = controlHTTPServer(handler, d.controlTLS)
	d.forward("serve private control API", serveTLS(d.privateControlServer, listener))
	log.Printf("private control API listening on %s", listener.Addr())
	return nil
}

type controlTLSSettings struct {
	certificateFile     string
	privateKeyFile      string
	directoryURL        string
	hostname            string
	additionalHostnames []string
	email               string
	acceptTerms         bool
}

func controlTLSSettingsFrom(cfg config.TNLD) controlTLSSettings {
	additionalHostnames := []string(nil)
	if cfg.Mode == config.TNLDModeStandalone && cfg.ControlTLSCertificateFile == "" &&
		cfg.RelayTLSCertificateFile == "" && !cfg.RelayCertificateAutomationEnabled() {
		additionalHostnames = []string{cfg.StandaloneRelayHostname()}
	}
	return controlTLSSettings{
		certificateFile:     cfg.ControlTLSCertificateFile,
		privateKeyFile:      cfg.ControlTLSPrivateKeyFile,
		directoryURL:        cfg.ACMEDirectoryURL,
		hostname:            cfg.ServerHostname(),
		additionalHostnames: additionalHostnames,
		email:               cfg.ACMEEmail,
		acceptTerms:         cfg.ACMEAcceptTerms,
	}
}

func controlTLSConfig(
	settings controlTLSSettings,
	database *controlstate.Database,
	account controlstate.ACMEAccount,
	acmeHTTPClient *http.Client,
) (*tls.Config, *controltls.Source, error) {
	if settings.certificateFile != "" {
		config, err := staticServerTLS(settings.certificateFile, settings.privateKeyFile)
		return config, nil, err
	}
	cache, err := database.ControlTLSCache(settings.directoryURL)
	if err != nil {
		return nil, nil, err
	}
	source, err := controltls.New(controltls.Config{
		Hostname: settings.hostname, Cache: cache, DirectoryURL: settings.directoryURL,
		AdditionalHostnames: settings.additionalHostnames,
		Email:               settings.email, AcceptTerms: settings.acceptTerms, AccountKey: account.AccountKeyDER,
		HTTPClient: acmeHTTPClient, RunLeader: database.RunControlTLSLeader,
		Report: func(err error) { log.Printf("public control certificate: %v", err) },
	})
	if err != nil {
		return nil, nil, err
	}
	return source.TLSConfig(), source, nil
}

func staticServerTLS(certificateFile, privateKeyFile string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(certificateFile, privateKeyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}, nil
}

func relayTLSConfig(cfg config.TNLD, fallback *tls.Config) (*tls.Config, error) {
	if cfg.RelayTLSCertificateFile != "" {
		return staticServerTLS(cfg.RelayTLSCertificateFile, cfg.RelayTLSPrivateKeyFile)
	}
	if fallback == nil {
		return nil, nil
	}
	return fallback.Clone(), nil
}

func controlHTTPServer(handler http.Handler, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Handler: handler, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
	}
}

func serveTLS(server *http.Server, listener net.Listener) <-chan error {
	return runAsync(func() error {
		err := server.ServeTLS(listener, "", "")
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	})
}

func (d *daemon) shutdown(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var result error
	deadline := time.Now().Add(timeout)
	for _, runtime := range d.ingresses {
		if runtime.controller != nil && runtime.controller.Ready(time.Now()) {
			result = errors.Join(result, runtime.controller.Drain(ctx, deadline))
		}
		if runtime.server != nil {
			result = errors.Join(result, runtime.server.Drain(ctx))
		}
		if runtime.usage != nil {
			result = errors.Join(result, runtime.usage.Close(ctx))
		}
		if runtime.recovery != nil {
			result = errors.Join(result, runtime.recovery.Close(ctx))
		}
	}
	for _, runtime := range d.relays {
		if runtime.controller != nil && runtime.controller.Ready(time.Now()) {
			result = errors.Join(result, runtime.controller.Drain(ctx, deadline))
		}
		for _, listener := range []net.Listener{runtime.tcpListener, runtime.internalListener} {
			if listener != nil {
				result = errors.Join(result, closeNetworkListener(listener))
			}
		}
		if runtime.udpListener != nil {
			result = errors.Join(result, closeNetworkListener(runtime.udpListener))
		}
		if runtime.registry != nil {
			result = errors.Join(result, runtime.registry.Drain(ctx))
		}
	}
	if d.cancel != nil {
		d.cancel()
	}
	for _, runtime := range d.ingresses {
		if runtime.forwarder != nil {
			result = errors.Join(result, runtime.forwarder.Close())
		}
	}
	for _, runtime := range d.relays {
		if runtime.registry != nil {
			result = errors.Join(result, runtime.registry.Close())
		}
	}
	for _, server := range []struct {
		name   string
		server *http.Server
	}{
		{name: "control API", server: d.controlServer},
		{name: "private control API", server: d.privateControlServer},
	} {
		if server.server != nil {
			if err := server.server.Shutdown(ctx); err != nil {
				result = errors.Join(
					result,
					fmt.Errorf("shut down %s: %w", server.name, errors.Join(err, server.server.Close())),
				)
			}
		}
	}
	for _, listener := range []net.Listener{d.controlListener, d.privateControlListener} {
		if listener != nil {
			result = errors.Join(result, closeNetworkListener(listener))
		}
	}
	if d.metricsServer != nil {
		if err := d.metricsServer.Shutdown(ctx); err != nil {
			result = errors.Join(result, fmt.Errorf("shut down observability: %w", err))
		}
	}
	forwardedDone := make(chan struct{})
	go func() {
		d.forwarded.Wait()
		close(forwardedDone)
	}()
	select {
	case <-forwardedDone:
	case <-ctx.Done():
		result = errors.Join(result, fmt.Errorf("wait for process components: %w", ctx.Err()))
	}
	if d.database != nil {
		d.database.Close()
	}
	return result
}

func closeNetworkListener(listener io.Closer) error {
	err := listener.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (d *daemon) forward(name string, source <-chan error) {
	d.forwarded.Add(1)
	go func() {
		defer d.forwarded.Done()
		err := <-source
		if err != nil {
			err = fmt.Errorf("%s: %w", name, err)
		}
		d.done <- err
	}()
}

type connectionListener struct {
	address     net.Addr
	connections chan net.Conn
	closed      chan struct{}
	once        sync.Once
}

func newConnectionListener(address net.Addr) *connectionListener {
	return &connectionListener{address: address, connections: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *connectionListener) Accept() (net.Conn, error) {
	select {
	case connection := <-l.connections:
		return connection, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *connectionListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *connectionListener) Addr() net.Addr { return l.address }

func (l *connectionListener) Enqueue(connection net.Conn) bool {
	select {
	case l.connections <- connection:
		return true
	case <-l.closed:
		return false
	}
}

func runAsync(run func() error) <-chan error {
	done := make(chan error, 1)
	go func() {
		done <- run()
		close(done)
	}()
	return done
}
