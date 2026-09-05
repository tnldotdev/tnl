package tnldruntime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/certificateworker"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlapi"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/controltls"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/ingressapi"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/relay"
	"github.com/tnldotdev/tnl/internal/relayapi"
	"github.com/tnldotdev/tnl/internal/routebackend"
	"github.com/tnldotdev/tnl/internal/routeusageworker"
	"github.com/tnldotdev/tnl/internal/serviceenrollment"
	"github.com/tnldotdev/tnl/internal/servicepki"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
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
	ingressControlServer   *http.Server
	ingressControlListener net.Listener
	relayControlServer     *http.Server
	relayControlListener   net.Listener
	ingresses              []*ingressRuntime
	relays                 []*relayRuntime
	controlTLS             *tls.Config
	controlTLSManager      *controltls.Source
	serviceEnrollmentHTTP  *http.Client
	cancel                 context.CancelFunc
	done                   chan error
}

type ingressRuntime struct {
	enrollment *serviceenrollment.State
	controller *ingress.Controller
	server     *ingress.Server
	forwarder  *ingress.Forwarder
	usage      *ingress.UsageReporter
	recovery   *ingress.RecoveryReporter
}

type relayRuntime struct {
	enrollment       *serviceenrollment.State
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

func serveWithACMEHTTPClient(ctx context.Context, cfg config.TNLD, acmeHTTPClient *http.Client) (retErr error) {
	return serveWithHTTPClients(ctx, cfg, acmeHTTPClient, &http.Client{Timeout: 30 * time.Second})
}

func serveWithHTTPClients(
	ctx context.Context,
	cfg config.TNLD,
	acmeHTTPClient, serviceEnrollmentHTTPClient *http.Client,
) (retErr error) {
	if acmeHTTPClient == nil || serviceEnrollmentHTTPClient == nil {
		return errors.New("ACME and service enrollment HTTP clients are required")
	}
	lifetime, cancel := context.WithCancel(ctx)
	d := &daemon{
		serviceEnrollmentHTTP: serviceEnrollmentHTTPClient,
		cancel:                cancel, done: make(chan error, 32),
	}
	defer func() { retErr = errors.Join(retErr, d.shutdown(cfg.DrainTimeout)) }()

	metrics := observability.New(string(cfg.Mode))

	if cfg.Mode.RunsControl() {
		database, err := controlstate.Open(ctx, cfg.DatabaseURL)
		if err != nil {
			return err
		}
		d.database = database
		if _, err := database.EnsureServiceAuthority(ctx, time.Now()); err != nil {
			return err
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
				HTTPClient: acmeHTTPClient,
			})
			if err != nil {
				return err
			}
			d.forward("run certificate worker", runAsync(func() error { return worker.Run(lifetime) }))
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
	}

	controlHandler := http.Handler(nil)
	if d.database != nil {
		controlHandler = controlapi.NewHandler(controlAPIConfigFrom(cfg), d.database, d.database.Readiness)
	}

	switch cfg.Mode {
	case config.TNLDModeRelay:
		if err := d.startRelay(lifetime, relayProcessSettingsFrom(cfg), metrics); err != nil {
			return err
		}
	case config.TNLDModeIngress:
		if err := d.startIngress(lifetime, ingressProcessSettingsFrom(cfg), metrics); err != nil {
			return err
		}
	case config.TNLDModeStandalone:
		if err := d.startPrivateControlAPIs(lifetime, privateControlSettingsFrom(cfg)); err != nil {
			return err
		}
		if err := d.startStandalone(lifetime, standaloneSettingsFrom(cfg), metrics, controlHandler); err != nil {
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

func controlAPIConfigFrom(cfg config.TNLD) controlapi.Config {
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
		IngressControlEndpoint:  cfg.IngressControlEndpoint(),
		RelayControlEndpoint:    cfg.RelayControlEndpoint(),
	}
}

func (d *daemon) ready(ctx context.Context, mode config.TNLDMode, now time.Time) error {
	if mode.RunsControl() {
		if d.database == nil || d.controlServer == nil || d.controlListener == nil ||
			d.ingressControlServer == nil || d.ingressControlListener == nil ||
			d.relayControlServer == nil || d.relayControlListener == nil {
			return errors.New("control listeners are not ready")
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
		if runtime.enrollment == nil || !runtime.enrollment.Ready(now) || runtime.controller == nil ||
			!runtime.controller.Ready(now) || runtime.server == nil || !runtime.server.Ready() {
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
			if runtime.enrollment == nil || !runtime.enrollment.Ready(now) || runtime.controller == nil ||
				!runtime.controller.Ready(now) || runtime.registry == nil || runtime.internalListener == nil {
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
	enrollment serviceEnrollmentSettings
	ingressID  string
	listen     string
	runtime    ingressSettings
}

func ingressProcessSettingsFrom(cfg config.TNLD) ingressProcessSettings {
	return ingressProcessSettings{
		enrollment: serviceEnrollmentSettingsFrom(cfg),
		ingressID:  cfg.IngressID,
		listen:     cfg.IngressListen,
		runtime:    ingressSettingsFrom(cfg),
	}
}

func (d *daemon) startIngress(ctx context.Context, settings ingressProcessSettings, metrics *observability.Metrics) error {
	enrollment, err := newServiceEnrollmentState(
		ctx, settings.enrollment, servicepki.RoleIngress, settings.ingressID, d.serviceEnrollmentHTTP,
	)
	if err != nil {
		return err
	}
	privateClient, err := newIngressControlClient(enrollment, "")
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", settings.listen)
	if err != nil {
		return fmt.Errorf("listen for public ingress: %w", err)
	}
	if err := d.startIngressRuntime(ctx, settings.runtime, metrics, ingressRuntimeConfig{
		enrollment: enrollment, client: privateClient, ingressID: settings.ingressID, listener: listener,
	}); err != nil {
		_ = listener.Close()
		return err
	}
	return nil
}

type ingressRuntimeConfig struct {
	enrollment *serviceenrollment.State
	client     ingress.ControlClient
	ingressID  string
	listener   net.Listener
	configure  func(*ingress.Config)
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
	runtime := &ingressRuntime{enrollment: runtimeConfig.enrollment}
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
	forwardingTLS, err := runtimeConfig.enrollment.ForwardingClientTLSConfig()
	if err != nil {
		return err
	}
	forwarder, err := ingress.NewForwarder(ingress.ForwarderConfig{
		TLSConfig: forwardingTLS,
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
			if !runtimeConfig.enrollment.Ready(time.Now()) {
				return ingress.Route{}, false
			}
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
			if !runtimeConfig.enrollment.Ready(time.Now()) {
				return nil, false
			}
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
	d.forward("renew ingress enrollment", runAsync(func() error {
		return runtimeConfig.enrollment.Run(ctx, settings.controlRetryInterval, func(err error) { log.Printf("ingress enrollment: %v", err) })
	}))
	d.forward("run ingress control", runAsync(func() error { return controller.Run(ctx) }))
	d.forward("report ingress usage", runAsync(func() error { return usage.Run(ctx) }))
	d.forward("serve public ingress", runAsync(server.Serve))
	log.Printf("public ingress listening on %s", runtimeConfig.listener.Addr())
	return nil
}

type relayProcessSettings struct {
	enrollment             serviceEnrollmentSettings
	relayID                string
	internalListen         string
	internalAddress        string
	tcpListen              string
	udpListen              string
	quicIdleTimeout        time.Duration
	quicMaxIncomingStreams int64
	runtime                relaySettings
}

func relayProcessSettingsFrom(cfg config.TNLD) relayProcessSettings {
	return relayProcessSettings{
		enrollment:             serviceEnrollmentSettingsFrom(cfg),
		relayID:                cfg.RelayID,
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
	enrollment, err := newServiceEnrollmentState(
		ctx, settings.enrollment, servicepki.RoleRelay, settings.relayID, d.serviceEnrollmentHTTP,
	)
	if err != nil {
		return err
	}
	privateClient, err := newRelayControlClient(enrollment, "")
	if err != nil {
		return err
	}
	internalListener, err := net.Listen("tcp", settings.internalListen)
	if err != nil {
		return fmt.Errorf("listen for internal forwarding: %w", err)
	}
	runtime, err := d.startRelayRuntime(ctx, settings.runtime, relayRuntimeConfig{
		enrollment: enrollment, client: privateClient, relayID: settings.relayID,
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
	enrollment       *serviceenrollment.State
	client           relay.ControlClient
	relayID          string
	internalAddress  string
	internalListener net.Listener
	metrics          *observability.Metrics
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
	runtime := &relayRuntime{enrollment: runtimeConfig.enrollment, internalListener: runtimeConfig.internalListener}
	if runtimeConfig.metrics != nil {
		runtimeConfig.metrics.AddRelayLeases("active", 0)
		runtimeConfig.metrics.AddRelayLeases("draining", 0)
		runtimeConfig.metrics.AddPublisherConnections("ready", 0)
	}
	runID, err := opaqueid.New("relay_run_")
	if err != nil {
		return nil, fmt.Errorf("create relay process run ID: %w", err)
	}
	current := runtimeConfig.enrollment.Enrollment()
	registry := relay.NewRegistry()
	runtime.registry = registry
	controller, err := relay.NewController(relay.ControllerConfig{
		Client: runtimeConfig.client,
		Registration: relayv1.RelayRegistration{
			RelayServiceId: current.RelayServiceID, RelayId: runtimeConfig.relayID, RelayRunId: runID,
			ProtocolVersion: tunnelv1.Version, RelayAddress: current.RelayAddress,
			TlsServerName: current.TLSServerName, InternalRelayAddress: runtimeConfig.internalAddress,
			InternalNetworks: []string{}, ConnectionCapacity: settings.publisherConnectionLimit,
			StreamCapacity: settings.streamCapacity,
		},
		RenewalInterval: settings.leaseRenewalInterval, RetryInterval: settings.controlRetryInterval,
		Load: registry.Load, LeaseChanged: func(previous, current relayv1.RelayLease) {
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
		Registry: registry, StreamCapacity: streamCapacity,
		Report: func(err error) { log.Printf("relay forwarding: %v", err) },
	})
	if err != nil {
		return nil, err
	}
	transportTLS, err := runtimeConfig.enrollment.RelayTransportTLSConfig()
	if err != nil {
		return nil, err
	}
	runtime.transportTLS = transportTLS
	forwardingTLS, err := runtimeConfig.enrollment.ForwardingServerTLSConfig()
	if err != nil {
		return nil, err
	}
	d.relays = append(d.relays, runtime)

	d.forward("renew relay enrollment", runAsync(func() error {
		return runtimeConfig.enrollment.Run(ctx, settings.controlRetryInterval, func(err error) { log.Printf("relay enrollment: %v", err) })
	}))
	d.forward("run relay control", runAsync(func() error { return controller.Run(ctx) }))
	d.forward("serve internal forwarding", serveTLSYamuxSessions(
		ctx, runtimeConfig.internalListener, forwardingTLS,
		muxsession.TLSYamuxConfig{MaxIncomingStreams: streamCapacity}, forwardingAcceptor.Accept,
	))
	log.Printf("relay internal forwarding listening on %s", runtimeConfig.internalListener.Addr())
	return runtime, nil
}

type standaloneSettings struct {
	ingressControlListen   string
	relayControlListen     string
	publicListen           string
	relayUDPListen         string
	quicIdleTimeout        time.Duration
	quicMaxIncomingStreams int64
	serverHostname         string
	relayHostname          string
	ingress                ingressSettings
	relay                  relaySettings
	enrollment             localEnrollmentSettings
}

func standaloneSettingsFrom(cfg config.TNLD) standaloneSettings {
	return standaloneSettings{
		ingressControlListen:   cfg.IngressControlListen,
		relayControlListen:     cfg.RelayControlListen,
		publicListen:           cfg.IngressListen,
		relayUDPListen:         cfg.RelayUDPListen,
		quicIdleTimeout:        cfg.QUICIdleTimeout,
		quicMaxIncomingStreams: cfg.QUICMaxIncomingStreams,
		serverHostname:         cfg.ServerHostname(),
		relayHostname:          cfg.StandaloneRelayHostname(),
		ingress:                ingressSettingsFrom(cfg),
		relay:                  relaySettingsFrom(cfg),
		enrollment:             localEnrollmentSettingsFrom(cfg),
	}
}

func (d *daemon) startStandalone(
	ctx context.Context,
	settings standaloneSettings,
	metrics *observability.Metrics,
	controlHandler http.Handler,
) error {
	ingressControlAddress, err := localControlDialAddress(settings.ingressControlListen)
	if err != nil {
		return err
	}
	relayControlAddress, err := localControlDialAddress(settings.relayControlListen)
	if err != nil {
		return err
	}
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

	targets := make(map[string]*relayRuntime, len(standaloneRelays))
	for _, identity := range standaloneRelays {
		enrollment, err := newLocalServiceEnrollmentState(
			ctx, settings.enrollment, d.database, servicepki.RoleRelay, identity.relayID, identity.serviceID,
		)
		if err != nil {
			return err
		}
		client, err := newRelayControlClient(enrollment, relayControlAddress)
		if err != nil {
			return err
		}
		internalListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("listen for standalone internal forwarding: %w", err)
		}
		runtime, err := d.startRelayRuntime(ctx, settings.relay, relayRuntimeConfig{
			enrollment: enrollment, client: client, relayID: identity.relayID,
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
	transportTLS := d.relays[0].transportTLS
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

	ingressEnrollment, err := newLocalServiceEnrollmentState(
		ctx, settings.enrollment, d.database, servicepki.RoleIngress, standaloneIngressID, "",
	)
	if err != nil {
		return err
	}
	ingressClient, err := newIngressControlClient(ingressEnrollment, ingressControlAddress)
	if err != nil {
		return err
	}
	if err := d.startIngressRuntime(ctx, settings.ingress, metrics, ingressRuntimeConfig{
		enrollment: ingressEnrollment, client: ingressClient, ingressID: standaloneIngressID,
		listener: publicListener,
		configure: func(ingressConfig *ingress.Config) {
			ingressConfig.ServerHostname = settings.serverHostname
			ingressConfig.HandleControl = controlListener.Enqueue
			ingressConfig.RelayHostname = settings.relayHostname
			ingressConfig.HandleRelay = relayListener.Enqueue
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

func localControlDialAddress(listenAddress string) (string, error) {
	host, port, err := net.SplitHostPort(listenAddress)
	if err != nil {
		return "", fmt.Errorf("parse private control listen address: %w", err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}

type serviceEnrollmentSettings struct {
	controlHostname string
	token           credentials.ServiceEnrollmentToken
}

func serviceEnrollmentSettingsFrom(cfg config.TNLD) serviceEnrollmentSettings {
	return serviceEnrollmentSettings{
		controlHostname: cfg.ControlHostname,
		token:           credentials.ServiceEnrollmentToken(cfg.ServiceEnrollmentToken),
	}
}

func newServiceEnrollmentState(
	ctx context.Context,
	settings serviceEnrollmentSettings,
	role servicepki.Role,
	processID string,
	httpClient *http.Client,
) (*serviceenrollment.State, error) {
	publicClient, err := controlv1.NewClientWithResponses(
		"https://"+settings.controlHostname,
		controlv1.WithHTTPClient(httpClient),
	)
	if err != nil {
		return nil, fmt.Errorf("configure service enrollment client: %w", err)
	}
	enroller, err := serviceenrollment.New(serviceenrollment.Config{
		Client: publicClient, ControlHostname: settings.controlHostname,
		ServiceEnrollmentToken: settings.token,
		Role:                   role, ProcessID: processID,
	})
	if err != nil {
		return nil, err
	}
	return serviceenrollment.NewState(ctx, enroller)
}

type localEnrollmentSettings struct {
	controlHostname        string
	ingressControlEndpoint string
	relayControlEndpoint   string
	relayHostname          string
}

func localEnrollmentSettingsFrom(cfg config.TNLD) localEnrollmentSettings {
	return localEnrollmentSettings{
		controlHostname:        cfg.ServerHostname(),
		ingressControlEndpoint: cfg.IngressControlEndpoint(),
		relayControlEndpoint:   cfg.RelayControlEndpoint(),
		relayHostname:          cfg.StandaloneRelayHostname(),
	}
}

func newLocalServiceEnrollmentState(
	ctx context.Context,
	settings localEnrollmentSettings,
	database *controlstate.Database,
	role servicepki.Role,
	processID, relayServiceID string,
) (*serviceenrollment.State, error) {
	enroller, err := serviceenrollment.NewLocal(serviceenrollment.Config{
		Client: &localEnrollmentClient{
			database: database, settings: settings, role: role, processID: processID,
			relayServiceID: relayServiceID,
		},
		ControlHostname: settings.controlHostname, Role: role, ProcessID: processID,
	})
	if err != nil {
		return nil, err
	}
	return serviceenrollment.NewState(ctx, enroller)
}

type localEnrollmentClient struct {
	database       *controlstate.Database
	settings       localEnrollmentSettings
	role           servicepki.Role
	processID      string
	relayServiceID string
}

func (c *localEnrollmentClient) EnrollServiceWithResponse(
	ctx context.Context,
	body controlv1.EnrollServiceJSONRequestBody,
	_ ...controlv1.RequestEditorFn,
) (*controlv1.EnrollServiceResponse, error) {
	processID := ""
	if body.IngressId != nil {
		processID = *body.IngressId
	}
	if body.RelayId != nil {
		if processID != "" {
			return nil, errors.New("local enrollment sent multiple process identities")
		}
		processID = *body.RelayId
	}
	if servicepki.Role(body.Role) != c.role || processID != c.processID || body.ServiceEnrollmentToken != "" {
		return nil, errors.New("local enrollment identity changed")
	}
	relayAddress, tlsServerName := "", ""
	if c.role == servicepki.RoleRelay {
		tlsServerName = c.settings.relayHostname
		relayAddress = net.JoinHostPort(tlsServerName, "443")
	}
	enrollment, err := c.database.EnrollLocalService(ctx, controlstate.LocalServiceEnrollmentRequest{
		Role: c.role, ProcessID: c.processID, CSRPEM: body.CertificateSigningRequest,
		RelayServiceID: c.relayServiceID, RelayAddress: relayAddress,
		TLSServerName: tlsServerName, EnrolledAt: time.Now(),
	})
	if err != nil {
		return nil, err
	}
	response := serviceEnrollmentResponse(c.settings, enrollment)
	return &controlv1.EnrollServiceResponse{
		HTTPResponse: &http.Response{StatusCode: http.StatusOK}, JSON200: &response,
	}, nil
}

func newRelayControlClient(enrollment *serviceenrollment.State, dialAddress string) (*relayv1.ClientWithResponses, error) {
	client, err := newPrivateServiceHTTPClient(enrollment, dialAddress)
	if err != nil {
		return nil, err
	}
	return relayv1.NewClientWithResponses(
		enrollment.Enrollment().InternalControlEndpoint,
		relayv1.WithHTTPClient(client),
	)
}

func newIngressControlClient(enrollment *serviceenrollment.State, dialAddress string) (*ingressv1.ClientWithResponses, error) {
	client, err := newPrivateServiceHTTPClient(enrollment, dialAddress)
	if err != nil {
		return nil, err
	}
	return ingressv1.NewClientWithResponses(
		enrollment.Enrollment().InternalControlEndpoint,
		ingressv1.WithHTTPClient(client),
	)
}

func newPrivateServiceHTTPClient(enrollment *serviceenrollment.State, dialAddress string) (*http.Client, error) {
	tlsConfig, err := enrollment.InternalControlTLSConfig()
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	if dialAddress != "" {
		dialer := new(net.Dialer)
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, dialAddress)
		}
	}
	client := &http.Client{
		Transport: enrollmentRoundTripper{state: enrollment, transport: transport},
		Timeout:   30 * time.Second,
	}
	return client, nil
}

type enrollmentRoundTripper struct {
	state     *serviceenrollment.State
	transport *http.Transport
}

func (t enrollmentRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if !t.state.Ready(time.Now()) {
		return nil, errors.New("service enrollment certificate is expired")
	}
	return t.transport.RoundTrip(request)
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
	ingressListen        string
	relayListen          string
	tls                  privateControlTLSSettings
}

type privateControlTLSSettings struct {
	hostname      string
	retryInterval time.Duration
}

func privateControlSettingsFrom(cfg config.TNLD) privateControlSettings {
	return privateControlSettings{
		ingressLeaseDuration: cfg.IngressLeaseDuration,
		relayLeaseDuration:   cfg.RelayLeaseDuration,
		ingressListen:        cfg.IngressControlListen,
		relayListen:          cfg.RelayControlListen,
		tls: privateControlTLSSettings{
			hostname: cfg.ServerHostname(), retryInterval: cfg.ControlRetryInterval,
		},
	}
}

func (d *daemon) startPrivateControlAPIs(ctx context.Context, settings privateControlSettings) error {
	ingressHandler, err := ingressapi.NewHandler(ingressapi.Config{
		Store: d.database,
		IngressIdentity: func(certificate *x509.Certificate) (string, error) {
			identity, err := servicepki.CertificateIdentity(certificate)
			if err != nil || identity.Role != servicepki.RoleIngress {
				return "", errors.New("certificate does not contain an ingress identity")
			}
			return identity.ProcessID, nil
		},
		LeaseDuration: settings.ingressLeaseDuration,
	})
	if err != nil {
		return err
	}
	relayHandler, err := relayapi.NewHandler(relayapi.Config{
		Store: d.database,
		RelayIdentity: func(certificate *x509.Certificate) (relayapi.RelayIdentity, error) {
			identity, err := servicepki.CertificateIdentity(certificate)
			if err != nil || identity.Role != servicepki.RoleRelay {
				return relayapi.RelayIdentity{}, errors.New("certificate does not contain a relay identity")
			}
			return relayapi.RelayIdentity{RelayServiceID: identity.RelayServiceID, RelayID: identity.ProcessID}, nil
		},
		LeaseDuration: settings.relayLeaseDuration,
	})
	if err != nil {
		return err
	}
	ingressTLS, err := d.privateControlTLSConfig(ctx, settings.tls, servicepki.RoleIngress)
	if err != nil {
		return err
	}
	relayTLS, err := d.privateControlTLSConfig(ctx, settings.tls, servicepki.RoleRelay)
	if err != nil {
		return err
	}
	ingressListener, err := net.Listen("tcp", settings.ingressListen)
	if err != nil {
		return fmt.Errorf("listen for ingress API: %w", err)
	}
	d.ingressControlListener = ingressListener
	ingressServer := controlHTTPServer(ingressHandler, ingressTLS)
	d.ingressControlServer = ingressServer
	d.forward("serve ingress API", serveTLS(ingressServer, ingressListener))
	log.Printf("ingress API listening on %s", ingressListener.Addr())

	relayListener, err := net.Listen("tcp", settings.relayListen)
	if err != nil {
		return fmt.Errorf("listen for relay API: %w", err)
	}
	d.relayControlListener = relayListener
	relayServer := controlHTTPServer(relayHandler, relayTLS)
	d.relayControlServer = relayServer
	d.forward("serve relay API", serveTLS(relayServer, relayListener))
	log.Printf("relay API listening on %s", relayListener.Addr())
	return nil
}

func (d *daemon) privateControlTLSConfig(ctx context.Context, settings privateControlTLSSettings, role servicepki.Role) (*tls.Config, error) {
	authority, err := d.database.EnsureServiceAuthority(ctx, time.Now())
	if err != nil {
		return nil, err
	}
	clientAuthorities := x509.NewCertPool()
	if !clientAuthorities.AppendCertsFromPEM([]byte(authority.CertificatePEM)) {
		return nil, errors.New("parse service CA trust bundle")
	}
	source := new(privateControlCertificateSource)
	if err := source.renew(ctx, d.database, role, settings.hostname); err != nil {
		return nil, err
	}
	go source.run(ctx, d.database, role, settings.hostname, settings.retryInterval)
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      clientAuthorities,
		GetCertificate: source.getCertificate,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("service client certificate is missing")
			}
			identity, err := servicepki.CertificateIdentity(state.PeerCertificates[0])
			if err != nil || identity.Role != role {
				return errors.New("service client certificate has the wrong role")
			}
			return nil
		},
	}, nil
}

type privateControlCertificateSource struct {
	mu          sync.RWMutex
	certificate *tls.Certificate
	expiresAt   time.Time
}

func (s *privateControlCertificateSource) renew(
	ctx context.Context,
	database *controlstate.Database,
	role servicepki.Role,
	hostname string,
) error {
	issued, err := database.IssueInternalControlCertificate(ctx, role, hostname, time.Now())
	if err != nil {
		return err
	}
	certificate, err := tls.X509KeyPair([]byte(issued.CertificatePEM), []byte(issued.PrivateKeyPEM))
	if err != nil {
		return fmt.Errorf("parse internal control certificate: %w", err)
	}
	s.mu.Lock()
	s.certificate = &certificate
	s.expiresAt = issued.ExpiresAt
	s.mu.Unlock()
	return nil
}

func (s *privateControlCertificateSource) run(
	ctx context.Context,
	database *controlstate.Database,
	role servicepki.Role,
	hostname string,
	retryInterval time.Duration,
) {
	for {
		s.mu.RLock()
		renewAt := s.expiresAt.Add(-30 * time.Minute)
		s.mu.RUnlock()
		delay := time.Until(renewAt)
		if delay < 0 {
			delay = 0
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if err := s.renew(ctx, database, role, hostname); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("renew %s API certificate: %v", role, err)
			timer.Reset(retryInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}
}

func (s *privateControlCertificateSource) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.certificate == nil || !s.expiresAt.After(time.Now()) {
		return nil, errors.New("internal control certificate is expired")
	}
	return s.certificate, nil
}

type controlTLSSettings struct {
	certificateFile string
	privateKeyFile  string
	directoryURL    string
	hostname        string
	email           string
	acceptTerms     bool
}

func controlTLSSettingsFrom(cfg config.TNLD) controlTLSSettings {
	return controlTLSSettings{
		certificateFile: cfg.ControlTLSCertificateFile,
		privateKeyFile:  cfg.ControlTLSPrivateKeyFile,
		directoryURL:    cfg.ACMEDirectoryURL,
		hostname:        cfg.ServerHostname(),
		email:           cfg.ACMEEmail,
		acceptTerms:     cfg.ACMEAcceptTerms,
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
		Email: settings.email, AcceptTerms: settings.acceptTerms, AccountKey: account.AccountKeyDER,
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

func serviceEnrollmentResponse(
	settings localEnrollmentSettings,
	enrollment controlstate.ServiceEnrollment,
) controlv1.ServiceEnrollmentResponse {
	response := controlv1.ServiceEnrollmentResponse{
		Role: controlv1.ServiceEnrollmentRole(enrollment.Role), ServiceCertificate: enrollment.ServiceCertificatePEM,
		TrustBundle: enrollment.TrustBundlePEM, CertificateExpiresAt: enrollment.CertificateExpiresAt,
	}
	if enrollment.Role == controlstate.ServiceEnrollmentRoleIngress {
		response.InternalControlEndpoint = settings.ingressControlEndpoint
		return response
	}
	response.InternalControlEndpoint = settings.relayControlEndpoint
	response.RelayServiceId = &enrollment.RelayServiceID
	response.RelayAddress = &enrollment.RelayAddress
	response.TlsServerName = &enrollment.TLSServerName
	response.RelayTransportCertificate = &enrollment.RelayTransportMaterial.CertificatePEM
	response.RelayTransportPrivateKey = &enrollment.RelayTransportMaterial.PrivateKeyPEM
	return response
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
	for _, server := range []*http.Server{d.controlServer, d.ingressControlServer, d.relayControlServer} {
		if server != nil {
			result = errors.Join(result, server.Shutdown(ctx))
		}
	}
	for _, listener := range []net.Listener{d.controlListener, d.ingressControlListener, d.relayControlListener} {
		if listener != nil {
			result = errors.Join(result, closeNetworkListener(listener))
		}
	}
	if d.metricsServer != nil {
		result = errors.Join(result, d.metricsServer.Shutdown(ctx))
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
	go func() {
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
