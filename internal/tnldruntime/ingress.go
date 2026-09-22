package tnldruntime

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/routebackend"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ingressRuntime struct {
	controller *ingress.Controller
	server     *ingress.Server
	forwarder  *ingress.Forwarder
	usage      *ingress.UsageReporter
	recovery   *ingress.RecoveryReporter
}

type ingressProcessSettings struct {
	controlEndpoint string
	controlAddress  string
	clusterSecret   string
	ingressID       string
	listen          string
	runtime         ingressSettings
}

func ingressProcessSettingsFrom(cfg tnldconfig.Config) ingressProcessSettings {
	return ingressProcessSettings{
		controlEndpoint: cfg.PrivateControlEndpoint(), controlAddress: cfg.PrivateControlAddress,
		clusterSecret: cfg.ClusterSecret,
		ingressID:     cfg.IngressID, listen: cfg.IngressListen, runtime: ingressSettingsFrom(cfg),
	}
}

func (d *daemon) startIngress(ctx context.Context, settings ingressProcessSettings, metrics *observability.Metrics) error {
	privateClient, err := newIngressControlClient(
		settings.controlEndpoint, settings.clusterSecret, d.serviceHTTP, settings.controlAddress,
	)
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
	clientHelloConnectionLimit       int
	challengeConnectionLimit         int
	challengeHostnameConnectionLimit int
	standaloneControlConnectionLimit int
	standaloneRelayConnectionLimit   int
	sourceConnectionRate             float64
	sourceConnectionBurst            int
	visitorConnectionLimit           int64
	routeConnectionLimit             int64
	requireProxyHeader               bool
	leaseRenewalInterval             time.Duration
	controlRetryInterval             time.Duration
	routingTableWait                 time.Duration
}

func ingressSettingsFrom(cfg tnldconfig.Config) ingressSettings {
	return ingressSettings{
		clientHelloConnectionLimit:       cfg.ClientHelloConnectionLimit,
		challengeConnectionLimit:         cfg.ChallengeConnectionLimit,
		challengeHostnameConnectionLimit: cfg.ChallengeHostnameConnectionLimit,
		standaloneControlConnectionLimit: cfg.StandaloneControlConnectionLimit,
		standaloneRelayConnectionLimit:   cfg.StandaloneRelayConnectionLimit,
		sourceConnectionRate:             cfg.SourceConnectionRate,
		sourceConnectionBurst:            cfg.SourceConnectionBurst,
		visitorConnectionLimit:           cfg.VisitorConnectionLimit,
		routeConnectionLimit:             cfg.RouteConnectionLimit,
		requireProxyHeader:               cfg.RequireProxyHeader,
		leaseRenewalInterval:             cfg.LeaseRenewalInterval,
		controlRetryInterval:             cfg.ControlRetryInterval,
		routingTableWait:                 cfg.RoutingTableWait,
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
			ConnectionCapacity: settings.visitorConnectionLimit,
		},
		RenewalInterval: settings.leaseRenewalInterval, RetryInterval: settings.controlRetryInterval,
		RoutingWait: settings.routingTableWait, Observer: metrics,
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
	metrics.RegisterIngressRouting(controller.RoutingStatus)
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
		TLSConfig: forwardingTLS, ClusterSecret: runtimeConfig.clusterSecret, Observer: metrics,
	})
	if err != nil {
		return err
	}
	runtime.forwarder = forwarder
	publicCapacity, err := runtimeCapacity("visitor connection", settings.visitorConnectionLimit)
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
		MaxClientHelloConnections:       settings.clientHelloConnectionLimit,
		MaxChallengeConnections:         settings.challengeConnectionLimit,
		MaxHostnameChallengeConnections: settings.challengeHostnameConnectionLimit,
		MaxControlConnections:           settings.standaloneControlConnectionLimit,
		MaxRelayConnections:             settings.standaloneRelayConnectionLimit,
		SourceConnectionRate:            settings.sourceConnectionRate, SourceConnectionBurst: settings.sourceConnectionBurst,
		MaxRouteConnections: routeCapacity, Metrics: metrics, Observer: metrics,
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

func newIngressControlClient(endpoint, clusterSecret string, base *http.Client, dialAddress string) (ingress.ControlClient, error) {
	client, err := newPrivateServiceHTTPClient(base, clusterSecret, dialAddress)
	if err != nil {
		return nil, err
	}
	generated, err := ingressv1.NewClientWithResponses(endpoint, ingressv1.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	return ingress.NewHTTPControlClient(generated)
}
