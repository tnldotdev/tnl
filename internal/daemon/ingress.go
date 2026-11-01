package daemon

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"time"

	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/ingress"
	ingresspool "github.com/tnldotdev/tnl/internal/ingress/pool"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ingressRuntime struct {
	configuredIdentity string
	processRunID       string
	controller         *ingress.Controller
	server             *ingress.Server
	forwarder          *ingress.Forwarder
	usage              *ingress.UsageReporter
	recovery           *ingress.RecoveryReporter
	publicServices     *ingress.PublicServices
	audit              *ingressServiceAudit
}

// only fully constructed controllers enter the immutable collection snapshot.
// metric callbacks never read the constructor-owned daemon runtime slice.
type ingressLeaseSnapshot struct{ controllers []*ingress.Controller }

func (d *daemon) publishIngressRuntime(runtime *ingressRuntime) {
	d.ingresses = append(d.ingresses, runtime)
	controllers := make([]*ingress.Controller, 0, len(d.ingresses))
	for _, current := range d.ingresses {
		controllers = append(controllers, current.controller)
	}
	d.ingressLeases.Store(&ingressLeaseSnapshot{controllers})
}

type ingressProcessSettings struct {
	controlEndpoint string
	controlAddress  string
	clusterSecret   string
	ingressID       string
	listen          string
	listener        net.Listener
	runtime         ingressSettings
}

func ingressProcessSettingsFrom(cfg daemonconfig.Config) ingressProcessSettings {
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
	listener := settings.listener
	if listener == nil {
		listener, err = listenIngress(settings.listen, settings.runtime.servicePortRanges.Ranges(), settings.runtime.requireProxyHeader)
		if err != nil {
			return fmt.Errorf("listen for public ingress: %w", err)
		}
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
	client                  ingress.ControlClient
	ingressID               string
	listener                net.Listener
	clusterSecret           string
	configure               func(*ingress.Config)
	configurePublicServices func(*ingress.PublicServicesConfig)
}

type ingressSettings struct {
	clientHelloConnectionLimit       int
	standaloneControlConnectionLimit int
	standaloneRelayConnectionLimit   int
	visitorConnectionLimit           int64
	ingressPoolID                    ingresspool.ID
	requireProxyHeader               bool
	trustedProxyPeers                []netip.Prefix
	leaseRenewalInterval             time.Duration
	controlRetryInterval             time.Duration
	routingTableWait                 time.Duration
	traffic                          ingress.TrafficConfig
	pending                          ingress.PendingConfig
	servicePortRanges                tcpport.Inventory
}

func ingressSettingsFrom(cfg daemonconfig.Config) ingressSettings {
	ports, _ := cfg.ServicePortInventory() // validated before runtime construction.
	pool := cfg.IngressPoolID
	if pool == "" {
		pool = ingresspool.PrimaryID
	}
	peers, _ := proxyproto.TrustedPeers(cfg.IngressTrustedProxies)
	return ingressSettings{
		clientHelloConnectionLimit:       cfg.ClientHelloConnectionLimit,
		standaloneControlConnectionLimit: cfg.StandaloneControlConnectionLimit,
		standaloneRelayConnectionLimit:   cfg.StandaloneRelayConnectionLimit,
		visitorConnectionLimit:           cfg.VisitorConnectionLimit,
		ingressPoolID:                    pool,
		requireProxyHeader:               cfg.RequireProxyHeader,
		trustedProxyPeers:                peers,
		leaseRenewalInterval:             cfg.LeaseRenewalInterval,
		controlRetryInterval:             cfg.ControlRetryInterval,
		routingTableWait:                 cfg.RoutingTableWait,
		traffic:                          cfg.IngressTraffic(),
		pending:                          cfg.IngressPending(),
		servicePortRanges:                ports,
	}
}

func (d *daemon) startIngressRuntime(
	ctx context.Context,
	settings ingressSettings,
	metrics *observability.Metrics,
	runtimeConfig ingressRuntimeConfig,
) error {
	runtime := &ingressRuntime{}
	auditClient, ok := runtimeConfig.client.(ingressServiceObservationClient)
	if !ok {
		return errors.New("ingress service observation reporting is required")
	}
	runtime.audit = &ingressServiceAudit{ctx: ctx, client: auditClient, metrics: metrics}
	owned := false
	defer func() {
		if !owned {
			flush, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			_ = runtime.audit.Close(flush)
			cancel()
			if runtime.publicServices != nil {
				_ = runtime.publicServices.Close()
			}
			if runtime.forwarder != nil {
				_ = runtime.forwarder.Close()
			}
		}
	}()
	runID, err := opaqueid.New(opaqueid.IngressRunPrefix)
	if err != nil {
		return fmt.Errorf("create ingress process run ID: %w", err)
	}
	runtime.configuredIdentity, runtime.processRunID = runtimeConfig.ingressID, runID
	routingTable := new(ingress.RoutingTable)
	var publicServer *ingress.Server
	registration := ingressv1.IngressRegistration{IngressId: runtimeConfig.ingressID, IngressRunId: runID, ProtocolVersion: tunnelv1.Version, ConnectionCapacity: settings.visitorConnectionLimit}
	registration.IngressPoolId, registration.ServicePorts = string(settings.ingressPoolID), settings.servicePortRanges.Ports()
	controller, err := ingress.NewController(ingress.ControllerConfig{
		Report: func(err error) {
			logOperationalError(ctx, "renew ingress lease", failure.ServerControlConnectionFailed, err)
		},
		LeaseEstablished: runtime.audit.bind,
		Client:           runtimeConfig.client, RoutingTable: routingTable,
		Registration:    registration,
		RenewalInterval: settings.leaseRenewalInterval, RetryInterval: settings.controlRetryInterval,
		RoutingWait: settings.routingTableWait, Observer: metrics,
		Load: func() int64 {
			var private int64
			if runtime.publicServices != nil {
				private = runtime.publicServices.Load()
			}
			if publicServer == nil {
				return private
			}
			return publicServer.Load() + private
		},
	})
	if err != nil {
		return err
	}
	runtime.controller = controller
	metrics.RegisterIngressRouting(controller.RoutingStatus)
	metrics.RegisterIngressLease(func() time.Time {
		deadline := controller.Lease().LeaseExpiresAt
		if snapshot := d.ingressLeases.Load(); snapshot != nil {
			for _, other := range snapshot.controllers {
				deadline = minTime(deadline, other.Lease().LeaseExpiresAt)
			}
		}
		return deadline
	})
	var recovery *ingress.RecoveryReporter
	// every actual ingress lease participates in public URL usage coverage.
	usage, err := ingress.NewUsageReporter(controller, 0, func(err error) { logOperationalError(ctx, "report ingress usage", failure.ServerWorkerFailed, err) })
	if err != nil {
		return err
	}
	usage.SetObserver(metrics)
	runtime.usage = usage
	recovery, err = ingress.NewRecoveryReporter(ctx, controller, settings.controlRetryInterval, func(err error) {
		logOperationalError(ctx, "report ingress recovery", failure.ServerWorkerFailed, err)
	})
	if err != nil {
		return err
	}
	runtime.recovery = recovery
	recovery.SetObserver(metrics)
	forwardingTLS := d.relayClientTLS
	if forwardingTLS == nil {
		forwardingTLS = &tls.Config{MinVersion: tls.VersionTLS13}
	} else {
		forwardingTLS = forwardingTLS.Clone()
		forwardingTLS.MinVersion = tls.VersionTLS13
	}
	forwarder, err := ingress.NewForwarder(ingress.ForwarderConfig{
		SignVisitorSource: controller.SignVisitorSource,
		Context:           ctx,
		TLSConfig:         forwardingTLS, ClusterSecret: runtimeConfig.clusterSecret, Observer: metrics,
		OnSessionClosed: func(relayServiceID, relayID, origin string, cause error) {
			logOperationalError(ctx, "close ingress relay session", failure.ServerConnectionFailed, cause)
		},
	})
	if err != nil {
		return err
	}
	runtime.forwarder = forwarder
	publicCapacity, err := runtimeCapacity("visitor connection", settings.visitorConnectionLimit)
	if err != nil {
		return err
	}
	ingressConfig := ingress.Config{
		AuditSink: runtime.audit,
		LookupPool: func(hostname string) ([]ingress.PublicURL, ingress.LookupReason) {
			entries, reason := controller.LookupAllWithReason(hostname, time.Now())
			if reason != ingress.LookupCurrent {
				return nil, reason
			}
			routes, err := forwarder.PublicURLs(entries)
			if err != nil {
				logOperationalError(ctx, "read ingress public URL", failure.ServerIngressFailed, err)
				return nil, ingress.LookupInvalidProjection
			}
			return routes, ingress.LookupCurrent
		},
		RequireProxyHeader: settings.requireProxyHeader, TrustedProxyPeers: settings.trustedProxyPeers, MaxConnections: publicCapacity,
		Traffic: settings.traffic, Pending: settings.pending,
		TerminalTrafficRuns:       routingTable.TerminalTrafficRuns,
		MaxClientHelloConnections: settings.clientHelloConnectionLimit,
		MaxControlConnections:     settings.standaloneControlConnectionLimit,
		MaxRelayConnections:       settings.standaloneRelayConnectionLimit,
		Metrics:                   metrics, Observer: metrics,
		OnError: func(err error) {
			logOperationalError(ctx, "serve ingress connection", failure.ServerIngressFailed, err)
		},
		OnForwardingFailure: func(publicURLID string, version uint64, visitorID string, reason ingress.ForwardingFailureReason, attempts int) {
			log.Printf("ingress forwarding failed public_url_id=%s publish_run_number=%d visitor_connection_id=%s reason=%s available_backends=%d",
				publicURLID, version, visitorID, reason, attempts)
		},
	}
	if usage != nil {
		ingressConfig.OpenUsage = usage.Open
	}
	if recovery != nil {
		ingressConfig.ObserveRecovery = recovery.Observe
	}
	if runtimeConfig.configure != nil {
		runtimeConfig.configure(&ingressConfig)
	}
	ingressConfig.AuditSink = runtime.audit
	publicServiceControl, ok := runtimeConfig.client.(ingress.PublicServiceControl)
	if !ok {
		return errors.New("public service ingress control operations are required")
	}
	publicServicesConfig := ingress.PublicServicesConfig{IngressPoolID: string(settings.ingressPoolID), Control: publicServiceControl, Forwarder: forwarder, CurrentLease: controller.Lease, AuditSink: runtime.audit}
	if runtimeConfig.configurePublicServices != nil {
		runtimeConfig.configurePublicServices(&publicServicesConfig)
	}
	publicServicesConfig.AuditSink = runtime.audit
	runtime.publicServices, err = ingress.NewPublicServices(publicServicesConfig)
	if err != nil {
		return err
	}
	ingressConfig.PublicServices, ingressConfig.ServicePortRanges = runtime.publicServices, settings.servicePortRanges.Ranges()
	ingressConfig.Traffic, ingressConfig.Pending, err = daemonconfig.ValidateIngressTraffic(ingressConfig.Traffic, ingressConfig.Pending)
	if err != nil {
		_ = forwarder.Close()
		return err
	}
	server, err := ingress.New(runtimeConfig.listener, ingressConfig)
	if err != nil {
		_ = forwarder.Close()
		return err
	}
	runtime.server = server
	forwarder.SetPromotionHandler(server.PromotePendingAdmission)
	if metrics != nil {
		for resource, limit := range map[string]int64{
			"public_url_connections":         int64(ingressConfig.Traffic.Default.Connections),
			"source_connections":             int64(ingressConfig.Traffic.SourceConnections),
			"source_connection_rate":         int64(ingressConfig.Traffic.SourceRate),
			"process_connection_rate":        int64(ingressConfig.Traffic.ProcessRate),
			"denied_connections":             int64(ingressConfig.Pending.Connections),
			"pending_public_url_connections": int64(ingressConfig.Pending.PublicURLConnections),
			"pending_source_connections":     int64(ingressConfig.Pending.SourceConnections),
		} {
			metrics.SetCapacityLimit(resource, limit)
		}
	}
	publicServer = server
	d.publishIngressRuntime(runtime)
	owned = true
	d.start("run ingress control", func() error { return controller.Run(ctx) })
	d.start("report ingress usage", func() error { return usage.Run(ctx) })
	d.start("serve public ingress", server.Serve)
	log.Printf("public ingress listening on %s", runtimeConfig.listener.Addr())
	return nil
}

func newIngressControlClient(endpoint, clusterSecret string, base *http.Client, dialAddress string) (ingress.ControlClient, error) {
	client, err := newServiceHTTPClient(base, clusterSecret, dialAddress)
	if err != nil {
		return nil, err
	}
	generated, err := ingressv1.NewClientWithResponses(endpoint, ingressv1.WithHTTPClient(observability.OwnedHTTPClient(client, "private_ingress")))
	if err != nil {
		return nil, err
	}
	control, err := ingress.NewHTTPControlClient(generated)
	if err != nil {
		return nil, err
	}
	return &ingressRuntimeClient{HTTPControlClient: control, generated: generated}, nil
}
