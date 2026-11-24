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
	"slices"
	"time"

	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/ingress"
	ingresspool "github.com/tnldotdev/tnl/internal/naming/ingresspool"
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
	recovery           *ingress.RecoveryReporter
	audit              *ingressServiceAudit
}

func (r *ingressRuntime) load() int64 {
	if r.server == nil {
		return 0
	}
	return r.server.Load()
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
	controlEndpoint      string
	controlAddress       string
	clusterSecret        string
	forwardingCredential string
	ingressID            string
	listen               string
	listener             net.Listener
	runtime              ingressSettings
	expectedPorts        []tcpport.Range
}

func ingressProcessSettingsFrom(cfg daemonconfig.Config) ingressProcessSettings {
	result := ingressProcessSettings{
		controlEndpoint: cfg.PrivateControlEndpoint(), controlAddress: cfg.PrivateControlAddress,
		clusterSecret:        cfg.IngressControlCredential,
		forwardingCredential: cfg.ForwardingCredential,
		ingressID:            cfg.IngressID, listen: cfg.IngressListen, runtime: ingressSettingsFrom(cfg),
	}
	if cfg.ServicePortRanges != nil {
		inventory, _ := cfg.ServicePortInventory()
		result.expectedPorts = inventory.Ranges()
	}
	return result
}

func (d *daemon) startIngress(startup, ctx context.Context, settings ingressProcessSettings, metrics *observability.Metrics) error {
	privateClient, err := newIngressControlClient(
		settings.controlEndpoint, settings.clusterSecret, d.serviceHTTP, settings.controlAddress,
	)
	if err != nil {
		return err
	}
	startup, cancelStartup := context.WithTimeout(startup, 30*time.Second)
	defer cancelStartup()
	ports, err := privateClient.ReadIngressPoolPorts(startup, string(settings.runtime.ingressPoolID), settings.runtime.controlRetryInterval)
	if err != nil {
		return fmt.Errorf("read ingress pool ports: %w", err)
	}
	if settings.expectedPorts != nil && !slices.Equal(settings.expectedPorts, ports.Ranges()) {
		return errors.New("explicit ingress service port ranges differ from control's saved pool")
	}
	settings.runtime.servicePortRanges = ports
	listener := settings.listener
	if listener == nil {
		listener, err = listenIngress(settings.listen, settings.runtime.servicePortRanges.Ranges(), settings.runtime.requireProxyHeader)
		if err != nil {
			return fmt.Errorf("listen for public ingress: %w", err)
		}
	}
	if err := d.startIngressRuntime(ctx, settings.runtime, metrics, ingressRuntimeConfig{
		client: privateClient, ingressID: settings.ingressID, listener: listener, clusterSecret: settings.forwardingCredential,
	}); err != nil {
		_ = listener.Close()
		return err
	}
	return nil
}

type ingressRuntimeControl interface {
	ingress.ControlClient
	ingress.PublicServiceControl
	ingressServiceObservationClient
}

type ingressRuntimeConfig struct {
	client        ingressRuntimeControl
	ingressID     string
	listener      net.Listener
	clusterSecret string
	configure     func(*ingress.Config)
}

type ingressSettings struct {
	region                           string
	clientHelloConnectionLimit       int
	standaloneControlConnectionLimit int
	standaloneRelayConnectionLimit   int
	visitorConnectionLimit           int64
	ingressPoolID                    ingresspool.ID
	requireProxyHeader               bool
	trustedProxyPeers                []netip.Prefix
	leaseRenewalInterval             time.Duration
	controlRetryInterval             time.Duration
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
		region:                           string(cfg.ServingRegion()),
		clientHelloConnectionLimit:       cfg.ClientHelloConnectionLimit,
		standaloneControlConnectionLimit: cfg.StandaloneControlConnectionLimit,
		standaloneRelayConnectionLimit:   cfg.StandaloneRelayConnectionLimit,
		visitorConnectionLimit:           cfg.VisitorConnectionLimit,
		ingressPoolID:                    pool,
		requireProxyHeader:               cfg.RequireProxyHeader,
		trustedProxyPeers:                peers,
		leaseRenewalInterval:             cfg.LeaseRenewalInterval,
		controlRetryInterval:             cfg.ControlRetryInterval,
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
	if runtimeConfig.client == nil {
		return errors.New("ingress runtime control client is required")
	}
	runtime.audit = &ingressServiceAudit{ctx: ctx, client: runtimeConfig.client, metrics: metrics}
	owned := false
	defer func() {
		if !owned {
			flush, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			_ = runtime.audit.Close(flush)
			cancel()
			if runtime.server != nil {
				_ = runtime.server.Close()
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
	registration := ingressv1.IngressRegistration{IngressId: runtimeConfig.ingressID, IngressRunId: runID, ProtocolVersion: tunnelv1.Version, ConnectionCapacity: settings.visitorConnectionLimit, Https: true}
	registration.Region = settings.region
	registration.IngressPoolId = string(settings.ingressPoolID)
	ranges := settings.servicePortRanges.Ranges()
	registration.ServicePortRanges = make([]ingressv1.ServicePortRange, len(ranges))
	for index, r := range ranges {
		registration.ServicePortRanges[index] = ingressv1.ServicePortRange{First: r.First, Last: r.Last}
	}
	controller, err := ingress.NewController(ingress.ControllerConfig{
		Report: func(err error) {
			logOperationalError(ctx, "renew ingress lease", failure.ServerControlConnectionFailed, err)
		},
		LeaseEstablished: runtime.audit.bind,
		Client:           runtimeConfig.client,
		Registration:     registration,
		RenewalInterval:  settings.leaseRenewalInterval, RetryInterval: settings.controlRetryInterval,
		Observer: metrics,
		Load:     runtime.load,
	})
	if err != nil {
		return err
	}
	runtime.controller = controller
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
		Context:   ctx,
		TLSConfig: forwardingTLS, ClusterSecret: runtimeConfig.clusterSecret, Observer: metrics,
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
		Control:   runtimeConfig.client, Forwarder: forwarder, CurrentLease: controller.Lease,
		IngressPoolID: string(settings.ingressPoolID), ServicePortRanges: settings.servicePortRanges.Ranges(),
		RequireProxyHeader: settings.requireProxyHeader, TrustedProxyPeers: settings.trustedProxyPeers, MaxConnections: publicCapacity,
		Traffic: settings.traffic, Pending: settings.pending,
		MaxClientHelloConnections: settings.clientHelloConnectionLimit,
		MaxControlConnections:     settings.standaloneControlConnectionLimit,
		MaxRelayConnections:       settings.standaloneRelayConnectionLimit,
		Metrics:                   metrics, Observer: metrics,
		OnError: func(err error) {
			d.reportOperationalError(ctx, "serve ingress connection", failure.ServerIngressFailed, err)
		},
	}
	if recovery != nil {
		ingressConfig.ObserveRecovery = recovery.Observe
	}
	if runtimeConfig.configure != nil {
		runtimeConfig.configure(&ingressConfig)
	}
	ingressConfig.AuditSink = runtime.audit
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
	metrics.RegisterIngressServiceRouting(server.RoutingObservedAt)
	if metrics != nil {
		for resource, limit := range map[string]int64{
			"source_connections":          int64(ingressConfig.Traffic.SourceConnections),
			"source_connection_rate":      int64(ingressConfig.Traffic.SourceRate),
			"process_connection_rate":     int64(ingressConfig.Traffic.ProcessRate),
			"denied_connections":          int64(ingressConfig.Pending.Connections),
			"pending_service_connections": int64(ingressConfig.Pending.ServiceConnections),
			"pending_source_connections":  int64(ingressConfig.Pending.SourceConnections),
		} {
			metrics.SetCapacityLimit(resource, limit)
		}
	}
	d.publishIngressRuntime(runtime)
	owned = true
	d.start("run ingress control", func() error { return controller.Run(ctx) })
	d.start("refresh service routing", func() error { return server.RefreshServices(ctx) })
	d.start("serve public ingress", server.Serve)
	log.Printf("public ingress listening on %s", runtimeConfig.listener.Addr())
	return nil
}

func newIngressControlClient(endpoint, clusterSecret string, base *http.Client, dialAddress string) (*ingressRuntimeClient, error) {
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
