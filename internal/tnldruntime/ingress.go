package tnldruntime

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/ingresspool"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/tcpport"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ingressRuntime struct {
	controller         *ingress.Controller
	server             *ingress.Server
	forwarder          *ingress.Forwarder
	usage              *ingress.UsageReporter
	recovery           *ingress.RecoveryReporter
	private            *ingress.PrivateConnector
	privateQUIC        *muxsession.QUICListener
	privateCertificate *ingressCertificateSource
	privateOnly        bool
	audit              *ingressServiceAudit
}

type ingressProcessSettings struct {
	controlEndpoint  string
	controlAddress   string
	clusterSecret    string
	ingressID        string
	listen           string
	runtime          ingressSettings
	privateHostname  string
	privateAddress   string
	privateUDPListen string
}

func ingressProcessSettingsFrom(cfg tnldconfig.Config) ingressProcessSettings {
	domain := strings.TrimPrefix(cfg.ControlHostname, "control.")
	hostname := ""
	if cfg.IngressID != "" && domain != "" {
		hostname = cfg.IngressID + "." + domain
	}
	return ingressProcessSettings{
		controlEndpoint: cfg.PrivateControlEndpoint(), controlAddress: cfg.PrivateControlAddress,
		clusterSecret: cfg.ClusterSecret,
		ingressID:     cfg.IngressID, listen: cfg.IngressListen, runtime: ingressSettingsFrom(cfg),
		privateHostname: hostname, privateAddress: net.JoinHostPort(hostname, "443"),
		privateUDPListen: cfg.IngressUDPListen,
	}
}

func (d *daemon) startIngress(ctx context.Context, settings ingressProcessSettings, metrics *observability.Metrics) error {
	privateClient, err := newIngressControlClient(
		settings.controlEndpoint, settings.clusterSecret, d.serviceHTTP, settings.controlAddress,
	)
	if err != nil {
		return err
	}
	listener, err := listenIngress(settings.listen, settings.runtime.servicePortRanges, settings.runtime.requireProxyHeader)
	if err != nil {
		return fmt.Errorf("listen for public ingress: %w", err)
	}
	if err := d.startIngressRuntime(ctx, settings.runtime, metrics, ingressRuntimeConfig{
		client: privateClient, ingressID: settings.ingressID, listener: listener, clusterSecret: settings.clusterSecret,
		privateHostname: settings.privateHostname, privateAddress: settings.privateAddress,
		privateUDPListen: settings.privateUDPListen,
	}); err != nil {
		_ = listener.Close()
		return err
	}
	return nil
}

type ingressRuntimeConfig struct {
	client             ingress.ControlClient
	ingressID          string
	listener           net.Listener
	clusterSecret      string
	configure          func(*ingress.Config)
	privateHostname    string
	privateAddress     string
	privateUDPListen   string
	disablePrivateQUIC bool
	configurePrivate   func(*ingress.PrivateConnectorConfig)
	privateOnly        bool
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
	servicePortRanges                []tcpport.Range
}

func ingressSettingsFrom(cfg tnldconfig.Config) ingressSettings {
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
	runtime := &ingressRuntime{privateOnly: runtimeConfig.privateOnly}
	auditClient, ok := runtimeConfig.client.(ingressServiceObservationClient)
	if !ok {
		return errors.New("ingress service observation reporting is required")
	}
	runtime.audit = &ingressServiceAudit{ctx: ctx, client: auditClient, metrics: metrics}
	if runtimeConfig.privateOnly && (runtimeConfig.privateHostname == "" || !runtimeConfig.disablePrivateQUIC) {
		return errors.New("logical private ingress requires a hostname and shared listener")
	}
	owned := false
	defer func() {
		if !owned {
			flush, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = runtime.audit.Close(flush)
			cancel()
			if runtime.private != nil {
				_ = runtime.private.Close()
			}
			if runtime.privateQUIC != nil {
				_ = runtime.privateQUIC.Close()
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
	routingTable := new(ingress.RoutingTable)
	var publicServer *ingress.Server
	registration := ingressv1.IngressRegistration{IngressId: runtimeConfig.ingressID, IngressRunId: runID, ProtocolVersion: tunnelv1.Version, ConnectionCapacity: settings.visitorConnectionLimit}
	registration.IngressPoolId, registration.ServicePorts = string(settings.ingressPoolID), tcpport.Ports(settings.servicePortRanges)
	if runtimeConfig.privateHostname != "" {
		registration.PrivateConnectorAddress = &runtimeConfig.privateAddress
		registration.PrivateConnectorTlsServerName = &runtimeConfig.privateHostname
	}
	controller, err := ingress.NewController(ingress.ControllerConfig{
		LeaseEstablished: runtime.audit.bind,
		Client:           runtimeConfig.client, RoutingTable: routingTable,
		Registration:    registration,
		RenewalInterval: settings.leaseRenewalInterval, RetryInterval: settings.controlRetryInterval,
		RoutingWait: settings.routingTableWait, Observer: metrics,
		Load: func() int64 {
			var private int64
			if runtime.private != nil {
				private = runtime.private.Load()
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
	if !runtimeConfig.privateOnly {
		metrics.RegisterIngressRouting(controller.RoutingStatus)
		metrics.RegisterIngressLease(func() time.Time {
			deadline := controller.Lease().LeaseExpiresAt
			for _, other := range d.ingresses {
				if other.controller != nil {
					deadline = minTime(deadline, other.controller.Lease().LeaseExpiresAt)
				}
			}
			return deadline
		})
	}
	var recovery *ingress.RecoveryReporter
	// every ingress lease participates in usage coverage, including an empty
	// private-only identity sharing the public listener. its idle and final
	// watermarks must not hold public URL usage buckets open.
	usage, err := ingress.NewUsageReporter(controller, 0, func(err error) { logOperationalError("report ingress usage", failure.ServerWorkerFailed, err) })
	if err != nil {
		return err
	}
	usage.SetObserver(metrics)
	runtime.usage = usage
	if !runtimeConfig.privateOnly {
		recovery, err = ingress.NewRecoveryReporter(ctx, controller, settings.controlRetryInterval, func(err error) {
			logOperationalError("report ingress recovery", failure.ServerWorkerFailed, err)
		})
		if err != nil {
			return err
		}
		runtime.recovery = recovery
		recovery.SetObserver(metrics)
	}
	forwardingTLS := d.relayClientTLS
	if forwardingTLS == nil {
		forwardingTLS = &tls.Config{MinVersion: tls.VersionTLS13}
	} else {
		forwardingTLS = forwardingTLS.Clone()
		forwardingTLS.MinVersion = tls.VersionTLS13
	}
	forwarder, err := ingress.NewForwarder(ingress.ForwarderConfig{
		TLSConfig: forwardingTLS, ClusterSecret: runtimeConfig.clusterSecret, Observer: metrics,
		OnSessionClosed: func(relayServiceID, relayID, origin string, cause error) {
			logOperationalError("close ingress relay session", failure.ServerConnectionFailed, cause)
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
		Lookup: func(hostname string) (ingress.PublicURL, ingress.LookupReason) {
			entry, reason := controller.LookupWithReason(hostname, time.Now())
			if reason != ingress.LookupCurrent {
				return ingress.PublicURL{}, reason
			}
			route, err := forwarder.PublicURL(entry)
			if err != nil {
				logOperationalError("read ingress public URL", failure.ServerIngressFailed, err)
				return ingress.PublicURL{}, ingress.LookupInvalidProjection
			}
			return route, ingress.LookupCurrent
		},
		RequireProxyHeader: settings.requireProxyHeader, TrustedProxyPeers: settings.trustedProxyPeers, MaxConnections: publicCapacity,
		Traffic: settings.traffic, Pending: settings.pending,
		CurrentTrafficRuns:        routingTable.CurrentTrafficRuns,
		MaxClientHelloConnections: settings.clientHelloConnectionLimit,
		MaxControlConnections:     settings.standaloneControlConnectionLimit,
		MaxRelayConnections:       settings.standaloneRelayConnectionLimit,
		Metrics:                   metrics, Observer: metrics,
		OnError: func(err error) { logOperationalError("serve ingress connection", failure.ServerIngressFailed, err) },
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
	if runtimeConfig.privateHostname != "" {
		privateControl, ok := runtimeConfig.client.(ingress.PrivateControl)
		if !ok {
			return errors.New("private ingress control operations are required")
		}
		certificates, ok := runtimeConfig.client.(ingressCertificateClient)
		if !ok {
			return errors.New("private ingress certificate retrieval is required")
		}
		source := &ingressCertificateSource{id: runtimeConfig.ingressID, hostname: runtimeConfig.privateHostname}
		runtime.privateCertificate = source
		transportTLS := source.TLSConfig()
		d.start("manage ingress transport certificate", func() error {
			return runIngressCertificate(ctx, certificates, controller, source, settings.controlRetryInterval)
		})
		privateConfig := ingress.PrivateConnectorConfig{Hostname: runtimeConfig.privateHostname, TLSConfig: transportTLS, IngressPoolID: string(settings.ingressPoolID),
			Control: privateControl, Forwarder: forwarder, Routing: new(ingress.PrivateRoutingTable), CurrentLease: controller.Lease, AuditSink: runtime.audit}
		privateConfig.DirectControl, _ = runtimeConfig.client.(ingress.DirectControl)
		if runtimeConfig.configurePrivate != nil {
			runtimeConfig.configurePrivate(&privateConfig)
		}
		privateConfig.AuditSink = runtime.audit
		private, err := ingress.NewPrivateConnector(privateConfig)
		if err != nil {
			return err
		}
		runtime.private = private
		ingressConfig.DirectConnector, ingressConfig.ServicePortRanges = private, settings.servicePortRanges
		ingressConfig.PrivateHostname, ingressConfig.PrivateConnector = runtimeConfig.privateHostname, private
		if !runtimeConfig.disablePrivateQUIC {
			address := runtimeConfig.privateUDPListen
			if address == "" {
				address = runtimeConfig.listener.Addr().String()
			}
			listener, err := muxsession.ListenPrivateQUIC(address, private.TransportTLSConfig(), muxsession.QUICConfig{})
			if err != nil {
				_ = private.Close()
				return err
			}
			runtime.privateQUIC = listener
		}
	}
	if runtimeConfig.privateOnly {
		d.ingresses = append(d.ingresses, runtime)
		owned = true
		d.start("run private ingress control", func() error { return controller.Run(ctx) })
		d.start("report private ingress idle coverage", func() error { return usage.Run(ctx) })
		return nil
	}
	ingressConfig.Traffic, ingressConfig.Pending, err = tnldconfig.ValidateIngressTraffic(ingressConfig.Traffic, ingressConfig.Pending)
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
	d.ingresses = append(d.ingresses, runtime)
	owned = true
	d.start("run ingress control", func() error { return controller.Run(ctx) })
	d.start("report ingress usage", func() error { return usage.Run(ctx) })
	d.start("serve public ingress", server.Serve)
	if runtime.privateQUIC != nil {
		d.start("serve private QUIC ingress", func() error { return serveQUICSessions(ctx, runtime.privateQUIC, runtime.private.AcceptQUIC) })
	}
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
	control, err := ingress.NewHTTPControlClient(generated)
	if err != nil {
		return nil, err
	}
	return &ingressRuntimeClient{HTTPControlClient: control, generated: generated}, nil
}
