package tnldruntime

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
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
	visitorConnectionLimit           int64
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
		visitorConnectionLimit:           cfg.VisitorConnectionLimit,
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
	runID, err := opaqueid.New(opaqueid.IngressRunPrefix)
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
	metrics.RegisterIngressLease(func() time.Time { return controller.Lease().LeaseExpiresAt })
	usage, err := ingress.NewUsageReporter(controller, 0, func(err error) {
		logOperationalError("report ingress usage", failure.ServerWorkerFailed, err)
	})
	if err != nil {
		return err
	}
	usage.SetObserver(metrics)
	runtime.usage = usage
	recovery, err := ingress.NewRecoveryReporter(ctx, controller, settings.controlRetryInterval, func(err error) {
		logOperationalError("report ingress recovery", failure.ServerWorkerFailed, err)
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
		Lookup: func(hostname string) (ingress.PublicURL, string) {
			entry, reason := controller.LookupWithReason(hostname, time.Now())
			if reason != "" {
				return ingress.PublicURL{}, reason
			}
			route, err := forwarder.PublicURL(entry)
			if err != nil {
				logOperationalError("read ingress public URL", failure.ServerIngressFailed, err)
				return ingress.PublicURL{}, "invalid_projection"
			}
			return route, ""
		},
		LookupChallenge: func(hostname string) ([]routebackend.Backend, string) {
			entry, reason := controller.LookupChallengeWithReason(hostname, time.Now())
			if reason != "" {
				return nil, reason
			}
			backends, err := forwarder.Backends(entry)
			if err != nil {
				logOperationalError("read ingress certificate challenge", failure.ServerIngressFailed, err)
				return nil, "invalid_projection"
			}
			return backends, ""
		},
		RequireProxyHeader: settings.requireProxyHeader, MaxConnections: publicCapacity,
		MaxClientHelloConnections:       settings.clientHelloConnectionLimit,
		MaxChallengeConnections:         settings.challengeConnectionLimit,
		MaxHostnameChallengeConnections: settings.challengeHostnameConnectionLimit,
		MaxControlConnections:           settings.standaloneControlConnectionLimit,
		MaxRelayConnections:             settings.standaloneRelayConnectionLimit,
		Metrics:                         metrics, Observer: metrics,
		OpenUsage:       usage.Open,
		ObserveRecovery: recovery.Observe,
		OnError:         func(err error) { logOperationalError("serve ingress connection", failure.ServerIngressFailed, err) },
		OnForwardingFailure: func(publicURLID string, version uint64, visitorID, reason string, attempts int) {
			log.Printf("ingress forwarding failed public_url_id=%s publish_run_number=%d visitor_connection_id=%s reason=%s available_backends=%d",
				publicURLID, version, visitorID, reason, attempts)
		},
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
	d.start("run ingress control", func() error { return controller.Run(ctx) })
	d.start("report ingress usage", func() error { return usage.Run(ctx) })
	d.start("serve public ingress", server.Serve)
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
