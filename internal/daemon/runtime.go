package tnldruntime

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	tnldconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/serviceapi"
)

type daemon struct {
	ctx                    context.Context
	processRunID           string
	draining               atomic.Bool
	startedAt              time.Time
	database               *controlstate.Database
	dnsBackend             dnsBackend
	metricsServer          *observability.Server
	controlServer          *http.Server
	controlListener        net.Listener
	privateControlServer   *http.Server
	privateControlListener net.Listener
	ingresses              []*ingressRuntime
	ingressLeases          atomic.Pointer[ingressLeaseSnapshot]
	relays                 []*relayRuntime
	controlTLS             *tls.Config
	route53Credentials     aws.CredentialsProvider
	serviceHTTP            *http.Client
	clusterSecret          string
	clusterSecrets         serviceapi.BearerSecrets
	relayClientTLS         *tls.Config
	cancel                 context.CancelFunc
	componentDone          chan error
	components             sync.WaitGroup
}

// Serve runs one configured tnld process until its context is canceled.
func Serve(ctx context.Context, cfg tnldconfig.Config) error {
	ctx, metrics, err := observability.StartProcess(ctx, string(cfg.Role))
	if err != nil {
		return err
	}
	defer func() { _ = metrics.Shutdown(context.Background()) }()
	return serveRuntime(ctx, cfg, runtimeOptions{
		acmeHTTPClient: &http.Client{Timeout: 30 * time.Second}, serviceHTTPClient: &http.Client{Timeout: 30 * time.Second},
	})
}

type runtimeListeners struct {
	control        net.Listener
	privateControl net.Listener
	metrics        net.Listener
	ingress        net.Listener
	relayInternal  net.Listener
	relayTCP       net.Listener
}

type runtimeOptions struct {
	acmeHTTPClient    *http.Client
	serviceHTTPClient *http.Client
	relayClientTLS    *tls.Config
	dns               dnsBackend
	listeners         runtimeListeners
}

func serveRuntime(ctx context.Context, cfg tnldconfig.Config, options runtimeOptions) (retErr error) {
	if options.acmeHTTPClient == nil || options.serviceHTTPClient == nil {
		return errors.New("ACME and service HTTP clients are required")
	}
	clusterSecret := cfg.ClusterSecret
	if cfg.Role == tnldconfig.RoleStandalone {
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
	// caller cancellation starts shutdown. component contexts stay live until
	// admitted work drains or the shutdown deadline expires.
	lifetime, cancel := context.WithCancel(context.WithoutCancel(ctx))
	d := &daemon{
		ctx: lifetime, processRunID: rand.Text(),
		dnsBackend:  options.dns,
		serviceHTTP: options.serviceHTTPClient, clusterSecret: clusterSecret, clusterSecrets: clusterSecrets,
		relayClientTLS: options.relayClientTLS, cancel: cancel, componentDone: make(chan error, 1), startedAt: time.Now().UTC(),
	}
	metrics := observability.FromContext(ctx)
	if metrics == nil {
		metrics = observability.New(string(cfg.Role))
		defer func() { _ = metrics.Shutdown(context.Background()) }()
		ctx = observability.WithMetrics(ctx, metrics)
		lifetime = observability.WithMetrics(lifetime, metrics)
		d.ctx = lifetime
	}
	defer func() { retErr = errors.Join(retErr, d.shutdown(cfg.DrainTimeout)) }()
	if cfg.Role.RunsIngress() {
		metrics.SetCapacityLimit("client_hello_connections", int64(cfg.ClientHelloConnectionLimit))
		metrics.SetCapacityLimit("public_connections", cfg.VisitorConnectionLimit)
		metrics.SetCapacityLimit("public_url_connections", int64(cfg.TrafficDefaults().Connections))
		pending, err := cfg.IngressPending().Resolve()
		if err != nil {
			return err
		}
		metrics.SetCapacityLimit("denied_connections", int64(pending.Connections))
		metrics.SetCapacityLimit("denied_public_url_connections", int64(pending.PublicURLConnections))
	}
	if cfg.Role.RunsRelay() {
		relayCount := int64(1)
		if cfg.Role == tnldconfig.RoleStandalone {
			relayCount = 2
		}
		metrics.SetCapacityLimit("publisher_connections", cfg.PublisherConnectionLimit*relayCount)
		metrics.SetCapacityLimit("relay_streams", cfg.RelayStreamCapacity*relayCount)
	}
	if cfg.Role == tnldconfig.RoleStandalone {
		metrics.SetCapacityLimit("control_connections", int64(cfg.StandaloneControlConnectionLimit))
		metrics.SetCapacityLimit("relay_tcp_connections", int64(cfg.StandaloneRelayConnectionLimit))
	}

	if cfg.Role.RunsControl() {
		if err := d.startControlWorkers(ctx, lifetime, cfg, options.acmeHTTPClient, metrics); err != nil {
			return err
		}
		d.startVisitorPermissionWorkers(lifetime)
	}

	controlHandler := http.Handler(nil)
	if d.database != nil {
		var route53Readiness func(context.Context) error
		if d.route53Credentials != nil {
			route53Readiness = d.checkRoute53Credentials
		}
		controlHandler, err = newPublicAPIHandler(cfg, d.startedAt, d.serviceHTTP, d.database, metrics, d, route53Readiness)
		if err != nil {
			return err
		}
	}
	// reserve the observability address before role listeners allocate port 0.
	// serve it only after startup; readiness reads those listeners during setup.
	var metricsListener net.Listener
	if cfg.MetricsListen != "" {
		metricsListener = options.listeners.metrics
		if metricsListener == nil {
			metricsListener, err = net.Listen("tcp", cfg.MetricsListen)
			if err != nil {
				return fmt.Errorf("listen for observability: %w", err)
			}
		}
		defer func() {
			if metricsListener != nil {
				_ = metricsListener.Close()
			}
		}()
	}

	switch cfg.Role {
	case tnldconfig.RoleRelay:
		settings := relayProcessSettingsFrom(cfg)
		settings.internalListener = options.listeners.relayInternal
		settings.tcpListener = options.listeners.relayTCP
		settings.transportTLS, err = relayTLSConfig(cfg, nil)
		if err != nil {
			return err
		}
		if err := d.startRelay(lifetime, settings, metrics); err != nil {
			return err
		}
	case tnldconfig.RoleIngress:
		settings := ingressProcessSettingsFrom(cfg)
		settings.listener = options.listeners.ingress
		if err := d.startIngress(lifetime, settings, metrics); err != nil {
			return err
		}
	case tnldconfig.RoleStandalone:
		settings := standaloneSettingsFrom(cfg)
		settings.control.listener = options.listeners.control
		settings.publicListener = options.listeners.ingress
		settings.relayTransportTLS, err = relayTLSConfig(cfg, nil)
		if err != nil {
			return err
		}
		if err := d.startStandalone(lifetime, settings, metrics, controlHandler); err != nil {
			return err
		}
	case tnldconfig.RoleControl:
		settings := controlSettingsFrom(cfg)
		settings.listener = options.listeners.control
		if err := d.startControl(settings, controlHandler); err != nil {
			return err
		}
		privateSettings := privateControlSettingsFrom(cfg)
		privateSettings.listener = options.listeners.privateControl
		if err := d.startPrivateControlAPIs(lifetime, privateSettings, metrics); err != nil {
			return err
		}
	}
	if metricsListener != nil {
		handler := observability.ProcessHandler(metrics.Handler(), func() bool {
			readyCtx, cancel := context.WithTimeout(lifetime, 2*time.Second)
			defer cancel()
			return d.ready(readyCtx, cfg.Role, time.Now()) == nil
		})
		server := observability.Serve(metricsListener, d.withRoleDiagnostics(withDatabaseDiagnostics(handler, d.database), cfg.Role))
		metricsListener = nil
		d.metricsServer = server
		d.start("serve observability", func() error { return <-server.Done() })
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-d.componentDone:
		return err
	}
}
