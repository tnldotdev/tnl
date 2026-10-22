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
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
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
	return serveWithHTTPClients(
		ctx, cfg, &http.Client{Timeout: 30 * time.Second}, &http.Client{Timeout: 30 * time.Second},
	)
}

func serveWithHTTPClients(
	ctx context.Context,
	cfg tnldconfig.Config,
	acmeHTTPClient, serviceHTTPClient *http.Client,
) (retErr error) {
	return serveWithRelayClientTLS(ctx, cfg, acmeHTTPClient, serviceHTTPClient, nil)
}

func serveWithRelayClientTLS(
	ctx context.Context,
	cfg tnldconfig.Config,
	acmeHTTPClient, serviceHTTPClient *http.Client,
	relayClientTLS *tls.Config,
) (retErr error) {
	return serveWithDNSBackend(ctx, cfg, acmeHTTPClient, serviceHTTPClient, relayClientTLS, nil)
}

func serveWithDNSBackend(ctx context.Context, cfg tnldconfig.Config, acmeHTTPClient, serviceHTTPClient *http.Client, relayClientTLS *tls.Config, dns dnsBackend) (retErr error) {
	if acmeHTTPClient == nil || serviceHTTPClient == nil {
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
		dnsBackend:  dns,
		serviceHTTP: serviceHTTPClient, clusterSecret: clusterSecret, clusterSecrets: clusterSecrets,
		relayClientTLS: relayClientTLS, cancel: cancel, componentDone: make(chan error, 1), startedAt: time.Now().UTC(),
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
		if err := d.startControlWorkers(ctx, lifetime, cfg, acmeHTTPClient, metrics); err != nil {
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
		metricsListener, err = net.Listen("tcp", cfg.MetricsListen)
		if err != nil {
			return fmt.Errorf("listen for observability: %w", err)
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
		settings.transportTLS, err = relayTLSConfig(cfg, nil)
		if err != nil {
			return err
		}
		if err := d.startRelay(lifetime, settings, metrics); err != nil {
			return err
		}
	case tnldconfig.RoleIngress:
		if err := d.startIngress(lifetime, ingressProcessSettingsFrom(cfg), metrics); err != nil {
			return err
		}
	case tnldconfig.RoleStandalone:
		settings := standaloneSettingsFrom(cfg)
		settings.relayTransportTLS, err = relayTLSConfig(cfg, nil)
		if err != nil {
			return err
		}
		if err := d.startStandalone(lifetime, settings, metrics, controlHandler); err != nil {
			return err
		}
	case tnldconfig.RoleControl:
		if err := d.startControl(controlSettingsFrom(cfg), controlHandler); err != nil {
			return err
		}
		if err := d.startPrivateControlAPIs(lifetime, privateControlSettingsFrom(cfg), metrics); err != nil {
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

func (d *daemon) ready(ctx context.Context, role tnldconfig.Role, now time.Time) error {
	if d.draining.Load() {
		return errors.New("process is draining")
	}
	if role.RunsControl() {
		if d.database == nil {
			return errors.New("control database is not ready")
		}
		if err := d.database.Readiness(ctx); err != nil {
			return err
		}
		if err := d.readyControl(role, now); err != nil {
			return err
		}
		if err := d.checkRoute53Credentials(ctx); err != nil {
			return err
		}
	}
	if role.RunsIngress() {
		if err := d.readyIngress(now); err != nil {
			return err
		}
	}
	if role.RunsRelay() {
		if err := d.readyRelays(role, now); err != nil {
			return err
		}
	}
	return nil
}

func (d *daemon) readyControl(role tnldconfig.Role, now time.Time) error {
	if d.draining.Load() {
		return errors.New("control is draining")
	}
	if d.controlServer == nil || d.controlListener == nil {
		return errors.New("control listener is not ready")
	}
	if role == tnldconfig.RoleControl && (d.privateControlServer == nil || d.privateControlListener == nil) {
		return errors.New("private control listener is not ready")
	}
	return nil
}

func (d *daemon) readyIngress(now time.Time) error {
	if len(d.ingresses) < 1 || len(d.ingresses) > 2 {
		return errors.New("ingress runtime is not ready")
	}
	public := 0
	for _, runtime := range d.ingresses {
		if runtime.controller == nil || !runtime.controller.Ready(now) || !runtime.privateOnly && (runtime.server == nil || !runtime.server.Ready()) {
			return errors.New("ingress lease, routing table, certificate, or listener is not ready")
		}
		if runtime.privateCertificate != nil && !runtime.privateCertificate.ready(now) {
			return errors.New("private ingress transport certificate is not ready")
		}
		if !runtime.privateOnly {
			public++
		}
	}
	if public != 1 {
		return errors.New("public ingress listener is not ready")
	}
	return nil
}

func (d *daemon) readyRelays(role tnldconfig.Role, now time.Time) error {
	expected := 1
	if role == tnldconfig.RoleStandalone {
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
	return nil
}

func (d *daemon) checkRoute53Credentials(ctx context.Context) error {
	if d.route53Credentials == nil {
		return nil
	}
	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, err := d.route53Credentials.Retrieve(checkCtx); err != nil {
		return fmt.Errorf("retrieve Route 53 credentials: %w", err)
	}
	return nil
}

func runtimeCapacity(name string, value int64) (int, error) {
	converted := int(value)
	if value <= 0 || int64(converted) != value {
		return 0, fmt.Errorf("%s capacity is out of range", name)
	}
	return converted, nil
}

// start supervises a component for the process lifetime. only its first exit
// determines the result of Serve; shutdown joins every component, including
// those that exit after the result has been selected.
func (d *daemon) start(name string, run func() error) {
	d.components.Go(func() {
		err := run()
		if err != nil {
			err = fmt.Errorf("%s: %w", name, err)
		}
		select {
		case d.componentDone <- err:
		default:
		}
	})
}

// background tracks work that can complete without ending the process, such
// as draining a relay after control updates its lease.
func (d *daemon) background(run func()) {
	d.components.Go(run)
}
