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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/controltls"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
)

type daemon struct {
	startedAt              time.Time
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
	// Caller cancellation starts graceful shutdown; component contexts remain
	// live until shutdown has drained admitted work or reached its deadline.
	lifetime, cancel := context.WithCancel(context.WithoutCancel(ctx))
	d := &daemon{
		serviceHTTP: serviceHTTPClient, clusterSecret: clusterSecret, clusterSecrets: clusterSecrets,
		relayClientTLS: relayClientTLS, cancel: cancel, componentDone: make(chan error, 1), startedAt: time.Now().UTC(),
	}
	defer func() { retErr = errors.Join(retErr, d.shutdown(cfg.DrainTimeout)) }()

	metrics := observability.New(string(cfg.Role))
	if cfg.Role.RunsIngress() {
		metrics.SetCapacityLimit("client_hello_connections", int64(cfg.ClientHelloConnectionLimit))
		metrics.SetCapacityLimit("challenge_connections", int64(cfg.ChallengeConnectionLimit))
		metrics.SetCapacityLimit("challenge_hostname_connections", int64(cfg.ChallengeHostnameConnectionLimit))
		metrics.SetCapacityLimit("public_connections", cfg.VisitorConnectionLimit)
		metrics.SetCapacityLimit("public_url_connections", max(1, cfg.VisitorConnectionLimit/2))
		metrics.SetCapacityLimit("denied_connections", int64(ingress.DefaultDeniedConnectionLimit))
		metrics.SetCapacityLimit("denied_public_url_connections", int64(max(1, ingress.DefaultDeniedConnectionLimit/2)))
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
	// Reserve the configured observability address before standalone or split
	// roles allocate listeners on port 0. Do not serve it until startup finishes:
	// readiness inspects the role's listeners while they are being assigned.
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
	case tnldconfig.RoleControl:
		if err := d.startControl(cfg.ControlListen, cfg.RequireProxyHeader, controlHandler); err != nil {
			return err
		}
		if err := d.startPrivateControlAPIs(lifetime, privateControlSettingsFrom(cfg), metrics); err != nil {
			return err
		}
	}
	if d.controlTLSManager != nil {
		d.start("manage public control certificate", func() error {
			return d.controlTLSManager.Run(lifetime)
		})
	}
	if metricsListener != nil {
		handler := observability.ProcessHandler(metrics.Handler(), func() bool {
			readyCtx, cancel := context.WithTimeout(lifetime, 2*time.Second)
			defer cancel()
			return d.ready(readyCtx, cfg.Role, time.Now()) == nil
		})
		server := observability.Serve(metricsListener, withDatabaseDiagnostics(handler, d.database))
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
	if d.controlServer == nil || d.controlListener == nil {
		return errors.New("control listener is not ready")
	}
	if role == tnldconfig.RoleControl && (d.privateControlServer == nil || d.privateControlListener == nil) {
		return errors.New("private control listener is not ready")
	}
	if d.controlTLSManager != nil && !d.controlTLSManager.Ready(now) {
		return errors.New("public control certificate is not ready")
	}
	return nil
}

func (d *daemon) readyIngress(now time.Time) error {
	if len(d.ingresses) != 1 {
		return errors.New("ingress runtime is not ready")
	}
	runtime := d.ingresses[0]
	if runtime.controller == nil || !runtime.controller.Ready(now) || runtime.server == nil || !runtime.server.Ready() {
		return errors.New("ingress lease, routing table, certificate, or listener is not ready")
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

// start supervises a component for the process lifetime. Only its first exit
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
