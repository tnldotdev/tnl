package tnldruntime

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/tnldotdev/tnl/internal/certificates"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/controltls"
	"github.com/tnldotdev/tnl/internal/dnscontroller"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publicurlusageworker"
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
	serviceHTTP            *http.Client
	clusterSecret          string
	clusterSecrets         serviceapi.BearerSecrets
	relayClientTLS         *tls.Config
	cancel                 context.CancelFunc
	done                   chan error
	forwarded              sync.WaitGroup
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
		relayClientTLS: relayClientTLS, cancel: cancel, done: make(chan error, 32), startedAt: time.Now().UTC(),
	}
	defer func() { retErr = errors.Join(retErr, d.shutdown(cfg.DrainTimeout)) }()

	metrics := observability.New(string(cfg.Role))

	if cfg.Role.RunsControl() {
		database, err := controlstate.Open(ctx, cfg.DatabaseURL, cfg.StorageKey, cfg.StorageKeyPrevious)
		if err != nil {
			return err
		}
		d.database = database
		database.Instrument(metrics)
		metrics.RegisterDatabase(database.PrometheusMetrics)
		d.forward("clean up ephemeral routes", runAsync(func() error {
			return runEphemeralRouteCleanup(lifetime, database)
		}))
		d.forward("clean up routing history", runAsync(func() error {
			return runRoutingHistoryCleanup(lifetime, database)
		}))
		if err := database.CompleteStorageKeyRotation(ctx); err != nil {
			return fmt.Errorf("rotate stored secrets: %w", err)
		}
		if cfg.StorageKeyPrevious != "" {
			log.Printf("stored secrets re-encrypted with the current storage key")
		}
		var dnsProvider *dnscontroller.Route53Provider
		var dnsVerifier *dnscontroller.AuthoritativeVerifier
		var routeDNSChallenges certificates.PublicURLDNSChallenges
		var relayDNSChallenges certificates.RelayDNSChallenges
		dnsConfig := dnscontroller.Config{
			ManagedDomain: cfg.ManagedDomain(), ManagedZoneID: cfg.Route53ManagedZoneID,
			IngressIPv4Addresses: cfg.IngressIPv4Addresses, IngressIPv6Addresses: cfg.IngressIPv6Addresses,
		}
		if cfg.DNSProviderEnabled() {
			awsConfig, err := route53AWSConfig(ctx, cfg.Route53Region)
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
				routeDNSChallenges, err = dnscontroller.NewChallengeManager(database, dnsProvider, dnsVerifier, dnsConfig)
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
			account, err = certificates.ReconcileACMEAccount(
				ctx, database, acmeHTTPClient, account, cfg.ACMEAcceptTerms, time.Now(),
			)
			if err != nil {
				return err
			}
			for index := range cfg.PublicURLCertificateWorkers {
				publicURLWorkerID, err := opaqueid.New("public_url_certificate_worker_")
				if err != nil {
					return fmt.Errorf("create public URL certificate worker identity: %w", err)
				}
				publicURLWorker, err := certificates.NewPublicURLWorker(database, certificates.PublicURLConfig{
					WorkerID: publicURLWorkerID, Profile: cfg.ACMEProfile,
					HTTPClient: acmeHTTPClient, DNSChallenges: routeDNSChallenges, Observer: metrics,
				})
				if err != nil {
					return err
				}
				d.forward(fmt.Sprintf("run public URL certificate worker %d", index+1), runAsync(func() error { return publicURLWorker.Run(lifetime) }))
			}
			if relayDNSChallenges != nil {
				relayWorkerID, err := opaqueid.New("relay_certificate_worker_")
				if err != nil {
					return fmt.Errorf("create relay certificate worker identity: %w", err)
				}
				relayWorker, err := certificates.NewRelayWorker(database, certificates.RelayConfig{
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
		if cfg.PublicURLUsageURL != "" {
			workerID, err := opaqueid.New("public_url_usage_worker_")
			if err != nil {
				return fmt.Errorf("create public URL usage worker identity: %w", err)
			}
			worker, err := publicurlusageworker.New(database, publicurlusageworker.Config{
				WorkerID: workerID, Endpoint: cfg.PublicURLUsageURL, Token: cfg.PublicURLUsageToken,
			})
			if err != nil {
				return err
			}
			d.forward("run public URL usage worker", runAsync(func() error { return worker.Run(lifetime) }))
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
		controlHandler, err = newPublicAPIHandler(cfg, d.startedAt, d.serviceHTTP, d.database, metrics)
		if err != nil {
			return err
		}
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
			return d.ready(readyCtx, cfg.Role, time.Now()) == nil
		})
		server, err := observability.Listen(cfg.MetricsListen, withDatabaseDiagnostics(handler, d.database))
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

func (d *daemon) ready(ctx context.Context, role tnldconfig.Role, now time.Time) error {
	if role.RunsControl() {
		if d.database == nil || d.controlServer == nil || d.controlListener == nil {
			return errors.New("control listeners are not ready")
		}
		if role == tnldconfig.RoleControl && (d.privateControlServer == nil || d.privateControlListener == nil) {
			return errors.New("private control listener is not ready")
		}
		if err := d.database.Readiness(ctx); err != nil {
			return err
		}
		if d.controlTLSManager != nil && !d.controlTLSManager.Ready(now) {
			return errors.New("public control certificate is not ready")
		}
	}
	if role.RunsIngress() {
		if len(d.ingresses) != 1 {
			return errors.New("ingress runtime is not ready")
		}
		runtime := d.ingresses[0]
		if runtime.controller == nil || !runtime.controller.Ready(now) || runtime.server == nil || !runtime.server.Ready() {
			return errors.New("ingress lease, routing table, certificate, or listener is not ready")
		}
	}
	if role.RunsRelay() {
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

func runAsync(run func() error) <-chan error {
	done := make(chan error, 1)
	go func() {
		done <- run()
		close(done)
	}()
	return done
}
