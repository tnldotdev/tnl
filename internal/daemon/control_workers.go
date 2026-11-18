package daemon

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/tnldotdev/tnl/internal/control/certificates"
	"github.com/tnldotdev/tnl/internal/control/dns"
	"github.com/tnldotdev/tnl/internal/control/email"
	"github.com/tnldotdev/tnl/internal/control/maintenance"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
)

type dnsBackend interface {
	dns.Provider
	dns.ChallengeProvider
	dns.DNSVerifier
	dns.ChallengeVerifier
}

// startControlWorkers opens control's durable state and starts its background
// work. all started workers are joined by daemon.shutdown, including when a
// later initialization step fails.
func (d *daemon) startControlWorkers(
	ctx, lifetime context.Context,
	cfg daemonconfig.Config,
	acmeHTTPClient *http.Client,
	metrics *observability.Metrics,
) error {
	database, err := controlstate.Open(ctx, cfg.DatabaseURL, cfg.StorageKey, cfg.StorageKeyPrevious, cfg.ManagedURLMode)
	if err != nil {
		return err
	}
	d.database = database
	if err := database.ConfigureControlOutageTolerance(cfg.ControlOutageTolerance); err != nil {
		return err
	}
	if len(cfg.IngressIPv4Addresses) > 1 || len(cfg.IngressIPv6Addresses) > 1 {
		return errors.New("provision primary ingress pool: configure at most one ingress IPv4 and one ingress IPv6 address")
	}
	if len(cfg.IngressIPv4Addresses)+len(cfg.IngressIPv6Addresses) != 0 {
		ipv4, ipv6 := "", ""
		if len(cfg.IngressIPv4Addresses) != 0 {
			ipv4 = cfg.IngressIPv4Addresses[0]
		}
		if len(cfg.IngressIPv6Addresses) != 0 {
			ipv6 = cfg.IngressIPv6Addresses[0]
		}
		if err := database.EnsurePrimaryIngressPool(ctx, ipv4, ipv6, time.Now()); err != nil {
			return fmt.Errorf("provision primary ingress pool: %w", err)
		}
	}
	ports, err := cfg.ServicePortInventory()
	if err != nil {
		return err
	}
	if err = database.ConfigureIngressServicePorts(ctx, controlstate.PrimaryIngressPoolID, ports.Ranges()); err != nil {
		return fmt.Errorf("configure service port inventory: %w", err)
	}
	database.Instrument(metrics)
	metrics.RegisterDatabase(database.PrometheusMetrics)
	d.start("observe service port capacity", func() error { return maintenance.RunPortPoolMetrics(lifetime, database, metrics) })
	d.start("expire service runs", func() error {
		return maintenance.RunServiceRunCleanup(lifetime, database, metrics)
	})
	d.start("clean up connector peer pairs", func() error {
		return maintenance.RunConnectorPeerPairCleanup(lifetime, database, metrics)
	})
	d.start("forget expired guest private state", func() error {
		return maintenance.RunGuestPrivateStateCleanup(lifetime, database, metrics)
	})
	d.start("clean up service audit", func() error { return maintenance.RunServiceAuditCleanup(lifetime, database, metrics) })
	d.start("clean up workload history", func() error { return maintenance.RunWorkloadCleanup(lifetime, database, metrics) })
	if err := database.CompleteStorageKeyRotation(ctx); err != nil {
		return fmt.Errorf("rotate stored secrets: %w", err)
	}
	if cfg.StorageKeyPrevious != "" {
		log.Printf("stored secrets re-encrypted with the current storage key")
	}
	if err := database.PrepareVisitorSigningKeys(ctx, cfg.ControlOrigin(), time.Now()); err != nil {
		return fmt.Errorf("prepare visitor signing keys: %w", err)
	}
	var dnsProvider interface {
		dns.Provider
		dns.ChallengeProvider
	}
	var dnsVerifier interface {
		dns.DNSVerifier
		dns.ChallengeVerifier
	}
	var serviceDNSChallenges certificates.ServiceDNSChallenges
	var relayDNSChallenges certificates.RelayDNSChallenges
	dnsConfig := dns.Config{
		ManagedDomain: cfg.ManagedDomain, ManagedZoneID: cfg.Route53ManagedZoneID,
		IngressIPv4Addresses: cfg.IngressIPv4Addresses, IngressIPv6Addresses: cfg.IngressIPv6Addresses,
		Observer: metrics,
	}
	if cfg.DNSProviderEnabled() {
		if d.dnsBackend != nil {
			dnsProvider, dnsVerifier = d.dnsBackend, d.dnsBackend
		} else {
			awsConfig, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Route53Region))
			if err != nil {
				return fmt.Errorf("load Route 53 configuration: %w", err)
			}
			d.route53Credentials = awsConfig.Credentials
			dnsProvider, err = dns.NewRoute53Provider(route53.NewFromConfig(awsConfig))
			if err != nil {
				return err
			}
			dnsVerifier, err = dns.NewAuthoritativeVerifier(cfg.DNSServer)
			if err != nil {
				return err
			}
		}
		if cfg.DNSAutomationEnabled() {
			serviceDNSChallenges, err = dns.NewChallengeManager(database, dnsProvider, dnsVerifier, dnsConfig)
			if err != nil {
				return err
			}
		}
		if cfg.RelayCertificateAutomationEnabled() {
			manager, err := dns.NewRelayChallengeManager(
				database, dnsProvider, dnsVerifier, cfg.ServerDomain, cfg.Route53ServerZoneID,
			)
			if err != nil {
				return err
			}
			manager.SetObserver(metrics)
			relayDNSChallenges = manager
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
		for index := range cfg.ServiceCertificateWorkers {
			serviceWorkerID, err := opaqueid.New(opaqueid.ServiceCertificateWorkerPrefix)
			if err != nil {
				return fmt.Errorf("create service certificate worker identity: %w", err)
			}
			serviceWorker, err := certificates.NewServiceWorker(database, certificates.ServiceConfig{
				WorkerID: serviceWorkerID, Profile: cfg.ACMEProfile,
				HTTPClient: acmeHTTPClient, DNSChallenges: serviceDNSChallenges, Observer: metrics,
			})
			if err != nil {
				return err
			}
			d.start(fmt.Sprintf("run service certificate worker %d", index+1), func() error {
				return serviceWorker.Run(lifetime)
			})
		}
		if relayDNSChallenges != nil {
			relayWorkerID, err := opaqueid.New(opaqueid.RelayCertificateWorkerPrefix)
			if err != nil {
				return fmt.Errorf("create relay certificate worker identity: %w", err)
			}
			relayWorker, err := certificates.NewRelayWorker(database, certificates.RelayConfig{
				WorkerID: relayWorkerID, AccountID: account.ID, Profile: cfg.ACMEProfile,
				HTTPClient: acmeHTTPClient, DNSChallenges: relayDNSChallenges, Observer: metrics,
			})
			if err != nil {
				return err
			}
			d.start("run relay certificate worker", func() error { return relayWorker.Run(lifetime) })
		}
	}
	if cfg.Role == daemonconfig.RoleControl {
		d.controlTLS, err = staticServerTLS(cfg.ControlTLSCertificateFile, cfg.ControlTLSPrivateKeyFile)
		if err != nil {
			return err
		}
	}
	if cfg.EmailURL != "" {
		worker, err := email.New(database, cfg.EmailURL, cfg.WebhookSecret, nil)
		if err != nil {
			return err
		}
		d.start("run email delivery worker", func() error { return worker.Run(lifetime) })
	}
	if cfg.DNSAutomationEnabled() {
		workerID, err := opaqueid.New(opaqueid.DNSWorkerPrefix)
		if err != nil {
			return fmt.Errorf("create DNS worker identity: %w", err)
		}
		dnsConfig.WorkerID = workerID
		worker, err := dns.New(database, dnsProvider, dnsVerifier, dnsConfig)
		if err != nil {
			return err
		}
		d.start("run DNS controller", func() error { return worker.Run(lifetime) })
	}
	d.registerControlCertificateMetrics(metrics)
	return nil
}

func (d *daemon) registerControlCertificateMetrics(metrics *observability.Metrics) {
	if expires, found := firstCertificateExpiry(d.controlTLS); found {
		metrics.RegisterControlCertificate(func() time.Time { return expires })
	}
}
