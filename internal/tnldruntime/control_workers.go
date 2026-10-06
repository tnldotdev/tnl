package tnldruntime

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/tnldotdev/tnl/internal/certificates"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/dnscontroller"
	"github.com/tnldotdev/tnl/internal/emaildelivery"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publicurlusageworker"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
)

// startControlWorkers opens control's durable state and starts its background
// work. all started workers are joined by daemon.shutdown, including when a
// later initialization step fails.
func (d *daemon) startControlWorkers(
	ctx, lifetime context.Context,
	cfg tnldconfig.Config,
	acmeHTTPClient *http.Client,
	metrics *observability.Metrics,
) error {
	database, err := controlstate.Open(ctx, cfg.DatabaseURL, cfg.StorageKey, cfg.StorageKeyPrevious)
	if err != nil {
		return err
	}
	d.database = database
	database.Instrument(metrics)
	metrics.RegisterDatabase(database.PrometheusMetrics)
	d.start("expire saved publish runs", func() error {
		return runExpiredPublishRunCleanup(lifetime, database, metrics)
	})
	d.start("clean up ephemeral public URLs", func() error {
		return runEphemeralPublicURLCleanup(lifetime, database, metrics)
	})
	d.start("forget expired guest credentials", func() error {
		return runGuestPrivateStateCleanup(lifetime, database, metrics)
	})
	d.start("clean up routing history", func() error {
		return runRoutingHistoryCleanup(lifetime, database, metrics)
	})
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
		Observer: metrics,
	}
	if cfg.DNSProviderEnabled() {
		awsConfig, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Route53Region))
		if err != nil {
			return fmt.Errorf("load Route 53 configuration: %w", err)
		}
		d.route53Credentials = awsConfig.Credentials
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
			manager, err := dnscontroller.NewRelayChallengeManager(
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
		for index := range cfg.PublicURLCertificateWorkers {
			publicURLWorkerID, err := opaqueid.New(opaqueid.PublicURLCertificateWorkerPrefix)
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
			d.start(fmt.Sprintf("run public URL certificate worker %d", index+1), func() error {
				return publicURLWorker.Run(lifetime)
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
		d.controlTLS, d.controlTLSManager, err = controlTLSConfig(controlTLSSettingsFrom(cfg), database, account, acmeHTTPClient)
		if err != nil {
			return err
		}
	}
	if cfg.PublicURLUsageURL != "" {
		workerID, err := opaqueid.New(opaqueid.PublicURLUsageWorkerPrefix)
		if err != nil {
			return fmt.Errorf("create public URL usage worker identity: %w", err)
		}
		worker, err := publicurlusageworker.New(database, publicurlusageworker.Config{
			WorkerID: workerID, Endpoint: cfg.PublicURLUsageURL, Token: cfg.PublicURLUsageToken,
			Observer: metrics,
		})
		if err != nil {
			return err
		}
		d.start("run public URL usage worker", func() error { return worker.Run(lifetime) })
	}
	if cfg.EmailURL != "" {
		worker, err := emaildelivery.New(database, cfg.EmailURL, cfg.EmailToken, nil)
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
		worker, err := dnscontroller.New(database, dnsProvider, dnsVerifier, dnsConfig)
		if err != nil {
			return err
		}
		d.start("run DNS controller", func() error { return worker.Run(lifetime) })
	}
	d.registerControlCertificateMetrics(metrics)
	return nil
}

func (d *daemon) registerControlCertificateMetrics(metrics *observability.Metrics) {
	if d.controlTLSManager != nil {
		metrics.RegisterControlCertificate(d.controlTLSManager.EarliestCertificateExpiry)
		return
	}
	if expires, found := firstCertificateExpiry(d.controlTLS); found {
		metrics.RegisterControlCertificate(func() time.Time { return expires })
	}
}
