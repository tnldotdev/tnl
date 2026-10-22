package tnldruntime

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	authorityapi "github.com/tnldotdev/tnl/internal/control/api/authority"
	controlapi "github.com/tnldotdev/tnl/internal/control/api/public"
	"github.com/tnldotdev/tnl/internal/control/maintenance"
	oidcauth "github.com/tnldotdev/tnl/internal/control/oidc"
	controlproxy "github.com/tnldotdev/tnl/internal/control/proxy"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	tnldconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/observability"
)

func controlAPIConfigFrom(cfg tnldconfig.Config, httpClient *http.Client) controlapi.Config {
	return controlapi.Config{
		TrafficDefaults:                   cfg.TrafficDefaults(),
		TrafficCeiling:                    cfg.TrafficCeiling(),
		Role:                              cfg.Role,
		ManagedDomain:                     cfg.ManagedDomain,
		ManagedURLMode:                    cfg.ManagedURLMode,
		ManagedDomainMaxMemberChildLabels: cfg.ManagedDomainMaxMemberChildLabels,
		CustomDomainsEnabled:              cfg.CustomDomainsEnabled,
		ControlURL:                        cfg.ControlOrigin(),
		OIDCIssuer:                        cfg.OIDCIssuer,
		OIDCClientID:                      cfg.OIDCClientID,
		OIDCClientSecret:                  cfg.OIDCClientSecret,
		AccessTokenLifetime:               cfg.AccessTokenLifetime,
		RefreshTokenLifetime:              cfg.RefreshTokenLifetime,
		OIDCScopes:                        cfg.EffectiveOIDCScopes(),
		CertificateIssuance:               cfg.ACMEEnabled() && cfg.DNSAutomationEnabled(),
		ACMEDirectoryURL:                  cfg.ACMEDirectoryURL,
		ServerDomain:                      cfg.ServerDomain,
		HTTPClient:                        httpClient,
		DNSAutomation:                     cfg.DNSAutomationEnabled(),
		GuestDemoEnabled:                  cfg.GuestDemoEnabled,
	}
}

func authorityAPIConfigFrom(cfg tnldconfig.Config, httpClient *http.Client) authorityapi.Config {
	return authorityapi.Config{
		ControlURL: cfg.ControlOrigin(),
		OIDCIssuer: cfg.OIDCIssuer, WebServiceSecret: cfg.WebServiceSecret,
		ManagedDomain:        cfg.ManagedDomain,
		CustomDomainsEnabled: cfg.CustomDomainsEnabled,
		OIDCClientID:         cfg.OIDCClientID, OIDCClientSecret: cfg.OIDCClientSecret, OIDCScopes: cfg.EffectiveOIDCScopes(), HTTPClient: httpClient,
		AccessTokenLifetime:  cfg.AccessTokenLifetime,
		RefreshTokenLifetime: cfg.RefreshTokenLifetime,
		DNSAutomation:        cfg.DNSAutomationEnabled(),
		EmailDelivery:        cfg.EmailURL != "",
	}
}

func newPublicAPIHandler(
	cfg tnldconfig.Config,
	startedAt time.Time,
	httpClient *http.Client,
	database *controlstate.Database,
	metrics *observability.Metrics,
	d *daemon,
	route53Readiness func(context.Context) error,
) (http.Handler, error) {
	controlConfig := controlAPIConfigFrom(cfg, httpClient)
	controlConfig.StartedAt = startedAt
	controlConfig.Metrics = metrics
	controlConfig.Route53CredentialsReadiness = route53Readiness
	controlConfig.ControlReadiness = func() error { return d.readyControl(cfg.Role, time.Now()) }
	controlConfig.AcceptingNewWork = func() bool { return !d.draining.Load() }
	if cfg.Role == tnldconfig.RoleStandalone {
		controlConfig.IngressReadiness = func() error { return d.readyIngress(time.Now()) }
		controlConfig.RelayReadiness = func() error { return d.readyRelays(cfg.Role, time.Now()) }
	}
	mux, err := controlapi.NewHandler(
		controlConfig, database, database, database.Readiness,
	)
	if err != nil {
		return nil, err
	}
	var authorityRoutes authorityapi.Routes
	owner := d.ctx
	if owner == nil {
		owner = observability.WithMetrics(context.Background(), metrics)
	}
	seedContext, stopSeeding := context.WithTimeout(owner, 30*time.Second)
	defer stopSeeding()
	if err := database.SeedHumanAuthentication(seedContext, cfg.ManagedDomain, controlstate.HumanAuthenticationSeeds{Issuer: cfg.OIDCIssuer, Administrators: cfg.InitialAdministrators, TeamOwners: cfg.InitialTeamOwners, DefaultTeam: cfg.DefaultTeam, DefaultTeamMembers: cfg.DefaultTeamMembers}, time.Now()); err != nil {
		return nil, err
	}
	admissions, err := oidcauth.LoadAdmissions(cfg.OIDCAdmissionFile)
	if err != nil {
		return nil, err
	}
	if err := database.ConfigureOIDCAdmissions(seedContext, cfg.OIDCIssuer, admissions, time.Now()); err != nil {
		return nil, err
	}
	authorityRoutes, err = authorityapi.Register(mux, authorityAPIConfigFrom(cfg, httpClient), database)
	if err != nil {
		return nil, err
	}
	controlObserved := metrics.APIRequests("control", mux)
	authorityObserved := metrics.APIRequests("authority", mux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if matchedAPIPattern(r, func(candidate *http.Request) string {
			_, pattern := mux.Handler(candidate)
			if authorityRoutes.Matches(pattern) {
				return pattern
			}
			return ""
		}) != "" {
			authorityObserved.ServeHTTP(w, r)
			return
		}
		controlObserved.ServeHTTP(w, r)
	}), nil
}

type controlSettings struct {
	listen   string
	listener net.Listener
	proxy    controlproxy.Config
}

func controlSettingsFrom(cfg tnldconfig.Config) controlSettings {
	return controlSettings{listen: cfg.ControlListen, proxy: cfg.ControlProxy()}
}

func (d *daemon) startControl(settings controlSettings, handler http.Handler) error {
	handler, err := settings.proxy.Handler(handler)
	if err != nil {
		return err
	}
	listener := settings.listener
	if listener == nil {
		listener, err = net.Listen("tcp", settings.listen)
		if err != nil {
			return fmt.Errorf("listen for control API: %w", err)
		}
	}
	d.controlListener = listener
	d.controlServer = controlHTTPServer(handler, nil)
	d.start("serve control API", func() error {
		err := d.controlServer.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	})
	log.Printf("control API listening on %s", listener.Addr())
	return nil
}

// startVisitorPermissionWorkers uses the daemon component lifetime, so expiry
// stops before the database pool is closed during shutdown.
func (d *daemon) startVisitorPermissionWorkers(lifetime context.Context) {
	d.start("expire visitor IP grants", func() error {
		return maintenance.RunVisitorPermissionCleanup(lifetime, d.database)
	})
}
