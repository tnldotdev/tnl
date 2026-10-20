package tnldruntime

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityapi"
	"github.com/tnldotdev/tnl/internal/controlapi"
	"github.com/tnldotdev/tnl/internal/controlproxy"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/ingressapi"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/oidcauth"
	"github.com/tnldotdev/tnl/internal/relayapi"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
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

func (d *daemon) startControl(listenAddress string, proxy controlproxy.Config, handler http.Handler) error {
	handler, err := proxy.Handler(handler)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return fmt.Errorf("listen for control API: %w", err)
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

func controlProxyConfig(cfg tnldconfig.Config) controlproxy.Config {
	return cfg.ControlProxy()
}

// startVisitorPermissionWorkers uses the daemon component lifetime, so expiry
// stops before the database pool is closed during shutdown.
func (d *daemon) startVisitorPermissionWorkers(lifetime context.Context) {
	d.start("expire visitor IP grants", func() error {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-lifetime.Done():
				return nil
			case now := <-ticker.C:
				ctx, cancel := context.WithTimeout(lifetime, 10*time.Second)
				err := d.database.ExpireVisitorPermissions(ctx, now)
				if err == nil {
					err = d.database.ExpireDeviceLogins(ctx, now)
				}
				cancel()
				if err != nil && lifetime.Err() == nil {
					log.Print("visitor IP expiry failed; retrying")
				}
			}
		}
	})
}

type privateControlSettings struct {
	ingressLeaseDuration time.Duration
	relayLeaseDuration   time.Duration
	listen               string
}

func privateControlSettingsFrom(cfg tnldconfig.Config) privateControlSettings {
	return privateControlSettings{
		ingressLeaseDuration: cfg.IngressLeaseDuration,
		relayLeaseDuration:   cfg.RelayLeaseDuration,
		listen:               cfg.PrivateControlListen,
	}
}

func (d *daemon) startPrivateControlAPIs(_ context.Context, settings privateControlSettings, metrics *observability.Metrics) error {
	ingressHandler, err := ingressapi.NewHandler(ingressapi.Config{
		Store: d.database, ClusterSecrets: d.clusterSecrets,
		LeaseDuration: settings.ingressLeaseDuration,
	})
	if err != nil {
		return err
	}
	relayHandler, err := relayapi.NewHandler(relayapi.Config{
		Store: d.database, ClusterSecrets: d.clusterSecrets,
		LeaseDuration: settings.relayLeaseDuration,
	})
	if err != nil {
		return err
	}
	handler := privateControlHandler(ingressHandler, relayHandler, metrics)
	listener, err := net.Listen("tcp", settings.listen)
	if err != nil {
		return fmt.Errorf("listen for private control API: %w", err)
	}
	d.privateControlListener = listener
	d.privateControlServer = controlHTTPServer(handler, d.controlTLS)
	d.start("serve private control API", func() error { return serveTLS(d.privateControlServer, listener) })
	log.Printf("private control API listening on %s", listener.Addr())
	return nil
}

func privateControlHandler(ingressHandler, relayHandler http.Handler, metrics *observability.Metrics) http.Handler {
	ingressObserved := metrics.APIRequests("private_ingress", ingressHandler)
	relayObserved := metrics.APIRequests("private_relay", relayHandler)
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		switch {
		case matchedAPIPattern(request, func(candidate *http.Request) string {
			return matchedPrivatePattern(ingressHandler, candidate)
		}) != "":
			request.Pattern = matchedPrivatePattern(ingressHandler, request)
			ingressObserved.ServeHTTP(response, request)
		case matchedAPIPattern(request, func(candidate *http.Request) string {
			return matchedPrivatePattern(relayHandler, candidate)
		}) != "":
			request.Pattern = matchedPrivatePattern(relayHandler, request)
			relayObserved.ServeHTTP(response, request)
		default:
			serviceapi.WriteProblem(response, http.StatusNotFound, "not_found", "Private control endpoint not found")
		}
	})
}

// matchedAPIPattern also probes known HTTP methods when the router reports a
// method mismatch, so the owning API still handles authentication and fallback.
func matchedAPIPattern(request *http.Request, match func(*http.Request) string) string {
	if pattern := match(request); pattern != "" && pattern != "/" {
		return pattern
	}
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if method == request.Method {
			continue
		}
		candidate := *request
		candidate.Method = method
		if pattern := match(&candidate); pattern != "" && pattern != "/" {
			return pattern
		}
	}
	return ""
}

func matchedPrivatePattern(handler http.Handler, request *http.Request) string {
	if matcher, ok := handler.(interface{ MatchedPattern(*http.Request) string }); ok {
		return matcher.MatchedPattern(request)
	}
	return ""
}

func controlHTTPServer(handler http.Handler, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Handler: handler, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 3 * time.Minute,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
		ErrorLog: log.New(io.Discard, "", 0),
	}
}

func serveTLS(server *http.Server, listener net.Listener) error {
	err := server.ServeTLS(listener, "", "")
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func newPrivateServiceHTTPClient(base *http.Client, clusterSecret, dialAddress string) (*http.Client, error) {
	if base == nil || clusterSecret == "" {
		return nil, errors.New("private service HTTP client and cluster secret are required")
	}
	baseTransport := base.Transport
	if baseTransport == nil {
		baseTransport = http.DefaultTransport
	}
	if dialAddress != "" {
		configured, ok := baseTransport.(*http.Transport)
		if !ok {
			return nil, errors.New("private service dial override requires an HTTP transport")
		}
		transport := configured.Clone()
		dialer := new(net.Dialer)
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, dialAddress)
		}
		baseTransport = transport
	}
	client := *base
	client.Transport = serviceBearerRoundTripper{secret: clusterSecret, base: baseTransport}
	client.Timeout = 30 * time.Second
	return &client, nil
}

type serviceBearerRoundTripper struct {
	secret string
	base   http.RoundTripper
}

func (t serviceBearerRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	copy.Header = request.Header.Clone()
	copy.Header.Set("Authorization", "Bearer "+t.secret)
	return t.base.RoundTrip(copy)
}
