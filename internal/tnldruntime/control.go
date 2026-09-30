package tnldruntime

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityapi"
	"github.com/tnldotdev/tnl/internal/controlapi"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/ingressapi"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/oidcauth"
	"github.com/tnldotdev/tnl/internal/relayapi"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
)

func controlAPIConfigFrom(cfg tnldconfig.Config, httpClient *http.Client) controlapi.Config {
	loginToken := cfg.LoginToken
	if cfg.AuthorityEndpoint != "" {
		loginToken = ""
	}
	return controlapi.Config{
		Role:                    string(cfg.Role),
		ManagedDeploymentDomain: cfg.ManagedDomain(),
		AuthorityEndpoint:       cfg.AuthorityOrigin(),
		LoginToken:              loginToken,
		OIDCIssuer:              cfg.OIDCIssuer,
		OIDCClientID:            cfg.OIDCClientID,
		OIDCLoginFlow:           string(cfg.OIDCLoginFlow),
		OIDCScopes:              cfg.EffectiveOIDCScopes(),
		CertificateIssuance:     cfg.ACMEEnabled(),
		ACMEDirectoryURL:        cfg.ACMEDirectoryURL,
		ServerDomain:            cfg.ServerDomain,
		HostedSecret:            cfg.HostedSecret,
		HostedSecretPrevious:    cfg.HostedSecretPrevious,
		HTTPClient:              httpClient,
		DNSAutomation:           cfg.DNSAutomationEnabled(),
	}
}

func authorityAPIConfigFrom(cfg tnldconfig.Config, verifier oidcauth.Verifier) authorityapi.Config {
	return authorityapi.Config{
		ManagedDeploymentDomain: cfg.ManagedDomain(),
		LoginToken:              cfg.LoginToken,
		AccessTokenLifetime:     cfg.AccessTokenLifetime,
		RefreshTokenLifetime:    cfg.RefreshTokenLifetime,
		DNSAutomation:           cfg.DNSAutomationEnabled(),
		OIDCVerifier:            verifier,
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
	if cfg.AuthorityEndpoint == "" {
		var verifier oidcauth.Verifier
		if cfg.OIDCEnabled() {
			var err error
			verifier, err = oidcauth.NewVerifier(oidcauth.VerifierConfig{
				Issuer: cfg.OIDCIssuer, ClientID: cfg.OIDCClientID, HTTPClient: httpClient,
			})
			if err != nil {
				return nil, err
			}
		}
		if err := authorityapi.Register(mux, authorityAPIConfigFrom(cfg, verifier), database); err != nil {
			return nil, err
		}
	}
	// Classify by fixed API prefixes, never by an identity or path parameter.
	// The router sets r.Pattern for matched routes, including binding errors.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		surface := "control"
		for _, prefix := range []string{"/v1/auth/", "/v1/identity", "/v1/teams", "/v1/invitations/", "/v1/service/authorize"} {
			if strings.HasPrefix(r.URL.Path, prefix) {
				surface = "authority"
				break
			}
		}
		metrics.APIRequests(surface, mux).ServeHTTP(w, r)
	}), nil
}

func (d *daemon) startControl(listenAddress string, requireProxyHeader bool, handler http.Handler) error {
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return fmt.Errorf("listen for control API: %w", err)
	}
	d.controlListener = listener
	d.controlServer = controlHTTPServer(handler, d.controlTLS)
	publicListener := net.Listener(listener)
	if requireProxyHeader {
		publicListener = controlProxyListener{Listener: listener}
	}
	d.start("serve control API", func() error { return serveTLS(d.controlServer, publicListener) })
	log.Printf("control API listening on %s", listener.Addr())
	return nil
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
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch {
		case strings.HasPrefix(request.URL.Path, "/internal/v1/ingresses/"):
			request.Pattern = matchedPrivatePattern(ingressHandler, request)
			metrics.APIRequests("private_ingress", ingressHandler).ServeHTTP(response, request)
		case strings.HasPrefix(request.URL.Path, "/internal/v1/relays/"),
			strings.HasPrefix(request.URL.Path, "/internal/v1/relay-services/"),
			strings.HasPrefix(request.URL.Path, "/internal/v1/publisher-connections/"):
			request.Pattern = matchedPrivatePattern(relayHandler, request)
			metrics.APIRequests("private_relay", relayHandler).ServeHTTP(response, request)
		default:
			serviceapi.WriteProblem(response, http.StatusNotFound, "not_found", "Private control endpoint not found")
		}
	})
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
