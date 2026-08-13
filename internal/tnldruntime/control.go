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
		Mode:                    string(cfg.Mode),
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
) (*http.ServeMux, error) {
	controlConfig := controlAPIConfigFrom(cfg, httpClient)
	controlConfig.StartedAt = startedAt
	controlConfig.Metrics = metrics
	mux := controlapi.NewHandler(
		controlConfig, database, database, database.Readiness,
	)
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
		authorityapi.Register(mux, authorityAPIConfigFrom(cfg, verifier), database)
	}
	return mux, nil
}

func (d *daemon) startControl(listenAddress string, handler http.Handler) error {
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return fmt.Errorf("listen for control API: %w", err)
	}
	d.controlListener = listener
	d.controlServer = controlHTTPServer(handler, d.controlTLS)
	d.forward("serve control API", serveTLS(d.controlServer, listener))
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

func (d *daemon) startPrivateControlAPIs(_ context.Context, settings privateControlSettings) error {
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
			ingressHandler.ServeHTTP(response, request)
		case strings.HasPrefix(request.URL.Path, "/internal/v1/relays/"),
			strings.HasPrefix(request.URL.Path, "/internal/v1/relay-services/"),
			strings.HasPrefix(request.URL.Path, "/internal/v1/publisher-connections/"):
			relayHandler.ServeHTTP(response, request)
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
	d.forward("serve private control API", serveTLS(d.privateControlServer, listener))
	log.Printf("private control API listening on %s", listener.Addr())
	return nil
}

func controlHTTPServer(handler http.Handler, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Handler: handler, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
	}
}

func serveTLS(server *http.Server, listener net.Listener) <-chan error {
	return runAsync(func() error {
		err := server.ServeTLS(listener, "", "")
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	})
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
