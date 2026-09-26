// Package controlapi serves the control API and authorizes route operations.
package controlapi

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const (
	publisherLeaseDuration                = 45 * time.Second
	publisherConnectionCredentialDuration = 2 * time.Minute
)

// Config contains the public API settings derived from tnld configuration.
type Config struct {
	Role                    string
	StartedAt               time.Time
	ManagedDeploymentDomain string
	AuthorityEndpoint       string
	LoginToken              string
	OIDCIssuer              string
	OIDCClientID            string
	OIDCLoginFlow           string
	OIDCScopes              []string
	CertificateIssuance     bool
	ACMEDirectoryURL        string
	ServerDomain            string
	HostedSecret            string
	HostedSecretPrevious    string
	HTTPClient              *http.Client
	DNSAutomation           bool
	Metrics                 *observability.Metrics
}

// Store is the stored state used by the control API.
type Store interface {
	EnsureExternalAuthorityPrincipal(context.Context, string, time.Time) ([32]byte, error)
	ListAuthorizedPublicURLs(context.Context, string, string) (controlstate.PublicURLPage, error)
	GetAuthorizedPublicURLByHostname(context.Context, string, string) (controlstate.PublicURL, error)
	CreatePublicURL(context.Context, controlstate.CreatePublicURLRequest, time.Time) (controlstate.PublicURL, error)
	UpdateAuthorizedPublicURL(context.Context, controlstate.AuthorizedRouteUpdateRequest, time.Time) (controlstate.PublicURL, error)
	GetRouteForAuthorization(context.Context, string) (controlstate.PublicURL, error)
	GetRouteForSessionAuthorization(context.Context, string, string) (controlstate.PublicURL, error)
	DeleteAuthorizedPublicURL(context.Context, controlstate.AuthorizedRouteDeleteRequest, time.Time) error
	CreatePublishRun(context.Context, controlstate.PublishRunRequest, time.Time, time.Duration, time.Duration) (controlstate.PublishRunSetup, error)
	PublishRunAuthentication(context.Context, string, uint64, credentials.PublishRunToken) (controlstate.PublishRunAuthentication, error)
	HeartbeatPublishRun(context.Context, controlstate.PublishRunAuthentication, time.Time, time.Duration, time.Duration) (controlstate.PublishRunSetup, error)
	MarkPublicURLCertificateInstalled(context.Context, controlstate.PublishRunAuthentication, string, time.Time, time.Time) (controlstate.PublishRunLifecycle, error)
	CreateCertificateIssuance(context.Context, controlstate.CreateCertificateIssuanceRequest, time.Time) (controlstate.CertificateIssuance, error)
	GetCertificateIssuance(context.Context, string, credentials.PublishRunToken, time.Time) (controlstate.CertificateIssuance, error)
	MarkCertificateChallengeReady(context.Context, string, credentials.PublishRunToken, time.Time) (controlstate.CertificateIssuance, error)
	MarkCertificateChallengeRemoved(context.Context, string, credentials.PublishRunToken, time.Time) (controlstate.CertificateIssuance, error)
	MarkPublishRunReady(context.Context, controlstate.PublishRunAuthentication, time.Time) (controlstate.PublishRunLifecycle, error)
	ClosePublishRun(context.Context, string, credentials.PublishRunToken, time.Time) error
	ApplyHostedPolicyRevocation(context.Context, string, string, uint64, bool, []string, []string, time.Time) (bool, int, error)
	CreateDNSAuthority(context.Context, controlstate.CreateDNSAuthorityRequest, time.Time) (controlstate.DNSAuthority, error)
	GetDNSAuthority(context.Context, string) (controlstate.DNSAuthority, error)
	ReleaseDNSAuthority(context.Context, string, string, time.Time) (controlstate.DNSAuthority, error)
	AdminRuntimeCounts(context.Context, time.Time) (controlstate.AdminRuntimeCounts, error)
	ListAdminRelayLeases(context.Context, string, time.Time) (controlstate.AdminRelayPage, error)
	BeginAdminRelayDrain(context.Context, controlstate.RelayLeaseIdentity, string, string, time.Time, time.Time) (controlstate.RelayLease, error)
	ListMaintenanceControls(context.Context) ([]controlstate.MaintenanceControl, error)
	SetMaintenanceControl(context.Context, controlstate.MaintenanceControlName, bool, string, string, time.Time) (controlstate.MaintenanceControl, error)
}

// BuiltinAuthorizationStore provides the identity state needed for local public URL authorization.
type BuiltinAuthorizationStore interface {
	AuthenticateAccessToken(context.Context, credentials.AccessToken, int64, time.Time) (controlstate.ControlPrincipal, error)
	IdentityContext(context.Context, string) (controlstate.IdentityContext, error)
	ListTeamDomains(context.Context, string, string) ([]controlstate.Domain, error)
}

type handler struct {
	config        Config
	store         Store
	readiness     func(context.Context) error
	authorizer    publicURLAuthorizer
	hostedSecrets serviceapi.BearerSecrets
}

var _ controlv1.ServerInterface = (*handler)(nil)

// NewHandler constructs the control API.
func NewHandler(
	cfg Config,
	store Store,
	builtinAuthorizationStore BuiltinAuthorizationStore,
	readiness func(context.Context) error,
) (*http.ServeMux, error) {
	h := &handler{config: cfg, store: store, readiness: readiness}
	if h.config.StartedAt.IsZero() {
		h.config.StartedAt = time.Now().UTC()
	}
	loginSourceRevision := int64(0)
	if cfg.LoginToken != "" {
		verifier, err := credentials.ParseLoginToken(credentials.LoginToken(cfg.LoginToken))
		if err != nil {
			return nil, fmt.Errorf("controlapi: configure login token: %w", err)
		}
		loginSourceRevision = verifier.SourceRevision()
	}
	if builtinAuthorizationStore != nil {
		h.authorizer = localAuthorizer{
			store: builtinAuthorizationStore, sourceRevision: loginSourceRevision, dnsAutomation: cfg.DNSAutomation,
		}
	}
	if cfg.HostedSecret != "" || cfg.HostedSecretPrevious != "" {
		var err error
		h.hostedSecrets, err = serviceapi.NewBearerSecrets(cfg.HostedSecret, cfg.HostedSecretPrevious)
		if err != nil {
			return nil, fmt.Errorf("controlapi: configure hosted secret: %w", err)
		}
		client, err := authorityclient.New(cfg.AuthorityEndpoint, cfg.HTTPClient, "")
		if err != nil {
			return nil, fmt.Errorf("controlapi: configure authority client: %w", err)
		}
		if store != nil {
			h.authorizer = hostedAuthorizer{client: client, secret: cfg.HostedSecret, store: store}
		}
	}
	mux := http.NewServeMux()
	parameterError := func(response http.ResponseWriter, _ *http.Request, _ error) {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
	}
	var middleware []controlv1.MiddlewareFunc
	if cfg.Metrics != nil {
		middleware = append(middleware, cfg.Metrics.ControlRequests)
	}
	controlv1.HandlerWithOptions(h, controlv1.StdHTTPServerOptions{
		BaseRouter: mux, ErrorHandlerFunc: parameterError,
		Middlewares: middleware,
	})
	mux.HandleFunc("/", notFound)
	return mux, nil
}

func (h *handler) GetHealth(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, controlv1.HealthResponse{Status: controlv1.HealthResponseStatusOk})
}

func (h *handler) GetReadiness(response http.ResponseWriter, request *http.Request) {
	database := controlv1.ReadinessResponseChecksDatabaseOk
	result := controlv1.ReadinessResponseStatusReady
	code := http.StatusOK
	if h.readiness == nil || h.readiness(request.Context()) != nil {
		database = controlv1.ReadinessResponseChecksDatabaseFailed
		result = controlv1.ReadinessResponseStatusNotReady
		code = http.StatusServiceUnavailable
	}
	readiness := controlv1.ReadinessResponse{Status: result}
	readiness.Checks.Database = database
	writeJSON(response, code, readiness)
}

func (h *handler) GetControlDiscovery(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, controlDiscovery(h.config))
}

func (h *handler) GetClientIP(response http.ResponseWriter, request *http.Request) {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil || net.ParseIP(host) == nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid client address")
		return
	}
	writeJSON(response, http.StatusOK, controlv1.ClientIPResponse{Ip: host})
}

func controlDiscovery(cfg Config) controlv1.ControlDiscovery {
	result := controlv1.ControlDiscovery{
		ManagedDeploymentDomain: cfg.ManagedDeploymentDomain,
		DnsAutomation:           cfg.DNSAutomation,
		AuthorityEndpoint:       cfg.AuthorityEndpoint,
		Authentication:          controlv1.AuthenticationFacts{Methods: []controlv1.AuthenticationFactsMethods{}},
	}
	if cfg.LoginToken != "" {
		result.Authentication.Methods = append(result.Authentication.Methods, controlv1.LoginToken)
	}
	if cfg.OIDCIssuer != "" {
		result.Authentication.Methods = append(result.Authentication.Methods, controlv1.Oidc)
		result.Authentication.Oidc = &controlv1.OIDCAuthenticationFacts{
			Issuer: cfg.OIDCIssuer, ClientId: cfg.OIDCClientID,
			LoginFlow: controlv1.OIDCAuthenticationFactsLoginFlow(cfg.OIDCLoginFlow),
			Scopes:    slices.Clone(cfg.OIDCScopes),
		}
	}
	return result
}
