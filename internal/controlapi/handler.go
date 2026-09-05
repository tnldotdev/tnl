// Package controlapi serves the public control and authority APIs.
package controlapi

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const (
	publisherLeaseDuration                = 45 * time.Second
	publisherConnectionCredentialDuration = 2 * time.Minute
)

// Store is the durable control state consumed by the public APIs.
type Store interface {
	ListServiceEnrollmentTokens(context.Context) ([]controlstate.ServiceEnrollmentToken, error)
	CreateServiceEnrollmentToken(context.Context, controlstate.CreateServiceEnrollmentTokenRequest) (controlstate.CreatedServiceEnrollmentToken, error)
	RevokeServiceEnrollmentToken(context.Context, string, string, string, time.Time) (controlstate.ServiceEnrollmentToken, error)
	EnrollService(context.Context, controlstate.ServiceEnrollmentRequest) (controlstate.ServiceEnrollment, error)
	CreateBuiltinControlSession(context.Context, string, int64, time.Duration, time.Duration, time.Time) (controlstate.ControlSession, error)
	RefreshControlSession(context.Context, credentials.RefreshToken, int64, time.Duration, time.Time) (controlstate.ControlSession, error)
	RevokeControlSession(context.Context, controlstate.ControlPrincipal, time.Time) error
	AuthenticateAccessToken(context.Context, credentials.AccessToken, int64, time.Time) (controlstate.ControlPrincipal, error)
	IdentityContext(context.Context, string) (controlstate.IdentityContext, error)
	ListTeams(context.Context, string) ([]controlstate.Team, error)
	GetTeam(context.Context, string, string) (controlstate.Team, error)
	ListTeamDomains(context.Context, string, string) ([]controlstate.Domain, error)
	ListRoutes(context.Context, string, string, string) (controlstate.RoutePage, error)
	CreateRoute(context.Context, controlstate.CreateRouteRequest, time.Time) (controlstate.Route, error)
	GetRoute(context.Context, string, string) (controlstate.Route, error)
	DeleteRoute(context.Context, string, string, time.Time) error
	EnsureServiceAuthority(context.Context, time.Time) (controlstate.ServiceAuthority, error)
	CreateRouteSession(context.Context, controlstate.RouteSessionRequest, time.Time, time.Duration, time.Duration) (controlstate.RouteSessionSetup, error)
	RouteSessionAuthentication(context.Context, string, uint64, credentials.SessionToken) (controlstate.RouteSessionAuthentication, error)
	HeartbeatRouteSession(context.Context, controlstate.RouteSessionAuthentication, time.Time, time.Duration, time.Duration) (controlstate.RouteSessionSetup, error)
	MarkRouteCertificateInstalled(context.Context, controlstate.RouteSessionAuthentication, string, time.Time, time.Time) (controlstate.RouteSessionLifecycle, error)
	CreateCertificateIssuance(context.Context, controlstate.CreateCertificateIssuanceRequest, time.Time) (controlstate.CertificateIssuance, error)
	GetCertificateIssuance(context.Context, string, credentials.SessionToken, time.Time) (controlstate.CertificateIssuance, error)
	MarkCertificateChallengeReady(context.Context, string, credentials.SessionToken, time.Time) (controlstate.CertificateIssuance, error)
	MarkCertificateChallengeRemoved(context.Context, string, credentials.SessionToken, time.Time) (controlstate.CertificateIssuance, error)
	MarkRouteSessionReady(context.Context, controlstate.RouteSessionAuthentication, time.Time) (controlstate.RouteSessionLifecycle, error)
	CloseRouteSession(context.Context, string, credentials.SessionToken, time.Time) error
}

type handler struct {
	unavailableControlServer
	unavailableAuthorityServer

	config              config.TNLD
	store               Store
	readiness           func(context.Context) error
	loginVerifier       credentials.LoginVerifier
	loginSourceRevision int64
}

var _ controlv1.ServerInterface = (*handler)(nil)
var _ authorityv1.ServerInterface = (*handler)(nil)

// NewHandler constructs the public APIs. Known but unavailable operations and
// unknown paths retain the control-unavailable response used during rollout.
func NewHandler(cfg config.TNLD, store Store, readiness func(context.Context) error) http.Handler {
	h := &handler{config: cfg, store: store, readiness: readiness}
	if cfg.LoginToken != "" {
		h.loginVerifier, _ = credentials.ParseLoginToken(credentials.LoginToken(cfg.LoginToken))
		h.loginSourceRevision = credentialSourceRevision(cfg.LoginToken)
	}
	mux := http.NewServeMux()
	parameterError := func(response http.ResponseWriter, _ *http.Request, _ error) {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
	}
	controlv1.HandlerWithOptions(h, controlv1.StdHTTPServerOptions{
		BaseRouter: mux, ErrorHandlerFunc: parameterError,
	})
	authorityv1.HandlerWithOptions(h, authorityv1.StdHTTPServerOptions{
		BaseRouter: mux, ErrorHandlerFunc: parameterError,
	})
	mux.HandleFunc("/", unavailable)
	return mux
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

func controlDiscovery(cfg config.TNLD) controlv1.ControlDiscovery {
	result := controlv1.ControlDiscovery{
		ManagedDeploymentDomain: cfg.ManagedDomain(),
		DnsAutomation:           false,
		AuthorityEndpoint:       cfg.AuthorityOrigin(),
		Authentication:          controlv1.AuthenticationFacts{Methods: []controlv1.AuthenticationFactsMethods{}},
	}
	if cfg.LoginToken != "" {
		result.Authentication.Methods = append(result.Authentication.Methods, controlv1.LoginToken)
	}
	if cfg.SignedAuthorizationEnabled() {
		result.AuthorityEndpoint = cfg.AuthorityEndpoint
	}
	if cfg.OIDCEnabled() {
		result.Authentication.Methods = append(result.Authentication.Methods, controlv1.Oidc)
		result.Authentication.Oidc = &controlv1.OIDCAuthenticationFacts{
			Issuer: cfg.OIDCIssuer, ClientId: cfg.OIDCClientID,
			LoginFlow: controlv1.OIDCAuthenticationFactsLoginFlow(cfg.OIDCLoginFlow),
			Scopes:    cfg.EffectiveOIDCScopes(),
		}
	}
	return result
}
