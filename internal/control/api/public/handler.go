// package public adapts control API requests and performs request preflight.
// state owns the transactional authorization and lifecycle changes it requests.
package public

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	"github.com/tnldotdev/tnl/internal/control/oidc"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/control/webhooks"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/serverhttp"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// Config contains the public API settings derived from tnld configuration.
type Config struct {
	TrafficDefaults                   trafficlimits.Limits
	TrafficCeiling                    trafficlimits.Limits
	Role                              controlv1.AdminServerStatusRole
	StartedAt                         time.Time
	ManagedDomain                     string
	ManagedURLMode                    naming.ManagedURLMode
	ManagedDomainMaxMemberChildLabels int
	CustomDomainsEnabled              bool
	ControlURL                        string
	OIDCIssuer                        string
	OIDCClientID                      string
	OIDCClientSecret                  string
	OIDCVerifier                      oidc.Verifier
	WebServiceSecret                  string
	AccessTokenLifetime               time.Duration
	RefreshTokenLifetime              time.Duration
	OIDCScopes                        []string
	CertificateIssuance               bool
	ACMEDirectoryURL                  string
	ServerDomain                      string
	HTTPClient                        *http.Client
	WebhookCatalog                    *webhooks.Catalog
	DNSAutomation                     bool
	GuestDemoEnabled                  bool
	Metrics                           *observability.Metrics
	Route53CredentialsReadiness       func(context.Context) error
	ControlReadiness                  func() error
	AcceptingNewWork                  func() bool
	IngressReadiness                  func() error
	RelayReadiness                    func() error
}

// AdminStore owns administrator operations.
type AdminStore interface {
	AdminRuntimeCounts(context.Context, time.Time) (controlstate.AdminRuntimeCounts, error)
	ListAdminRelayLeases(context.Context, string, time.Time) (controlstate.AdminRelayPage, error)
	BeginAdminRelayDrain(context.Context, controlstate.RelayLeaseIdentity, string, string, time.Time, time.Time) (controlstate.RelayLease, error)
	ListMaintenanceControls(context.Context) ([]controlstate.MaintenanceControl, error)
	SetMaintenanceControl(context.Context, controlstate.MaintenanceControlName, bool, string, string, time.Time) (controlstate.MaintenanceControl, error)
}

type PreviewStore interface {
	ListPreviews(context.Context, string, string, string) (controlstate.PreviewPage, error)
	CreatePreview(context.Context, string, string, string, time.Time) (controlstate.Preview, error)
	GetPreview(context.Context, string) (controlstate.Preview, error)
	AddPreviewService(context.Context, controlstate.AddPreviewServiceRequest, time.Time) (controlstate.Preview, error)
}

type PreviewTeamAccessStore interface {
	SetPreviewTeamAccess(context.Context, controlstate.SetPreviewTeamAccessRequest, time.Time) (controlstate.Preview, error)
}

type BrowserAccessStore interface {
	ConsumeBrowserLogin(context.Context, string, []byte, time.Time) (controlstate.BrowserLoginAttempt, error)
	IssueBrowserHandoff(context.Context, controlstate.BrowserLoginAttempt, controlstate.BrowserAccessSession, time.Time) (controlstate.BrowserHandoff, error)
}

type ShareStore interface {
	CreateShare(context.Context, controlstate.CreateShareRequest, time.Time) (controlstate.Share, error)
	CreateGuestShare(context.Context, controlstate.GuestCredential, string, string, string, [32]byte, time.Time, time.Time) (controlstate.Share, error)
	GetShareForManagement(context.Context, string, string, time.Time) (controlstate.Share, error)
	ResolveCompanyAccount(context.Context, string, string) (string, error)
	ListShares(context.Context, string, string) (controlstate.SharePage, error)
	ListTeamShares(context.Context, string, string, string) (controlstate.SharePage, error)
	RevokeShare(context.Context, string, string, time.Time) (controlstate.Share, error)
}

type ShareAccessStore interface {
	RedeemShare(context.Context, controlstate.ServiceHTTPRun, string, []byte, []byte, time.Time) (controlstate.ShareRedemption, error)
}

type FeedbackStore interface {
	CreateServiceRunPreview(context.Context, controlstate.ServiceHTTPRun, time.Time) (controlstate.Preview, error)
	AuthorizeReviewerFeedback(context.Context, controlstate.ServiceHTTPRun, string, string, controlstate.FeedbackActor, time.Time) (controlv1.FeedbackAuthorization, error)
	AuthorizeImplementerFeedback(context.Context, string, string, string, string, time.Time) (controlv1.FeedbackAuthorization, error)
}

// AuthorizationStore provides current identity and team session authority.
type AuthorizationStore interface {
	AuthenticateAccessToken(context.Context, credentials.AccessToken, time.Time) (controlstate.ControlPrincipal, error)
	AuthorizeTeamSession(context.Context, controlstate.ControlPrincipal, string, time.Time) error
	IdentityContext(context.Context, string) (controlstate.IdentityContext, error)
}

type handler struct {
	dependencies      Stores
	config            Config
	admin             AdminStore
	previews          PreviewStore
	previewTeamAccess PreviewTeamAccessStore
	browserAccess     BrowserAccessStore
	browserOIDC       *oidc.Server
	browserAuthority  *clientauthority.Client
	shares            ShareStore
	shareAccess       ShareAccessStore
	feedback          FeedbackStore
	guests            GuestStore
	readiness         func(context.Context) error
	authorizer        controlSessionAuthorizer
	webhookCatalog    *webhooks.Catalog
	shareWebsiteAuth  serverhttp.BearerSecrets
}

var _ controlv1.ServerInterface = (*handler)(nil)

// NewHandler constructs the control API.
func NewHandler(
	cfg Config,
	stores Stores,
	authorizationStore AuthorizationStore,
	readiness func(context.Context) error,
) (*http.ServeMux, error) {
	if cfg.TrafficDefaults == (trafficlimits.Limits{}) {
		cfg.TrafficDefaults = trafficlimits.Default()
	}
	if cfg.TrafficCeiling == (trafficlimits.Limits{}) {
		cfg.TrafficCeiling = trafficlimits.Ceiling()
	}
	if err := trafficlimits.ValidateDefaults(cfg.TrafficDefaults, cfg.TrafficCeiling); err != nil {
		return nil, err
	}
	cfg.TrafficDefaults.RatePer = cfg.TrafficDefaults.Period()
	cfg.TrafficCeiling.RatePer = cfg.TrafficCeiling.Period()
	h := &handler{dependencies: stores, config: cfg, admin: stores.Admin, readiness: readiness,
		previews: stores.Previews, previewTeamAccess: stores.PreviewTeamAccess,
		browserAccess: stores.BrowserAccess, shares: stores.Shares, shareAccess: stores.ShareAccess,
		feedback: stores.Feedback, guests: stores.Guests}
	if cfg.WebServiceSecret != "" {
		if cfg.OIDCIssuer == "" || cfg.OIDCClientID == "" {
			return nil, errors.New("website share management requires an OIDC issuer and client ID")
		}
		var err error
		h.shareWebsiteAuth, err = serverhttp.NewBearerSecrets(cfg.WebServiceSecret, "")
		if err != nil {
			return nil, err
		}
		if h.config.OIDCVerifier == nil {
			h.config.OIDCVerifier, err = oidc.NewVerifier(oidc.VerifierConfig{Issuer: cfg.OIDCIssuer, ClientID: cfg.OIDCClientID, HTTPClient: cfg.HTTPClient})
			if err != nil {
				return nil, err
			}
		}
	}
	h.webhookCatalog = cfg.WebhookCatalog
	if h.webhookCatalog == nil {
		h.webhookCatalog = webhooks.New(cfg.HTTPClient)
	}
	if h.config.StartedAt.IsZero() {
		h.config.StartedAt = time.Now().UTC()
	}
	if authorizationStore != nil {
		h.authorizer = localAuthorizer{store: authorizationStore}
	}
	if cfg.OIDCClientID != "" {
		var err error
		h.browserOIDC, err = oidc.NewServer(oidc.ServerConfig{
			Issuer: cfg.OIDCIssuer, ClientID: cfg.OIDCClientID, ClientSecret: cfg.OIDCClientSecret, Scopes: cfg.OIDCScopes, RedirectURL: cfg.ControlURL + browserCallbackPath, HTTPClient: cfg.HTTPClient,
		})
		if err != nil {
			return nil, err
		}
	}
	if cfg.ControlURL != "" {
		var err error
		h.browserAuthority, err = clientauthority.New(cfg.ControlURL, cfg.HTTPClient, "")
		if err != nil {
			return nil, err
		}
	}
	mux := http.NewServeMux()
	parameterError := func(response http.ResponseWriter, _ *http.Request, _ error) {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
	}
	controlv1.HandlerWithOptions(h, controlv1.StdHTTPServerOptions{
		BaseRouter: mux, ErrorHandlerFunc: parameterError,
		Middlewares: []controlv1.MiddlewareFunc{publisherRequestSourceMiddleware},
	})
	mux.HandleFunc("/", notFound)
	return mux, nil
}

func (h *handler) GetHealth(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, controlv1.HealthResponse{Status: controlv1.HealthResponseStatusOk})
}

func (h *handler) GetReadiness(response http.ResponseWriter, request *http.Request) {
	readiness := controlv1.ReadinessResponse{Status: controlv1.ReadinessResponseStatusReady}
	readiness.Checks.Database = controlv1.ReadinessResponseChecksDatabaseOk
	ready := true
	if h.readiness == nil || h.readiness(request.Context()) != nil {
		readiness.Checks.Database = controlv1.ReadinessResponseChecksDatabaseFailed
		ready = false
	}
	readiness.Checks.Control = controlv1.ReadinessResponseChecksControlOk
	if h.config.ControlReadiness == nil || h.config.ControlReadiness() != nil {
		readiness.Checks.Control = controlv1.ReadinessResponseChecksControlFailed
		ready = false
	}
	if h.config.IngressReadiness != nil {
		status := controlv1.ReadinessResponseChecksIngressOk
		if h.config.IngressReadiness() != nil {
			status = controlv1.ReadinessResponseChecksIngressFailed
			ready = false
		}
		readiness.Checks.Ingress = &status
	}
	if h.config.RelayReadiness != nil {
		status := controlv1.ReadinessResponseChecksRelayOk
		if h.config.RelayReadiness() != nil {
			status = controlv1.ReadinessResponseChecksRelayFailed
			ready = false
		}
		readiness.Checks.Relay = &status
	}
	if h.config.Route53CredentialsReadiness != nil {
		credentials := controlv1.ReadinessResponseChecksRoute53CredentialsOk
		if h.config.Route53CredentialsReadiness(request.Context()) != nil {
			credentials = controlv1.ReadinessResponseChecksRoute53CredentialsFailed
			ready = false
		}
		readiness.Checks.Route53Credentials = &credentials
	}
	code := http.StatusOK
	if !ready {
		readiness.Status = controlv1.ReadinessResponseStatusNotReady
		code = http.StatusServiceUnavailable
	}
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
	mode := cfg.ManagedURLMode
	if mode == "" {
		mode = naming.ManagedURLModeGenerated
	}
	result := controlv1.ControlDiscovery{
		ManagedDomain:                     cfg.ManagedDomain,
		ManagedUrlMode:                    controlv1.ControlDiscoveryManagedUrlMode(mode),
		ManagedDomainMaxMemberChildLabels: cfg.ManagedDomainMaxMemberChildLabels,
		CustomDomainsEnabled:              cfg.CustomDomainsEnabled,
		DnsAutomation:                     cfg.DNSAutomation,
		GuestDemo:                         cfg.GuestDemoEnabled,
		BrowserLoginAvailable:             new(cfg.OIDCClientID != ""),
		Authentication:                    controlv1.AuthenticationFacts{Methods: []controlv1.AuthenticationFactsMethods{}},
	}
	if cfg.OIDCIssuer != "" {
		result.Authentication.Methods = append(result.Authentication.Methods, controlv1.Oidc)
		result.Authentication.Oidc = &controlv1.OIDCAuthenticationFacts{
			Issuer: cfg.OIDCIssuer, LoginFlow: controlv1.DeviceCode,
		}
	}
	return result
}
