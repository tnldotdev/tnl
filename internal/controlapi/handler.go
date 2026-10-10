// Package controlapi serves the control API and authorizes public URL operations.
package controlapi

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/oidcauth"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
	"github.com/tnldotdev/tnl/internal/webhookcatalog"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const (
	publisherLeaseDuration                = 45 * time.Second
	publisherConnectionCredentialDuration = 2 * time.Minute
)

// Config contains the public API settings derived from tnld configuration.
type Config struct {
	Role                              tnldconfig.Role
	StartedAt                         time.Time
	ManagedDomain                     string
	ManagedURLMode                    naming.ManagedURLMode
	ManagedDomainMaxMemberChildLabels int
	CustomDomainsEnabled              bool
	ControlURL                        string
	LoginToken                        string
	OIDCIssuer                        string
	OIDCClientID                      string
	BrowserOIDCClientID               string
	OIDCLoginFlow                     tnldconfig.OIDCLoginFlow
	OIDCScopes                        []string
	CertificateIssuance               bool
	ACMEDirectoryURL                  string
	ServerDomain                      string
	HTTPClient                        *http.Client
	WebhookCatalog                    *webhookcatalog.Catalog
	DNSAutomation                     bool
	GuestDemoEnabled                  bool
	Metrics                           *observability.Metrics
	Route53CredentialsReadiness       func(context.Context) error
	ControlReadiness                  func() error
	IngressReadiness                  func() error
	RelayReadiness                    func() error
}

// PublicURLStore owns saved public URL and publish run state.
type PublicURLStore interface {
	ListAuthorizedPublicURLs(context.Context, string, string) (controlstate.PublicURLPage, error)
	GetAuthorizedPublicURLByHostname(context.Context, string, string) (controlstate.PublicURL, error)
	CreatePublicURL(context.Context, controlstate.CreatePublicURLRequest, time.Time) (controlstate.PublicURL, error)
	UpdateAuthorizedPublicURL(context.Context, controlstate.AuthorizedPublicURLUpdateRequest, time.Time) (controlstate.PublicURL, error)
	GetPublicURLForAuthorization(context.Context, string) (controlstate.PublicURL, error)
	GetPublicURLForFeedbackAuthorization(context.Context, string) (controlstate.PublicURL, error)
	GetPublicURLForPublishRunAuthorization(context.Context, string, string) (controlstate.PublicURL, error)
	DeleteAuthorizedPublicURL(context.Context, controlstate.AuthorizedPublicURLDeleteRequest, time.Time) error
	CreatePublishRun(context.Context, controlstate.PublishRunRequest, time.Time, time.Duration, time.Duration) (controlstate.PublishRunSetup, error)
	PublishRunAuthentication(context.Context, string, uint64, credentials.PublishRunToken) (controlstate.PublishRunAuthentication, error)
	HeartbeatPublishRun(context.Context, controlstate.PublishRunAuthentication, time.Time, time.Duration, time.Duration) (controlstate.PublishRunSetup, error)
	MarkPublicURLCertificateInstalled(context.Context, controlstate.PublishRunAuthentication, string, time.Time, time.Time) (controlstate.PublishRunLifecycle, error)
	MarkPublishRunReady(context.Context, controlstate.PublishRunAuthentication, time.Time) (controlstate.PublishRunLifecycle, error)
	ClosePublishRun(context.Context, string, credentials.PublishRunToken, time.Time) error
}

type PublicURLPublishCredentialStore interface {
	CreatePublicURLPublishCredential(context.Context, controlstate.CreatePublicURLPublishCredentialRequest) (controlstate.PublicURLPublishCredential, credentials.PublicURLPublishCredential, error)
	CreateEphemeralCredential(context.Context, controlstate.CreateEphemeralCredentialRequest) (controlstate.PublicURLPublishCredential, credentials.EphemeralCredential, error)
	AuthenticateEphemeralCredential(context.Context, credentials.EphemeralCredential, time.Time) (controlstate.PublicURLPublishCredential, error)
	RevokeEphemeralCredential(context.Context, string, string, time.Time) (controlstate.PublicURLPublishCredential, error)
	AuthenticatePublicURLPublishCredential(context.Context, credentials.PublicURLPublishCredential, time.Time) (controlstate.PublicURLPublishCredential, []byte, error)
	ValidatePublicURLPublishCredential(context.Context, controlstate.PublicURLPublishCredential, controlstate.PublicURL) error
	ListPublicURLPublishCredentials(context.Context, string) ([]controlstate.PublicURLPublishCredential, error)
	ListTeamPublicURLPublishCredentials(context.Context, string, string) (controlstate.PublicURLPublishCredentialPage, error)
	PublicURLPublishCredentialByID(context.Context, string) (controlstate.PublicURLPublishCredential, error)
	RevokePublicURLPublishCredential(context.Context, string, string, time.Time) (controlstate.PublicURLPublishCredential, error)
}

// CertificateStore owns publish run certificate issuance state.
type CertificateStore interface {
	CreateCertificateIssuance(context.Context, controlstate.CreateCertificateIssuanceRequest, time.Time) (controlstate.CertificateIssuance, error)
	GetCertificateIssuance(context.Context, string, credentials.PublishRunToken, time.Time) (controlstate.CertificateIssuance, error)
	MarkCertificateChallengeReady(context.Context, string, credentials.PublishRunToken, time.Time) (controlstate.CertificateIssuance, error)
	MarkCertificateChallengeRemoved(context.Context, string, credentials.PublishRunToken, time.Time) (controlstate.CertificateIssuance, error)
}

// AdminStore owns administrator operations.
type AdminStore interface {
	AdminRuntimeCounts(context.Context, time.Time) (controlstate.AdminRuntimeCounts, error)
	ListAdminRelayLeases(context.Context, string, time.Time) (controlstate.AdminRelayPage, error)
	BeginAdminRelayDrain(context.Context, controlstate.RelayLeaseIdentity, string, string, time.Time, time.Time) (controlstate.RelayLease, error)
	ListMaintenanceControls(context.Context) ([]controlstate.MaintenanceControl, error)
	SetMaintenanceControl(context.Context, controlstate.MaintenanceControlName, bool, string, string, time.Time) (controlstate.MaintenanceControl, error)
}

// Store composes the control API's independent state boundaries.
type Store interface {
	PublicURLStore
	CertificateStore
	AdminStore
}

type PreviewStore interface {
	CreatePreview(context.Context, string, string, string, time.Time) (controlstate.Preview, error)
	GetPreview(context.Context, string) (controlstate.Preview, error)
	AddPreviewPublicURL(context.Context, controlstate.AddPreviewPublicURLRequest, time.Time) (controlstate.Preview, error)
}

type PreviewTeamAccessStore interface {
	SetPreviewTeamAccess(context.Context, controlstate.SetPreviewTeamAccessRequest, time.Time) (controlstate.Preview, error)
}

type BrowserAccessStore interface {
	BeginBrowserLogin(context.Context, string, string, string, string, string, []byte, time.Time) (string, error)
	ConsumeBrowserLogin(context.Context, string, []byte, time.Time) (controlstate.BrowserLoginAttempt, error)
	IssueBrowserHandoff(context.Context, controlstate.BrowserLoginAttempt, controlstate.BrowserAccessSession, time.Time) (controlstate.BrowserHandoff, error)
	RedeemBrowserHandoff(context.Context, string, string, time.Time) (string, string, string, bool, time.Time, error)
	BrowserSession(context.Context, string, string, time.Time) (controlstate.BrowserAccessSession, error)
	RotateBrowserSession(context.Context, string, string, string, time.Time) error
	RefreshBrowserSession(context.Context, string, string, time.Time, func(context.Context, string) (controlstate.BrowserTokenRotation, error)) (controlstate.BrowserAccessSession, error)
	RevokeBrowserSession(context.Context, string, string, time.Time) error
}

type ShareStore interface {
	CreateShare(context.Context, controlstate.CreateShareRequest, time.Time) (controlstate.Share, error)
	GetShare(context.Context, string) (controlstate.Share, error)
	ListShares(context.Context, string, string) (controlstate.SharePage, error)
	ListTeamShares(context.Context, string, string, string) (controlstate.SharePage, error)
	RevokeShare(context.Context, string, string, time.Time) (controlstate.Share, error)
}

type ShareAccessStore interface {
	EnableShareAccess(context.Context, controlstate.PublishRunAuthentication, string) error
	PublishRunShareState(context.Context, controlstate.PublishRunAuthentication, time.Time) ([]controlstate.PublisherShare, error)
	RedeemShare(context.Context, controlstate.PublishRunAuthentication, string, []byte, []byte, time.Time) (controlstate.ShareRedemption, error)
}

type FeedbackStore interface {
	ListFeedbackForPublicURL(context.Context, string, string, string, string, string) (controlstate.FeedbackThreadPage, error)
	CreatePublishRunPreview(context.Context, controlstate.PublishRunAuthentication, time.Time) (controlstate.Preview, error)
	CreateFeedback(context.Context, controlstate.PublishRunAuthentication, controlstate.CreateFeedbackRequest, time.Time) (controlstate.FeedbackThread, error)
	AppendFeedback(context.Context, controlstate.AppendFeedbackRequest, time.Time) (controlstate.FeedbackEvent, error)
	GetFeedback(context.Context, string) (controlstate.FeedbackThread, error)
	ListFeedbackForTeam(context.Context, string, string) (controlstate.FeedbackThreadPage, error)
	ListFeedbackForPage(context.Context, string, string, string, string) (controlstate.FeedbackThreadPage, error)
	ListFeedbackEventsForTeam(context.Context, string, uint64) (controlstate.FeedbackEventPage, error)
	ListFeedbackEventsForThread(context.Context, string, uint64) (controlstate.FeedbackEventPage, error)
	ReviewerFeedbackScope(context.Context, controlstate.PublishRunAuthentication, string, controlstate.FeedbackActor, time.Time) (string, string, error)
}

// AuthorizationStore provides the identity state needed for public URL authorization.
type AuthorizationStore interface {
	AuthenticateAccessToken(context.Context, credentials.AccessToken, int64, time.Time) (controlstate.ControlPrincipal, error)
	IdentityContext(context.Context, string) (controlstate.IdentityContext, error)
	ListTeamDomains(context.Context, string, string) ([]controlstate.Domain, error)
}

type handler struct {
	config             Config
	store              PublicURLStore
	publishCredentials PublicURLPublishCredentialStore
	certificates       CertificateStore
	admin              AdminStore
	previews           PreviewStore
	previewTeamAccess  PreviewTeamAccessStore
	browserAccess      BrowserAccessStore
	browserVerifier    oidcauth.Verifier
	browserAuthority   *authorityclient.Client
	shares             ShareStore
	shareAccess        ShareAccessStore
	feedback           FeedbackStore
	guests             interface {
		CreateGuestTrial(context.Context, controlstate.NewGuestTrial, string, time.Time) (string, error)
		GuestTrialByAccessToken(context.Context, credentials.AccessToken) (controlstate.GuestTrial, error)
		GuestOwnsPublicURL(context.Context, string, string) (bool, error)
		GuestSourceMatches(controlstate.GuestTrial, string) (bool, error)
		AllocateGuestDemoNumber(context.Context, string, time.Time) (int64, error)
		GuestIssuanceAllowed(context.Context, netip.Addr, time.Time) error
	}
	readiness      func(context.Context) error
	authorizer     publicURLAuthorizer
	webhookCatalog *webhookcatalog.Catalog
}

var _ controlv1.ServerInterface = (*handler)(nil)

// NewHandler constructs the control API.
func NewHandler(
	cfg Config,
	store Store,
	authorizationStore AuthorizationStore,
	readiness func(context.Context) error,
) (*http.ServeMux, error) {
	h := &handler{config: cfg, store: store, certificates: store, admin: store, readiness: readiness}
	if credentials, ok := store.(PublicURLPublishCredentialStore); ok {
		h.publishCredentials = credentials
	}
	h.webhookCatalog = cfg.WebhookCatalog
	if h.webhookCatalog == nil {
		h.webhookCatalog = webhookcatalog.New(cfg.HTTPClient)
	}
	if previews, ok := store.(PreviewStore); ok {
		h.previews = previews
	}
	if access, ok := store.(PreviewTeamAccessStore); ok {
		h.previewTeamAccess = access
	}
	if access, ok := store.(BrowserAccessStore); ok {
		h.browserAccess = access
	}
	if shares, ok := store.(ShareStore); ok {
		h.shares = shares
	}
	if shareAccess, ok := store.(ShareAccessStore); ok {
		h.shareAccess = shareAccess
	}
	if feedback, ok := store.(FeedbackStore); ok {
		h.feedback = feedback
	}
	if guestStore, ok := store.(interface {
		CreateGuestTrial(context.Context, controlstate.NewGuestTrial, string, time.Time) (string, error)
		GuestTrialByAccessToken(context.Context, credentials.AccessToken) (controlstate.GuestTrial, error)
		GuestOwnsPublicURL(context.Context, string, string) (bool, error)
		GuestSourceMatches(controlstate.GuestTrial, string) (bool, error)
		AllocateGuestDemoNumber(context.Context, string, time.Time) (int64, error)
		GuestIssuanceAllowed(context.Context, netip.Addr, time.Time) error
	}); ok {
		h.guests = guestStore
	}
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
	if authorizationStore != nil {
		h.authorizer = localAuthorizer{
			store: authorizationStore, sourceRevision: loginSourceRevision, dnsAutomation: cfg.DNSAutomation,
			managedDomainMaxMemberChildLabels: cfg.ManagedDomainMaxMemberChildLabels, managedURLMode: cfg.ManagedURLMode,
		}
	}
	if cfg.BrowserOIDCClientID != "" {
		var err error
		h.browserVerifier, err = oidcauth.NewVerifier(oidcauth.VerifierConfig{
			Issuer: cfg.OIDCIssuer, ClientID: cfg.BrowserOIDCClientID, HTTPClient: cfg.HTTPClient,
		})
		if err != nil {
			return nil, err
		}
		h.browserAuthority, err = authorityclient.New(cfg.ControlURL, cfg.HTTPClient, "")
		if err != nil {
			return nil, err
		}
	}
	if cfg.GuestDemoEnabled && h.guests != nil && h.authorizer != nil {
		if guestStore, ok := store.(guestAuthorizationStore); ok {
			h.authorizer = guestAuthorizer{
				fallback: h.authorizer, store: guestStore, managedDomain: cfg.ManagedDomain,
				dnsAutomation: cfg.DNSAutomation,
			}
		}
	}
	mux := http.NewServeMux()
	parameterError := func(response http.ResponseWriter, _ *http.Request, _ error) {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
	}
	controlv1.HandlerWithOptions(h, controlv1.StdHTTPServerOptions{
		BaseRouter: mux, ErrorHandlerFunc: parameterError,
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
		BrowserLoginAvailable:             new(cfg.BrowserOIDCClientID != ""),
		Authentication:                    controlv1.AuthenticationFacts{Methods: []controlv1.AuthenticationFactsMethods{}},
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
