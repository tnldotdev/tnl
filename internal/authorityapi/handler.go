package authorityapi

import (
	"context"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/oidcauth"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

// Config contains settings for the built-in authority API.
type Config struct {
	ManagedDeploymentDomain string
	LoginToken              string
	AccessTokenLifetime     time.Duration
	RefreshTokenLifetime    time.Duration
	DNSAutomation           bool
	OIDCVerifier            oidcauth.Verifier
}

// Store is the durable authority state consumed by the built-in authority API.
type Store interface {
	CreateBuiltinControlSession(context.Context, string, int64, time.Duration, time.Duration, time.Time) (controlstate.ControlSession, error)
	CreateOIDCControlSession(context.Context, string, controlstate.OIDCIdentity, time.Duration, time.Duration, time.Time) (controlstate.ControlSession, error)
	RefreshControlSession(context.Context, credentials.RefreshToken, int64, time.Duration, time.Time) (controlstate.ControlSession, error)
	RevokeControlSession(context.Context, controlstate.ControlPrincipal, time.Time) error
	AuthenticateAccessToken(context.Context, credentials.AccessToken, int64, time.Time) (controlstate.ControlPrincipal, error)
	IdentityContext(context.Context, string) (controlstate.IdentityContext, error)
	ListTeams(context.Context, string) ([]controlstate.Team, error)
	CreateTeam(context.Context, controlstate.CreateTeamRequest, time.Time) (controlstate.Team, error)
	GetTeam(context.Context, string, string) (controlstate.Team, error)
	ListTeamMemberships(context.Context, string, string) ([]controlstate.Membership, error)
	SetMembershipRole(context.Context, string, string, string, string, time.Time) (controlstate.Membership, error)
	RemoveMembership(context.Context, string, string, string, time.Time) error
	ListTeamInvitations(context.Context, string, string, time.Time) ([]controlstate.Invitation, error)
	CreateTeamInvitation(context.Context, controlstate.CreateInvitationRequest, time.Time) (controlstate.InvitationSecret, error)
	RevokeTeamInvitation(context.Context, string, string, string, time.Time) error
	AcceptInvitation(context.Context, string, credentials.InvitationToken, time.Time) (controlstate.Membership, error)
	ListTeamDomains(context.Context, string, string) ([]controlstate.Domain, error)
	ClaimTeamDomain(context.Context, controlstate.ClaimDomainRequest, time.Time) (controlstate.Domain, error)
	SetTeamDefaultDomain(context.Context, string, string, string, time.Time) (controlstate.Team, error)
	ReleaseTeamDomain(context.Context, string, string, string, time.Time) error
}

type handler struct {
	config              Config
	store               Store
	loginVerifier       credentials.LoginVerifier
	loginSourceRevision int64
}

var _ authorityv1.ServerInterface = (*handler)(nil)

// Register adds the built-in authority API routes to mux.
func Register(mux *http.ServeMux, cfg Config, store Store) {
	h := &handler{config: cfg, store: store}
	if cfg.LoginToken != "" {
		h.loginVerifier, _ = credentials.ParseLoginToken(credentials.LoginToken(cfg.LoginToken))
		h.loginSourceRevision = h.loginVerifier.SourceRevision()
	}
	parameterError := func(response http.ResponseWriter, _ *http.Request, _ error) {
		writeProblem(response, http.StatusBadRequest, authorityv1.InvalidRequest, "invalid request")
	}
	authorityv1.HandlerWithOptions(h, authorityv1.StdHTTPServerOptions{
		BaseRouter: mux, ErrorHandlerFunc: parameterError,
	})
}

// NewHandler constructs a standalone HTTP handler for the built-in authority API.
func NewHandler(cfg Config, store Store) *http.ServeMux {
	mux := http.NewServeMux()
	Register(mux, cfg, store)
	mux.HandleFunc("/", notFound)
	return mux
}

// AuthorizeServiceOperation belongs to the external hosted authority and is
// deliberately absent from the built-in authority implementation.
func (h *handler) AuthorizeServiceOperation(response http.ResponseWriter, _ *http.Request) {
	notFound(response, nil)
}
