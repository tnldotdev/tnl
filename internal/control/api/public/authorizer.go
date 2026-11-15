package public

import (
	"context"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability/operatorlog"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type localAuthorizer struct {
	store AuthorizationStore
}

type publicURLReadPrincipal struct {
	controlPrincipal controlstate.ControlPrincipal
	identityID       string
	displayName      string
	teamIDs          map[string]struct{}
	administrator    bool
}

type publicURLAuthorizer interface {
	AuthorizePublicURLReads(context.Context, string) (publicURLReadPrincipal, error)
}

func (a localAuthorizer) AuthorizePublicURLReads(ctx context.Context, accessToken string) (publicURLReadPrincipal, error) {
	principal, err := a.store.AuthenticateAccessToken(
		ctx, credentials.AccessToken(accessToken), time.Now(),
	)
	if errors.Is(err, controlstate.ErrControlAuthentication) {
		return publicURLReadPrincipal{}, authorization.ErrUnauthenticated
	}
	if err != nil {
		return publicURLReadPrincipal{}, errors.Join(authorization.ErrUnavailable, err)
	}
	identity, err := a.store.IdentityContext(ctx, principal.IdentityID)
	if err != nil {
		return publicURLReadPrincipal{}, authorization.ErrUnavailable
	}
	teamIDs := make(map[string]struct{}, len(identity.Memberships))
	for _, membership := range identity.Memberships {
		if err := a.store.AuthorizeTeamSession(ctx, principal, membership.TeamID, time.Now()); err != nil {
			if errors.Is(err, controlstate.ErrAuthorityAccess) {
				continue
			}
			return publicURLReadPrincipal{}, errors.Join(authorization.ErrUnavailable, err)
		}
		teamIDs[membership.TeamID] = struct{}{}
	}
	return publicURLReadPrincipal{
		identityID: principal.IdentityID, displayName: identity.Identity.DisplayName, teamIDs: teamIDs, administrator: principal.Administrator, controlPrincipal: principal,
	}, nil
}

func (h *handler) authorizeReads(
	response http.ResponseWriter,
	request *http.Request,
) (publicURLReadPrincipal, bool) {
	token, ok := requestBearerToken(request)
	if !ok {
		writeBearerProblem(response)
		return publicURLReadPrincipal{}, false
	}
	if h.authorizer == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "authorization is unavailable")
		return publicURLReadPrincipal{}, false
	}
	principal, err := h.authorizer.AuthorizePublicURLReads(request.Context(), token)
	switch {
	case errors.Is(err, authorization.ErrUnauthenticated):
		writeBearerProblem(response)
	case errors.Is(err, authorization.ErrForbidden):
		writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "operation is not authorized")
	case err != nil:
		requestID := writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "authorization is unavailable")
		operatorlog.Report("authorize control session", failure.ServerAPIInternal, requestID, err)
	default:
		*request = *request.WithContext(controlstate.WithControlPrincipal(request.Context(), principal.controlPrincipal))
		return principal, true
	}
	return publicURLReadPrincipal{}, false
}
