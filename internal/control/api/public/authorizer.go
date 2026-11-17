package public

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/control/oidc"
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

// only canonical share management accepts a website credential and signed actor.
// other control handlers continue to require their ordinary control session.
func (h *handler) authorizeShareRequest(w http.ResponseWriter, r *http.Request, bodyAllowed bool) (controlReadPrincipal, bool) {
	proofs := r.Header.Values("X-Tnl-Actor-Token")
	if len(proofs) == 0 {
		return h.authorizeReads(w, r)
	}
	w.Header().Set("Cache-Control", "no-store")
	if len(proofs) != 1 || proofs[0] == "" || !h.shareWebsiteAuth.Authenticate(r.Header) {
		writeBearerProblem(w)
		return controlReadPrincipal{}, false
	}
	if h.shares == nil || h.config.OIDCVerifier == nil {
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "share authorization is unavailable")
		return controlReadPrincipal{}, false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil || !bodyAllowed && len(raw) != 0 {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid signed share request")
		return controlReadPrincipal{}, false
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	identity, err := h.config.OIDCVerifier.Verify(r.Context(), proofs[0])
	if err != nil {
		if errors.Is(err, oidc.ErrUnavailable) {
			writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "share identity verification is unavailable")
		} else {
			writeBearerProblem(w)
		}
		return controlReadPrincipal{}, false
	}
	target := r.URL.EscapedPath()
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	nonce := controlstate.ServiceActorNonce(r.Method, target, raw)
	if identity.Issuer != h.config.OIDCIssuer || identity.ClientID != h.config.OIDCClientID || identity.Nonce != nonce {
		writeBearerProblem(w)
		return controlReadPrincipal{}, false
	}
	actor, err := h.shares.ResolveCompanyAccount(r.Context(), identity.Issuer, identity.Subject)
	if err != nil {
		if errors.Is(err, controlstate.ErrControlIdentity) || errors.Is(err, controlstate.ErrAuthorityAccess) {
			writeBearerProblem(w)
		} else {
			writeControlStateProblem(r.Context(), w, "resolve share actor", err)
		}
		return controlReadPrincipal{}, false
	}
	verified := controlstate.OIDCIdentity{Issuer: identity.Issuer, Subject: identity.Subject, DisplayName: identity.DisplayName,
		NormalizedEmail: identity.NormalizedEmail, EmailVerified: identity.EmailVerified, AssertionDigest: identity.AssertionDigest,
		AssertionID: identity.AssertionID, AssertionExpiry: identity.ExpiresAt, TeamContexts: identity.TeamContexts, Nonce: identity.Nonce,
		ClientID: identity.ClientID, IssuedAt: identity.IssuedAt, AuthenticatedAt: identity.AuthenticatedAt,
		TenantID: identity.TenantID, HostedDomain: identity.HostedDomain, Groups: identity.Groups}
	*r = *r.WithContext(controlstate.WithServiceActorProof(r.Context(), verified, nonce))
	return controlReadPrincipal{identityID: actor}, true
}

type controlReadPrincipal struct {
	controlPrincipal controlstate.ControlPrincipal
	identityID       string
	displayName      string
	teamIDs          map[string]struct{}
	administrator    bool
}

type controlSessionAuthorizer interface {
	AuthorizeControlReads(context.Context, string) (controlReadPrincipal, error)
}

func (a localAuthorizer) AuthorizeControlReads(ctx context.Context, accessToken string) (controlReadPrincipal, error) {
	principal, err := a.store.AuthenticateAccessToken(
		ctx, credentials.AccessToken(accessToken), time.Now(),
	)
	if errors.Is(err, controlstate.ErrControlAuthentication) {
		return controlReadPrincipal{}, authorization.ErrUnauthenticated
	}
	if err != nil {
		return controlReadPrincipal{}, errors.Join(authorization.ErrUnavailable, err)
	}
	identity, err := a.store.IdentityContext(ctx, principal.IdentityID)
	if err != nil {
		return controlReadPrincipal{}, authorization.ErrUnavailable
	}
	teamIDs := make(map[string]struct{}, len(identity.Memberships))
	for _, membership := range identity.Memberships {
		if err := a.store.AuthorizeTeamSession(ctx, principal, membership.TeamID, time.Now()); err != nil {
			if errors.Is(err, controlstate.ErrAuthorityAccess) {
				continue
			}
			return controlReadPrincipal{}, errors.Join(authorization.ErrUnavailable, err)
		}
		teamIDs[membership.TeamID] = struct{}{}
	}
	return controlReadPrincipal{
		identityID: principal.IdentityID, displayName: identity.Identity.DisplayName, teamIDs: teamIDs, administrator: principal.Administrator, controlPrincipal: principal,
	}, nil
}

func (h *handler) authorizeReads(
	response http.ResponseWriter,
	request *http.Request,
) (controlReadPrincipal, bool) {
	token, ok := requestBearerToken(request)
	if !ok {
		writeBearerProblem(response)
		return controlReadPrincipal{}, false
	}
	if h.authorizer == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "authorization is unavailable")
		return controlReadPrincipal{}, false
	}
	principal, err := h.authorizer.AuthorizeControlReads(request.Context(), token)
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
	return controlReadPrincipal{}, false
}
