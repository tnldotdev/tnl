package controlapi

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/netip"
	"time"

	authorityclient "github.com/tnldotdev/tnl/internal/client/authority"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type VisitorStore interface {
	HTTPVisitorPermission(context.Context, controlstate.PublishRunAuthentication, controlstate.HTTPVisitorRequest, time.Time) (controlstate.VisitorPermission, error)
	CreateTeamVisitorGrant(context.Context, string, string, string, *time.Time, time.Time) (controlstate.VisitorGrant, error)
	CreateIdentityVisitorGrant(context.Context, string, string, string, string, *time.Time, time.Time) (controlstate.VisitorGrant, error)
	ListVisitorGrants(context.Context, string, string) ([]controlstate.VisitorGrant, error)
	RevokeVisitorGrant(context.Context, string, string, string, time.Time) error
	CreateVisitorInvitation(context.Context, string, string, string, string, [32]byte, time.Time, time.Time) (controlstate.VisitorInvitation, error)
	ListVisitorInvitations(context.Context, string, string) ([]controlstate.VisitorInvitation, error)
	RevokeVisitorInvitation(context.Context, string, string, string, time.Time) error
	AcceptVisitorInvitation(context.Context, string, string, time.Time) (controlstate.VisitorGrant, error)
	ListAvailablePublicURLs(context.Context, string, string, string, time.Time) (controlstate.AvailablePublicURLPage, error)
	ReplaceVisitorAccess(context.Context, string, string, controlstate.VisitorAccessMode, []string, uint64, time.Time) (controlstate.PublicURL, error)
}

func (h *handler) AuthorizeHTTPVisitor(w http.ResponseWriter, r *http.Request, runID controlv1.PublishRunID) {
	if h.visitorState == nil {
		writeProblem(w, 503, controlv1.Unavailable, "visitor permissions are unavailable")
		return
	}
	var body controlv1.HTTPVisitorRequest
	if decodeJSON(w, r, &body) != nil || body.PublishRunNumber < 1 || !validVisitorSource(body.SourceIp) {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid visitor decision")
		return
	}
	auth, ok := h.authenticatePublishRunRequest(w, r, runID, uint64(body.PublishRunNumber))
	if !ok {
		return
	}
	input := controlstate.HTTPVisitorRequest{SourceIP: body.SourceIp, BrowserCookieSecret: optionalFeedbackString(body.BrowserCookieSecret), ShareID: optionalFeedbackString(body.ShareId)}
	if body.BrowserCookieSecret != nil {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(*body.BrowserCookieSecret)
		if err != nil || len(raw) != 32 {
			writeProblem(w, 403, controlv1.Forbidden, "invalid browser credential")
			return
		}
	}
	if body.ShareId != nil || body.ShareSecret != nil || body.ShareCookieSecret != nil {
		if body.ShareId == nil || !opaqueid.Valid(*body.ShareId, opaqueid.SharePrefix) || (body.ShareSecret == nil) == (body.ShareCookieSecret == nil) {
			writeProblem(w, 403, controlv1.Forbidden, "invalid share credential")
			return
		}
	}
	if body.ShareSecret != nil {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(*body.ShareSecret)
		if err != nil || len(raw) != 32 {
			writeProblem(w, 403, controlv1.Forbidden, "invalid share secret")
			return
		}
		input.ShareSecret = raw
	}
	if body.ShareCookieSecret != nil {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(*body.ShareCookieSecret)
		if err != nil || len(raw) != 32 {
			writeProblem(w, 403, controlv1.Forbidden, "invalid share cookie")
			return
		}
		input.ShareCookieSecret = raw
	}
	if input.BrowserCookieSecret != "" {
		if h.browserAccess == nil {
			writeProblem(w, 503, controlv1.Unavailable, "browser sign-in is unavailable")
			return
		}
		if _, _, _, err := h.browserSessionAccess(r, auth, input.BrowserCookieSecret); err != nil {
			writeVisitorDecisionProblem(w, "verify visitor identity", err)
			return
		}
	}
	decision, err := h.visitorState.HTTPVisitorPermission(r.Context(), auth, input, time.Now())
	if err != nil {
		writeVisitorDecisionProblem(w, "authorize HTTP visitor", err)
		return
	}
	result := controlv1.HTTPVisitorResponse{VisitAllowed: decision.VisitAllowed, TeamMember: decision.TeamMember}
	observability.AuthorizationDecision(r.Context(), "http_visitor", decision.VisitAllowed)
	if decision.VisitAllowed {
		result.ValidUntil = decision.ExpiresAt
	}
	if decision.IdentityID != "" {
		result.IdentityId = &decision.IdentityID
		result.DisplayName = &decision.DisplayName
	}
	writeJSON(w, 200, result)
}

func (h *handler) visitorActor(w http.ResponseWriter, r *http.Request) (string, bool) {
	if h.visitorState == nil || h.authorizer == nil {
		writeProblem(w, 503, controlv1.Unavailable, "visitor permissions are unavailable")
		return "", false
	}
	actor, ok := h.authorizeRouteReads(w, r)
	if !ok {
		return "", false
	}
	return actor.identityID, true
}
func visitorResult(w http.ResponseWriter, operation string, value any, err error, status int) {
	if err != nil {
		if errors.Is(err, controlstate.ErrShareInvalid) || errors.Is(err, controlstate.ErrShareNotFound) || errors.Is(err, controlstate.ErrShareIdempotency) || errors.Is(err, controlstate.ErrPublicURLInvalid) || errors.Is(err, controlstate.ErrPublicURLMutationStale) {
			writeControlStateProblem(w, operation, err)
		} else {
			writeVisitorDecisionProblem(w, operation, err)
		}
		return
	}
	if status == 204 {
		w.WriteHeader(204)
		return
	}
	writeJSON(w, status, value)
}

func validVisitorSource(value string) bool {
	addr, err := netip.ParseAddr(value)
	return err == nil && addr.Zone() == "" && addr.Unmap().String() == value
}
func writeVisitorDecisionProblem(w http.ResponseWriter, operation string, err error) {
	switch {
	case errors.Is(err, controlstate.ErrVisitorSignIn), errors.Is(err, controlstate.ErrControlAuthentication), errors.Is(err, controlstate.ErrPublishRunCredential), errors.Is(err, authorityclient.ErrUnauthenticated), errors.Is(err, authorization.ErrUnauthenticated):
		writeBearerProblem(w)
	case errors.Is(err, controlstate.ErrPreviewAccess), errors.Is(err, controlstate.ErrFeedbackAccess), errors.Is(err, controlstate.ErrPublishRunStale), errors.Is(err, authorization.ErrForbidden):
		writeProblem(w, 403, controlv1.Forbidden, "visitor permission denied")
	default:
		writeUnavailableProblem(w, failure.Operation(operation), "visitor authorization is unavailable; retry", failure.ServerAuthorityUnavailable, err)
	}
}
func (h *handler) ListAvailablePublicURLs(w http.ResponseWriter, r *http.Request, p controlv1.ListAvailablePublicURLsParams) {
	actor, ok := h.visitorActor(w, r)
	if !ok {
		return
	}
	result, err := h.visitorState.ListAvailablePublicURLs(r.Context(), actor, optionalFeedbackString(p.TeamId), optionalFeedbackString(p.Cursor), time.Now())
	visitorResult(w, "list visitor inventory", result, err, 200)
}
func (h *handler) CreateTeamVisitorGrant(w http.ResponseWriter, r *http.Request, id controlv1.PublicURLID, p controlv1.CreateTeamVisitorGrantParams) {
	actor, ok := h.visitorActor(w, r)
	if !ok {
		return
	}
	var body controlv1.CreateTeamVisitorGrantRequest
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid visitor grant")
		return
	}
	result, err := h.visitorState.CreateTeamVisitorGrant(r.Context(), id, actor, p.IdempotencyKey, body.ExpiresAt, time.Now())
	visitorResult(w, "create team visitor grant", result, err, 201)
}

func (h *handler) CreateIdentityVisitorGrant(w http.ResponseWriter, r *http.Request, id controlv1.PublicURLID, p controlv1.CreateIdentityVisitorGrantParams) {
	actor, ok := h.visitorActor(w, r)
	if !ok {
		return
	}
	var body controlv1.CreateIdentityVisitorGrantRequest
	if decodeJSON(w, r, &body) != nil || body.IdentityId == "" {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid visitor grant")
		return
	}
	result, err := h.visitorState.CreateIdentityVisitorGrant(r.Context(), id, actor, p.IdempotencyKey, body.IdentityId, body.ExpiresAt, time.Now())
	visitorResult(w, "create identity visitor grant", result, err, 201)
}

func (h *handler) ListVisitorGrants(w http.ResponseWriter, r *http.Request, id controlv1.PublicURLID) {
	actor, ok := h.visitorActor(w, r)
	if !ok {
		return
	}
	result, err := h.visitorState.ListVisitorGrants(r.Context(), id, actor)
	visitorResult(w, "list visitor grants", result, err, 200)
}
func (h *handler) RevokeVisitorGrant(w http.ResponseWriter, r *http.Request, id controlv1.PublicURLID, grantID string) {
	actor, ok := h.visitorActor(w, r)
	if !ok {
		return
	}
	err := h.visitorState.RevokeVisitorGrant(r.Context(), id, actor, grantID, time.Now())
	visitorResult(w, "revoke visitor grant", nil, err, 204)
}
func (h *handler) CreateVisitorInvitation(w http.ResponseWriter, r *http.Request, id controlv1.PublicURLID, p controlv1.CreateVisitorInvitationParams) {
	actor, ok := h.visitorActor(w, r)
	if !ok {
		return
	}
	var body controlv1.CreateVisitorInvitationRequest
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid visitor invitation")
		return
	}
	raw, err := hex.DecodeString(body.TokenDigest)
	if err != nil || len(raw) != 32 {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid invitation digest")
		return
	}
	var digest [32]byte
	copy(digest[:], raw)
	result, err := h.visitorState.CreateVisitorInvitation(r.Context(), id, actor, p.IdempotencyKey, body.Email, digest, body.ExpiresAt, time.Now())
	visitorResult(w, "create visitor invitation", result, err, 201)
}
func (h *handler) ListVisitorInvitations(w http.ResponseWriter, r *http.Request, id controlv1.PublicURLID) {
	actor, ok := h.visitorActor(w, r)
	if !ok {
		return
	}
	result, err := h.visitorState.ListVisitorInvitations(r.Context(), id, actor)
	visitorResult(w, "list visitor invitations", result, err, 200)
}
func (h *handler) RevokeVisitorInvitation(w http.ResponseWriter, r *http.Request, id controlv1.PublicURLID, inviteID string) {
	actor, ok := h.visitorActor(w, r)
	if !ok {
		return
	}
	err := h.visitorState.RevokeVisitorInvitation(r.Context(), id, actor, inviteID, time.Now())
	visitorResult(w, "revoke visitor invitation", nil, err, 204)
}
func (h *handler) AcceptVisitorInvitation(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.visitorActor(w, r)
	if !ok {
		return
	}
	var body controlv1.AcceptVisitorInvitationJSONRequestBody
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid visitor invitation")
		return
	}
	result, err := h.visitorState.AcceptVisitorInvitation(r.Context(), actor, body.Secret, time.Now())
	visitorResult(w, "accept visitor invitation", result, err, 200)
}

func (h *handler) ReplaceVisitorAccess(w http.ResponseWriter, r *http.Request, id controlv1.PublicURLID) {
	actor, ok := h.visitorActor(w, r)
	if !ok {
		return
	}
	var body controlv1.ReplaceVisitorAccessRequest
	if decodeJSON(w, r, &body) != nil || body.ExpectedRevision < 1 {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid visitor access policy")
		return
	}
	mode := controlstate.VisitorAccessMode(body.Mode)
	if !mode.Valid() || body.Ip == nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid visitor access policy")
		return
	}
	prefixes, err := authorization.CanonicalizeIPPrefixes(body.Ip)
	if err != nil || len(prefixes) > 256 {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid visitor IP policy")
		return
	}
	result, err := h.visitorState.ReplaceVisitorAccess(r.Context(), id, actor, mode, prefixes, uint64(body.ExpectedRevision), time.Now())
	if err != nil {
		writeControlStateProblem(w, "replace visitor access", err)
		return
	}
	writeJSON(w, http.StatusOK, publicURLResponse(result))
}
