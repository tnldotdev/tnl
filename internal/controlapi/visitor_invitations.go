package controlapi

import (
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) CreateVisitorInvitation(response http.ResponseWriter, request *http.Request, _ controlv1.CreateVisitorInvitationParams) {
	var body controlv1.CreateVisitorInvitationRequest
	if err := decodeJSON(response, request, &body); err != nil || body.TeamId == "" || body.PublicUrlId == "" || body.ExpiresAt.IsZero() {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "choose one public URL, recipient email, and expiry")
		return
	}
	key := request.Header.Get("Idempotency-Key")
	fingerprint, err := hex.DecodeString(body.SecretFingerprint)
	if key == "" || len(key) > 128 || strings.TrimSpace(key) != key || err != nil || len(fingerprint) != 32 ||
		hex.EncodeToString(fingerprint) != body.SecretFingerprint {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid invitation secret or idempotency key")
		return
	}
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return
	}
	if h.visitorInvitations == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "named sharing is unavailable")
		return
	}
	if !hasTeam(principal, body.TeamId) {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		return
	}
	url, err := h.store.GetPublicURLForAuthorization(request.Context(), body.PublicUrlId)
	if errors.Is(err, controlstate.ErrPublicURLNotFound) || err == nil && url.TeamID != body.TeamId {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		return
	}
	if err != nil {
		writeControlStateProblem(response, "read invited public URL", err)
		return
	}
	if url.Purpose != controlstate.PublicURLPurposeApp || url.ServiceProtocol != controlstate.PublicURLServiceHTTP &&
		url.ServiceProtocol != controlstate.PublicURLServicePostgres && url.ServiceProtocol != controlstate.PublicURLServiceMySQL &&
		url.ServiceProtocol != controlstate.PublicURLServiceRedis {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "named sharing requires an HTTP app or database public URL")
		return
	}
	if url.ServiceProtocol == controlstate.PublicURLServiceHTTP && h.config.BrowserOIDCClientID == "" {
		writeProblem(response, http.StatusConflict, controlv1.Conflict, "browser sign-in requires an OIDC client configured on control")
		return
	}
	prefixes := make([]string, len(url.AllowedIPPrefixes))
	for index, prefix := range url.AllowedIPPrefixes {
		prefixes[index] = prefix.String()
	}
	decision, ok := h.authorizeExistingRouteMutation(response, request, principal, authorization.Request{
		Operation: authorization.OperationShareCreate, TeamID: url.TeamID,
		PublicURLMembershipID: url.MembershipID, DomainID: url.DomainID,
		CanonicalHostname: url.CanonicalHostname, PublicURLScope: authorization.PublicURLScope(url.PublicURLScope),
		Target: url.Target, AllowedIPPrefixes: prefixes, Ephemeral: url.Ephemeral,
		PublicURLID: url.ID, PublicURLMutationRevision: url.MutationRevision,
	})
	if !ok {
		return
	}
	var digest [32]byte
	copy(digest[:], fingerprint)
	invitation, err := h.visitorInvitations.CreateVisitorShareInvitation(request.Context(), controlstate.CreateVisitorShareInvitationRequest{
		TeamID: body.TeamId, PublicURLID: url.ID, ActingIdentityID: decision.IdentityID,
		IdempotencyKey: key, Email: body.Email, TokenDigest: digest, ExpiresAt: body.ExpiresAt,
		PolicyRevision: decision.PolicyRevision, ExpectedMutationRevision: url.MutationRevision,
	}, time.Now())
	if err != nil {
		writeControlStateProblem(response, "create named share invitation", err)
		return
	}
	writeJSON(response, http.StatusCreated, visitorInvitationResponse(invitation))
}

func (h *handler) AcceptVisitorInvitation(response http.ResponseWriter, request *http.Request) {
	var body controlv1.AcceptVisitorInvitationRequest
	if err := decodeJSON(response, request, &body); err != nil || len(body.Secret) > 128 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid invitation secret")
		return
	}
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return
	}
	if h.visitorInvitations == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "named sharing is unavailable")
		return
	}
	invitation, err := h.visitorInvitations.AcceptVisitorShareInvitation(request.Context(), body.Secret, principal.identityID, time.Now())
	if err != nil {
		writeControlStateProblem(response, "accept named share invitation", err)
		return
	}
	writeJSON(response, http.StatusOK, visitorInvitationResponse(invitation))
}

func (h *handler) ListVisitorInvitations(response http.ResponseWriter, request *http.Request, _ controlv1.ListVisitorInvitationsParams) {
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return
	}
	teamID := request.URL.Query().Get("team_id")
	if !hasTeam(principal, teamID) {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		return
	}
	if h.visitorInvitations == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "named sharing is unavailable")
		return
	}
	page, err := h.visitorInvitations.ListVisitorShareInvitations(request.Context(), teamID, principal.identityID, request.URL.Query().Get("cursor"))
	if err != nil {
		writeControlStateProblem(response, "list named shares", err)
		return
	}
	items := make([]controlv1.VisitorInvitation, len(page.Invitations))
	for index, invitation := range page.Invitations {
		items[index] = visitorInvitationResponse(invitation)
	}
	result := controlv1.VisitorInvitationPage{Invitations: items}
	if page.NextCursor != "" {
		result.NextCursor = &page.NextCursor
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *handler) RevokeVisitorInvitation(response http.ResponseWriter, request *http.Request, shareID controlv1.ShareID) {
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return
	}
	if h.visitorInvitations == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "named sharing is unavailable")
		return
	}
	invitation, err := h.visitorInvitations.GetVisitorShareInvitation(request.Context(), string(shareID))
	if errors.Is(err, controlstate.ErrShareNotFound) || err == nil && !hasTeam(principal, invitation.TeamID) {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		return
	}
	if err != nil {
		writeControlStateProblem(response, "read named share", err)
		return
	}
	revoked, err := h.visitorInvitations.RevokeVisitorShareInvitation(request.Context(), invitation.ID, invitation.TeamID, principal.identityID, time.Now())
	if err != nil {
		writeControlStateProblem(response, "revoke named share", err)
		return
	}
	writeJSON(response, http.StatusOK, visitorInvitationResponse(revoked))
}

func visitorInvitationResponse(invitation controlstate.VisitorShareInvitation) controlv1.VisitorInvitation {
	result := controlv1.VisitorInvitation{
		Id: invitation.ID, TeamId: invitation.TeamID, PublicUrlId: invitation.PublicURLID,
		Email: invitation.Email, CreatedByIdentityId: invitation.CreatedByIdentityID,
		CreatedAt: invitation.CreatedAt, ExpiresAt: invitation.ExpiresAt,
		AcceptedAt: invitation.AcceptedAt, RevokedAt: invitation.RevokedAt,
	}
	if invitation.AcceptedIdentityID != "" {
		result.AcceptedIdentityId = &invitation.AcceptedIdentityID
	}
	return result
}
