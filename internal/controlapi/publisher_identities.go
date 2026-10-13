package controlapi

import (
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) CreatePublisherEnrollment(w http.ResponseWriter, r *http.Request) {
	if h.publisherIdentities == nil || h.store == nil {
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "publisher enrollment is unavailable")
		return
	}
	var body controlv1.CreatePublisherEnrollmentRequest
	if err := decodeJSON(w, r, &body); err != nil || !naming.ValidServiceName(body.Name) ||
		body.Kind != "installed" && body.Kind != "automation" {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "select one public URL or namespace grant")
		return
	}
	scope, decision, ok := h.authorizePublisherSelection(w, r, body.TeamId, body.PublicUrlId, body.DomainId, body.PublicUrlScope)
	if !ok {
		return
	}
	issued, err := h.publisherIdentities.IssuePublisherEnrollment(r.Context(), controlstate.CreatePublisherEnrollmentRequest{
		Scope: scope, Name: body.Name, Kind: string(body.Kind), EditorID: decision.IdentityID,
		EditorMembershipID: decision.ActingMembershipID, PolicyRevision: decision.PolicyRevision, Now: time.Now().UTC(),
	})
	if errors.Is(err, controlstate.ErrPublisherIdentity) || errors.Is(err, controlstate.ErrPublisherEnrollment) {
		writeProblem(w, http.StatusConflict, controlv1.Conflict, "publisher enrollment scope is no longer available")
		return
	}
	if err != nil {
		writeControlStateProblem(w, "issue publisher enrollment", err)
		return
	}
	result := controlv1.IssuedPublisherEnrollment{
		Id: issued.ID, EnrollmentKey: issued.Key, TeamId: controlv1.TeamID(scope.TeamID),
		Name: body.Name, Kind: controlv1.IssuedPublisherEnrollmentKind(scope.Kind), ExpiresAt: issued.Until,
	}
	if scope.PublicURLID != "" {
		publicURLID := controlv1.PublicURLID(scope.PublicURLID)
		result.PublicUrlId = &publicURLID
	} else {
		domainID := controlv1.DomainID(scope.DomainID)
		result.DomainId = &domainID
		result.Namespace = &scope.Namespace
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, result)
}

func (h *handler) authorizePublisherSelection(w http.ResponseWriter, r *http.Request, team controlv1.TeamID,
	publicURL *controlv1.PublicURLID, domain *controlv1.DomainID, selectedScope *controlv1.PublicURLScope,
) (controlstate.PublisherScope, authorization.Decision, bool) {
	if (publicURL == nil) == (domain == nil) || publicURL != nil && selectedScope != nil || domain != nil && selectedScope == nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "select one public URL or namespace grant")
		return controlstate.PublisherScope{}, authorization.Decision{}, false
	}
	if publicURL != nil {
		route, decision, ok := h.credentialManagementRoute(w, r, string(*publicURL))
		if !ok {
			return controlstate.PublisherScope{}, authorization.Decision{}, false
		}
		if route.TeamID != string(team) {
			writeProblem(w, http.StatusNotFound, controlv1.NotFound, "public URL not found in selected team")
			return controlstate.PublisherScope{}, authorization.Decision{}, false
		}
		return controlstate.PublisherScope{TeamID: route.TeamID, PublicURLID: route.ID, Kind: "saved_url"}, decision, true
	}
	if !h.config.DNSAutomation {
		writeProblem(w, http.StatusConflict, controlv1.Conflict, "namespace enrollment requires automated DNS")
		return controlstate.PublisherScope{}, authorization.Decision{}, false
	}
	decision, ok := h.authorizeMutation(w, r, authorization.Request{
		Operation: authorization.OperationCredentialCreate, TeamID: string(team),
		DomainID: string(*domain), PublicURLScope: authorization.PublicURLScope(*selectedScope),
	})
	if !ok {
		return controlstate.PublisherScope{}, authorization.Decision{}, false
	}
	plan := decision.CertificatePlan
	if decision.Namespace == "" || plan == nil || plan.ChallengeMethod != certificateidentity.ChallengeDNS01 ||
		!slices.Contains(plan.Identifiers, "*."+decision.Namespace) {
		writeProblem(w, http.StatusForbidden, controlv1.Forbidden, "an authorized DNS-01 wildcard namespace is required")
		return controlstate.PublisherScope{}, authorization.Decision{}, false
	}
	return controlstate.PublisherScope{TeamID: decision.TeamID, DomainID: decision.DomainID,
		Namespace: decision.Namespace, Kind: "namespace"}, decision, true
}

func (h *handler) CreatePublisherGrant(w http.ResponseWriter, r *http.Request, id controlv1.ResourceID) {
	if h.publisherIdentities == nil || !opaqueid.Valid(string(id), opaqueid.PublisherIdentityPrefix) {
		writeProblem(w, http.StatusNotFound, controlv1.NotFound, "publisher identity not found")
		return
	}
	var body controlv1.CreatePublisherGrantRequest
	if err := decodeJSON(w, r, &body); err != nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid publisher grant")
		return
	}
	scope, decision, ok := h.authorizePublisherSelection(w, r, body.TeamId, body.PublicUrlId, body.DomainId, body.PublicUrlScope)
	if !ok {
		return
	}
	grantID, err := h.publisherIdentities.CreatePublisherGrant(r.Context(), controlstate.CreatePublisherGrantRequest{
		PublisherIdentityID: string(id), Scope: scope, EditorID: decision.IdentityID,
		EditorMembershipID: decision.ActingMembershipID, PolicyRevision: decision.PolicyRevision,
		ExpiresAt: body.ExpiresAt, Now: time.Now().UTC(),
	})
	if errors.Is(err, controlstate.ErrPublisherIdentity) {
		writeProblem(w, http.StatusConflict, controlv1.Conflict, "publisher grant scope is no longer available")
		return
	}
	if err != nil {
		writeControlStateProblem(w, "create publisher grant", err)
		return
	}
	result := controlv1.PublisherGrant{Id: grantID, TeamId: controlv1.TeamID(scope.TeamID),
		Kind: controlv1.PublisherGrantKind(scope.Kind), ExpiresAt: body.ExpiresAt}
	if scope.PublicURLID != "" {
		urlID := controlv1.PublicURLID(scope.PublicURLID)
		result.PublicUrlId = &urlID
	} else {
		domainID := controlv1.DomainID(scope.DomainID)
		result.DomainId, result.Namespace = &domainID, &scope.Namespace
	}
	writeJSON(w, http.StatusCreated, result)
}

func (h *handler) RevokePublisherGrant(w http.ResponseWriter, r *http.Request, id, grantID controlv1.ResourceID, params controlv1.RevokePublisherGrantParams) {
	if !opaqueid.Valid(string(grantID), opaqueid.PublisherGrantPrefix) {
		writeProblem(w, http.StatusNotFound, controlv1.NotFound, "publisher grant not found")
		return
	}
	if !h.authorizePublisherGrantRevocation(w, r, string(params.TeamId), string(id), string(grantID)) {
		return
	}
	if err := h.publisherIdentities.RevokePublisherGrant(r.Context(), string(params.TeamId), string(id), string(grantID), time.Now().UTC()); err != nil {
		if errors.Is(err, controlstate.ErrPublisherIdentity) {
			writeProblem(w, http.StatusNotFound, controlv1.NotFound, "publisher grant not found")
			return
		}
		writeControlStateProblem(w, "revoke publisher grant", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) RevokePublisherIdentity(w http.ResponseWriter, r *http.Request, id controlv1.ResourceID, params controlv1.RevokePublisherIdentityParams) {
	if !h.authorizePublisherGrantRevocation(w, r, string(params.TeamId), string(id), "") {
		return
	}
	if err := h.publisherIdentities.RevokePublisherIdentity(r.Context(), string(params.TeamId), string(id), time.Now().UTC()); err != nil {
		writeControlStateProblem(w, "revoke publisher identity", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) authorizePublisherGrantRevocation(w http.ResponseWriter, r *http.Request, teamID, id, onlyGrantID string) bool {
	if h.publisherIdentities == nil || !opaqueid.Valid(string(id), opaqueid.PublisherIdentityPrefix) {
		writeProblem(w, http.StatusNotFound, controlv1.NotFound, "publisher identity not found")
		return false
	}
	principal, ok := h.authorizeRouteReads(w, r)
	if !ok {
		return false
	}
	if _, authorized := principal.teamIDs[teamID]; !authorized {
		writeProblem(w, http.StatusNotFound, controlv1.NotFound, "publisher identity not found")
		return false
	}
	grants, err := h.publisherIdentities.PublisherManagementGrants(r.Context(), teamID, string(id))
	if errors.Is(err, controlstate.ErrPublisherIdentity) {
		writeProblem(w, http.StatusNotFound, controlv1.NotFound, "publisher identity not found")
		return false
	}
	if err != nil {
		writeControlStateProblem(w, "read publisher identity grants", err)
		return false
	}
	found := false
	for _, grant := range grants {
		if onlyGrantID != "" && grant.ID != onlyGrantID {
			continue
		}
		found = true
		if _, ok := h.authorizeExistingRouteMutation(w, r, principal, authorization.Request{
			Operation: authorization.OperationCredentialRevoke, TeamID: teamID,
			PublicURLMembershipID: grant.PublicURLMembershipID,
		}); !ok {
			return false
		}
	}
	if !found {
		writeProblem(w, http.StatusNotFound, controlv1.NotFound, "publisher grant not found")
		return false
	}
	return true
}
