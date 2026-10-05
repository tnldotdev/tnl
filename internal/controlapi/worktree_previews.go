package controlapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) CreateWorktreePreview(response http.ResponseWriter, request *http.Request, _ controlv1.CreateWorktreePreviewParams) {
	var body controlv1.CreateWorktreePreviewRequest
	if err := decodeJSONLimited(response, request, &body, 1<<20); err != nil || body.TeamId == "" {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid worktree preview request")
		return
	}
	key := request.Header.Get("Idempotency-Key")
	if key == "" || len(key) > 128 || strings.TrimSpace(key) != key {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid idempotency key")
		return
	}
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return
	}
	if _, member := principal.teamIDs[body.TeamId]; !member {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		return
	}
	if h.previews == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "worktree previews are unavailable")
		return
	}
	preview, err := h.previews.CreateWorktreePreview(request.Context(), body.TeamId, principal.identityID, key, time.Now())
	if err != nil {
		writeControlStateProblem(response, "create worktree preview", err)
		return
	}
	writeJSON(response, http.StatusCreated, worktreePreviewResponse(preview))
}

func (h *handler) GetWorktreePreview(response http.ResponseWriter, request *http.Request, previewID controlv1.WorktreePreviewID) {
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return
	}
	preview, ok := h.readWorktreePreview(response, request, string(previewID), principal)
	if ok {
		writeJSON(response, http.StatusOK, worktreePreviewResponse(preview))
	}
}

func (h *handler) AddWorktreePreviewPublicURL(response http.ResponseWriter, request *http.Request, previewID controlv1.WorktreePreviewID) {
	var body controlv1.AddWorktreePreviewPublicURLRequest
	if err := decodeJSONLimited(response, request, &body, 1<<20); err != nil || body.PublicUrlId == "" {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid worktree preview public URL")
		return
	}
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return
	}
	preview, ok := h.readWorktreePreview(response, request, string(previewID), principal)
	if !ok {
		return
	}
	route, err := h.store.GetPublicURLForAuthorization(request.Context(), body.PublicUrlId)
	if errors.Is(err, controlstate.ErrPublicURLNotFound) {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		return
	}
	if err != nil {
		writeControlStateProblem(response, "read worktree preview public URL", err)
		return
	}
	if route.TeamID != preview.TeamID {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		return
	}
	prefixes := make([]string, len(route.AllowedIPPrefixes))
	for index, prefix := range route.AllowedIPPrefixes {
		prefixes[index] = prefix.String()
	}
	decision, ok := h.authorizeExistingRouteMutation(response, request, principal, authorization.Request{
		Operation: authorization.OperationPublicURLUpdate, TeamID: route.TeamID,
		PublicURLMembershipID: route.MembershipID, DomainID: route.DomainID,
		CanonicalHostname: route.CanonicalHostname, PublicURLScope: authorization.PublicURLScope(route.PublicURLScope),
		Target: route.Target, AllowedIPPrefixes: prefixes, Ephemeral: route.Ephemeral,
		PublicURLID: route.ID, PublicURLMutationRevision: route.MutationRevision,
	})
	if !ok {
		return
	}
	updated, err := h.previews.AddWorktreePreviewPublicURL(request.Context(), controlstate.AddWorktreePreviewPublicURLRequest{
		PreviewID: preview.ID, PublicURLID: route.ID, TeamID: decision.TeamID, IdentityID: decision.IdentityID,
		AuthorityIssuer: h.authorityIssuerFor(decision), PolicyRevision: decision.PolicyRevision,
		ExpectedMutationRevision: route.MutationRevision,
	}, time.Now())
	if err != nil {
		writeControlStateProblem(response, "add worktree preview public URL", err)
		return
	}
	writeJSON(response, http.StatusOK, worktreePreviewResponse(updated))
}

func (h *handler) readWorktreePreview(response http.ResponseWriter, request *http.Request, id string, principal publicURLReadPrincipal) (controlstate.WorktreePreview, bool) {
	if h.previews == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "worktree previews are unavailable")
		return controlstate.WorktreePreview{}, false
	}
	preview, err := h.previews.GetWorktreePreview(request.Context(), id)
	if err != nil {
		writeControlStateProblem(response, "read worktree preview", err)
		return controlstate.WorktreePreview{}, false
	}
	if _, member := principal.teamIDs[preview.TeamID]; !member || principal.identityID != preview.CreatedByIdentityID {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		return controlstate.WorktreePreview{}, false
	}
	return preview, true
}

func worktreePreviewResponse(preview controlstate.WorktreePreview) controlv1.WorktreePreview {
	return controlv1.WorktreePreview{
		Id: preview.ID, TeamId: preview.TeamID, CreatedAt: preview.CreatedAt,
		PublicUrlIds: preview.PublicURLIDs,
	}
}
