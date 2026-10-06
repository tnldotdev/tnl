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

func (h *handler) CreatePreview(response http.ResponseWriter, request *http.Request, _ controlv1.CreatePreviewParams) {
	var body controlv1.CreatePreviewRequest
	if err := decodeJSONLimited(response, request, &body, 1<<20); err != nil || body.TeamId == "" {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid preview request")
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
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "previews are unavailable")
		return
	}
	preview, err := h.previews.CreatePreview(request.Context(), body.TeamId, principal.identityID, key, time.Now())
	if err != nil {
		writeControlStateProblem(response, "create preview", err)
		return
	}
	writeJSON(response, http.StatusCreated, previewResponse(preview))
}

func (h *handler) GetPreview(response http.ResponseWriter, request *http.Request, previewID controlv1.PreviewID) {
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return
	}
	preview, ok := h.readPreview(response, request, string(previewID), principal)
	if ok {
		writeJSON(response, http.StatusOK, previewResponse(preview))
	}
}

func (h *handler) AddPreviewPublicURL(response http.ResponseWriter, request *http.Request, previewID controlv1.PreviewID) {
	var body controlv1.AddPreviewPublicURLRequest
	if err := decodeJSONLimited(response, request, &body, 1<<20); err != nil || body.PublicUrlId == "" {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid preview public URL")
		return
	}
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return
	}
	preview, ok := h.readPreview(response, request, string(previewID), principal)
	if !ok {
		return
	}
	route, err := h.store.GetPublicURLForAuthorization(request.Context(), body.PublicUrlId)
	if errors.Is(err, controlstate.ErrPublicURLNotFound) {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		return
	}
	if err != nil {
		writeControlStateProblem(response, "read preview public URL", err)
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
	updated, err := h.previews.AddPreviewPublicURL(request.Context(), controlstate.AddPreviewPublicURLRequest{
		PreviewID: preview.ID, PublicURLID: route.ID, TeamID: decision.TeamID, IdentityID: decision.IdentityID,
		PolicyRevision:           decision.PolicyRevision,
		ExpectedMutationRevision: route.MutationRevision,
	}, time.Now())
	if err != nil {
		writeControlStateProblem(response, "add preview public URL", err)
		return
	}
	writeJSON(response, http.StatusOK, previewResponse(updated))
}

func (h *handler) readPreview(response http.ResponseWriter, request *http.Request, id string, principal publicURLReadPrincipal) (controlstate.Preview, bool) {
	if h.previews == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "previews are unavailable")
		return controlstate.Preview{}, false
	}
	preview, err := h.previews.GetPreview(request.Context(), id)
	if err != nil {
		writeControlStateProblem(response, "read preview", err)
		return controlstate.Preview{}, false
	}
	if _, member := principal.teamIDs[preview.TeamID]; !member || principal.identityID != preview.CreatedByIdentityID {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		return controlstate.Preview{}, false
	}
	return preview, true
}

func previewResponse(preview controlstate.Preview) controlv1.Preview {
	return controlv1.Preview{
		SchemaVersion: controlv1.ReviewSchemaVersion(preview.SchemaVersion),
		Id:            preview.ID, TeamId: preview.TeamID, CreatedAt: preview.CreatedAt,
		PublicUrlIds:      preview.PublicURLIDs,
		TeamAccessEnabled: &preview.TeamAccessEnabled,
	}
}
