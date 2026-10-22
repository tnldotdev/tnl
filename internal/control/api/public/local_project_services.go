package controlapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) GetLocalProjectService(w http.ResponseWriter, r *http.Request, project, service string, params controlv1.GetLocalProjectServiceParams) {
	w.Header().Set("Cache-Control", "no-store")
	principal, ok := h.authorizeRouteReads(w, r)
	if !ok {
		return
	}
	store, ok := h.store.(interface {
		GetLocalProjectService(context.Context, controlstate.GetLocalProjectServiceRequest) (controlstate.LocalProjectService, error)
	})
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "local project services are unavailable")
		return
	}
	result, err := store.GetLocalProjectService(r.Context(), controlstate.GetLocalProjectServiceRequest{TeamID: params.TeamId, ProjectKey: project, Service: service, SourceFingerprint: params.SourceFingerprint, WorktreeKey: params.WorktreeKey, ActorID: principal.identityID, Now: time.Now()})
	if errors.Is(err, controlstate.ErrProjectConfigurationInvalid) || errors.Is(err, controlstate.ErrProjectSourceConflict) {
		projectConfigurationProblem(w, "get local project service", err)
		return
	}
	if err != nil {
		privateVisitorError(w, "get local project service", err)
		return
	}
	writeJSON(w, 200, result)
}

func (h *handler) RealizeLocalProjectService(w http.ResponseWriter, r *http.Request, project, service string) {
	w.Header().Set("Cache-Control", "no-store")
	var body struct {
		TeamID            string                                    `json:"team_id"`
		SourceFingerprint string                                    `json:"source_fingerprint"`
		WorktreeKey       string                                    `json:"worktree_key"`
		WorktreeLabel     string                                    `json:"worktree_label"`
		DomainID          string                                    `json:"domain_id"`
		PublicURLID       string                                    `json:"public_url_id"`
		Configuration     *controlstate.ProjectServiceConfiguration `json:"configuration"`
	}
	if decodeJSONLimited(w, r, &body, 2<<20) != nil || body.Configuration == nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid local project service declaration")
		return
	}
	actor, ok := h.projectManager(w, r, body.TeamID)
	if !ok {
		return
	}
	store, ok := h.store.(interface {
		RealizeLocalProjectService(context.Context, controlstate.RealizeLocalProjectServiceRequest) (controlstate.LocalProjectService, error)
	})
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "local project services are unavailable")
		return
	}
	result, err := store.RealizeLocalProjectService(r.Context(), controlstate.RealizeLocalProjectServiceRequest{TeamID: body.TeamID, ProjectKey: project, SourceFingerprint: body.SourceFingerprint, Service: service, WorktreeKey: body.WorktreeKey, WorktreeLabel: body.WorktreeLabel, DomainID: body.DomainID, DNSAutomation: h.config.DNSAutomation, PublicURLID: body.PublicURLID, ActorID: actor, Configuration: *body.Configuration, Now: time.Now()})
	if err != nil {
		projectConfigurationProblem(w, "realize local project service", err)
		return
	}
	writeJSON(w, 200, result)
}

func (h *handler) GetProjectPublicMetadata(w http.ResponseWriter, r *http.Request, project string, params controlv1.GetProjectPublicMetadataParams) {
	w.Header().Set("Cache-Control", "no-store")
	principal, ok := h.authorizeRouteReads(w, r)
	if !ok {
		return
	}
	store, ok := h.store.(interface {
		GetProjectPublicMetadata(context.Context, string, string, string, time.Time) (controlstate.ProjectPublicMetadata, error)
	})
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "project public metadata is unavailable")
		return
	}
	result, err := store.GetProjectPublicMetadata(r.Context(), params.TeamId, project, principal.identityID, time.Now())
	if err != nil {
		writeControlStateProblem(w, "get project public metadata", err)
		return
	}
	writeJSON(w, 200, result)
}

func (h *handler) ReleaseVisitorIngressAssignment(w http.ResponseWriter, r *http.Request, id controlv1.PrivateConnectorSessionID) {
	principal, ok := h.authorizeRouteReads(w, r)
	if !ok {
		return
	}
	store, ok := h.store.(interface {
		ReleaseVisitorIngressAssignment(context.Context, string, string, time.Time) error
	})
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "visitor ingress assignments are unavailable")
		return
	}
	if err := store.ReleaseVisitorIngressAssignment(r.Context(), principal.identityID, id, time.Now()); err != nil {
		privateVisitorError(w, "release visitor ingress assignment", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
