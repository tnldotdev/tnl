package public

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"unicode"

	"github.com/jackc/pgx/v5"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// EnvironmentPublisherGrantStore requires exact credential capture and all
// three environment-owned operations explicitly. another store cannot enable it.
type EnvironmentPublisherGrantStore interface {
	AuthenticateEnvironmentPublisherManager(context.Context, credentials.AccessToken) (controlstate.EnvironmentPublisherManager, error)
	GetEnvironmentPublisherGrant(context.Context, controlstate.InspectEnvironmentPublisherGrantRequest) (controlstate.EnvironmentPublisherGrantState, error)
	AuthorizeEnvironmentPublisherService(context.Context, controlstate.AuthorizeEnvironmentPublisherServiceRequest) (controlstate.EnvironmentPublisherGrantAuthorization, error)
	RevokeEnvironmentPublisherGrant(context.Context, controlstate.RevokeEnvironmentPublisherGrantRequest) error
}

func (h *handler) environmentPublisherGrantStore(w http.ResponseWriter) (EnvironmentPublisherGrantStore, bool) {
	w.Header().Set("Cache-Control", "no-store")
	store := h.dependencies.EnvironmentPublisherGrants
	if store == nil {
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "environment publisher grant management is unavailable")
		return nil, false
	}
	return store, true
}

func environmentPublisherGrantProblem(ctx context.Context, w http.ResponseWriter, operation string, err error) {
	switch {
	case errors.Is(err, controlstate.ErrControlAuthentication):
		writeBearerProblem(w)
	case errors.Is(err, controlstate.ErrEnvironmentInvalid):
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid environment publisher grant request")
	case errors.Is(err, controlstate.ErrServiceAccess), errors.Is(err, controlstate.ErrAuthorityAccess), errors.Is(err, controlstate.ErrMachineDenied):
		writeProblem(w, http.StatusForbidden, controlv1.Forbidden, "environment publisher grant operation requires current team manager access or an exact machine provisioning grant")
	case errors.Is(err, controlstate.ErrEnvironmentNotFound), errors.Is(err, pgx.ErrNoRows):
		writeProblem(w, http.StatusNotFound, controlv1.NotFound, "environment publisher member or service not found in this scope")
	case errors.Is(err, controlstate.ErrEnvironmentRetired):
		writeProblem(w, http.StatusConflict, controlv1.Conflict, "environment was retired")
	case errors.Is(err, controlstate.ErrEnvironmentStale), errors.Is(err, controlstate.ErrEnvironmentPublisherGrantConflict), errors.Is(err, controlstate.ErrAuthorityConflict):
		writeProblem(w, http.StatusConflict, controlv1.Conflict, "environment or publisher grant intent changed; inspect the current mapping before submitting new intent")
	default:
		writeControlStateProblem(ctx, w, operation, err)
	}
}

func environmentPublisherGrantManager(w http.ResponseWriter, r *http.Request, store EnvironmentPublisherGrantStore) (controlstate.EnvironmentPublisherManager, bool) {
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return controlstate.EnvironmentPublisherManager{}, false
	}
	manager, err := store.AuthenticateEnvironmentPublisherManager(r.Context(), credentials.AccessToken(token))
	if err != nil {
		environmentPublisherGrantProblem(r.Context(), w, "authenticate environment publisher manager", err)
		return controlstate.EnvironmentPublisherManager{}, false
	}
	return manager, true
}

func validEnvironmentPublisherGrantSelection(s controlstate.EnvironmentPublisherGrantSelection) bool {
	return naming.ValidProjectKey(s.ProjectKey) && opaqueid.Valid(s.TeamID, opaqueid.TeamPrefix) &&
		opaqueid.Valid(s.EnvironmentID, opaqueid.EnvironmentPrefix) && opaqueid.Valid(s.PublisherIdentityID, opaqueid.PublisherIdentityPrefix) && opaqueid.Valid(s.ServiceID, opaqueid.ServicePrefix)
}

func validEnvironmentPublisherGrantFence(revision int64, hash string) bool {
	return revision > 0 && len(hash) == 64 && strings.Trim(hash, "0123456789abcdef") == ""
}

func (h *handler) GetEnvironmentPublisherGrant(w http.ResponseWriter, r *http.Request, project, environment, publisher string, service controlv1.ServiceID, params controlv1.GetEnvironmentPublisherGrantParams) {
	store, ok := h.environmentPublisherGrantStore(w)
	if !ok {
		return
	}
	selection := controlstate.EnvironmentPublisherGrantSelection{TeamID: params.TeamId, ProjectKey: project, EnvironmentID: environment, PublisherIdentityID: publisher, ServiceID: service}
	if !validEnvironmentPublisherGrantSelection(selection) || !validEnvironmentPublisherGrantQuery(r, params) {
		environmentPublisherGrantProblem(r.Context(), w, "validate environment publisher selection", controlstate.ErrEnvironmentInvalid)
		return
	}
	manager, ok := environmentPublisherGrantManager(w, r, store)
	if !ok {
		return
	}
	result, err := store.GetEnvironmentPublisherGrant(r.Context(), controlstate.InspectEnvironmentPublisherGrantRequest{EnvironmentPublisherGrantSelection: selection, Manager: manager})
	if err != nil {
		environmentPublisherGrantProblem(r.Context(), w, "inspect environment publisher grant", err)
		return
	}
	writeJSON(w, http.StatusOK, environmentPublisherGrantResponse(result))
}

func (h *handler) AuthorizeEnvironmentPublisherService(w http.ResponseWriter, r *http.Request, project, environment, publisher string, service controlv1.ServiceID) {
	store, ok := h.environmentPublisherGrantStore(w)
	if !ok {
		return
	}
	body, err := decodeEnvironmentPublisherGrantJSON(w, r)
	if err != nil {
		environmentPublisherGrantProblem(r.Context(), w, "decode environment publisher authorization", controlstate.ErrEnvironmentInvalid)
		return
	}
	selection := controlstate.EnvironmentPublisherGrantSelection{TeamID: body.TeamId, ProjectKey: project, EnvironmentID: environment, PublisherIdentityID: publisher, ServiceID: service}
	key := body.IdempotencyKey
	if !validEnvironmentPublisherGrantSelection(selection) || !validEnvironmentPublisherGrantFence(body.ExpectedRevision, body.ExpectedConfigurationHash) ||
		len(key) == 0 || len(key) > 128 || strings.TrimSpace(key) != key || strings.ContainsFunc(key, unicode.IsControl) {
		environmentPublisherGrantProblem(r.Context(), w, "validate environment publisher authorization", controlstate.ErrEnvironmentInvalid)
		return
	}
	previous := controlstate.ExpectNoEnvironmentPublisherGrant()
	if body.ExpectedPreviousGrantId != nil {
		previous, err = controlstate.ExpectEnvironmentPublisherGrant(*body.ExpectedPreviousGrantId)
		if err != nil {
			environmentPublisherGrantProblem(r.Context(), w, "validate environment publisher grant precondition", err)
			return
		}
	}
	manager, ok := environmentPublisherGrantManager(w, r, store)
	if !ok {
		return
	}
	result, err := store.AuthorizeEnvironmentPublisherService(r.Context(), controlstate.AuthorizeEnvironmentPublisherServiceRequest{
		EnvironmentPublisherGrantMutation: controlstate.EnvironmentPublisherGrantMutation{
			InspectEnvironmentPublisherGrantRequest: controlstate.InspectEnvironmentPublisherGrantRequest{EnvironmentPublisherGrantSelection: selection, Manager: manager},
			ExpectedRevision:                        body.ExpectedRevision, ExpectedConfigurationHash: body.ExpectedConfigurationHash},
		ExpectedPreviousGrantID: previous, IdempotencyKey: key,
	})
	if err != nil {
		environmentPublisherGrantProblem(r.Context(), w, "authorize environment publisher service", err)
		return
	}
	status := http.StatusOK
	if result.Created {
		status = http.StatusCreated
	}
	writeJSON(w, status, environmentPublisherGrantResponse(result.EnvironmentPublisherGrantState))
}

func (h *handler) RevokeEnvironmentPublisherGrant(w http.ResponseWriter, r *http.Request, project, environment, publisher string, service controlv1.ServiceID, grant string, params controlv1.RevokeEnvironmentPublisherGrantParams) {
	store, ok := h.environmentPublisherGrantStore(w)
	if !ok {
		return
	}
	selection := controlstate.EnvironmentPublisherGrantSelection{TeamID: params.TeamId, ProjectKey: project, EnvironmentID: environment, PublisherIdentityID: publisher, ServiceID: service}
	if !validEnvironmentPublisherGrantSelection(selection) || !opaqueid.Valid(grant, opaqueid.PublisherGrantPrefix) ||
		!validEnvironmentPublisherGrantFence(params.ExpectedRevision, params.ExpectedConfigurationHash) || !validEnvironmentPublisherGrantQuery(r, params) {
		environmentPublisherGrantProblem(r.Context(), w, "validate environment publisher revocation", controlstate.ErrEnvironmentInvalid)
		return
	}
	manager, ok := environmentPublisherGrantManager(w, r, store)
	if !ok {
		return
	}
	if err := store.RevokeEnvironmentPublisherGrant(r.Context(), controlstate.RevokeEnvironmentPublisherGrantRequest{
		EnvironmentPublisherGrantMutation: controlstate.EnvironmentPublisherGrantMutation{
			InspectEnvironmentPublisherGrantRequest: controlstate.InspectEnvironmentPublisherGrantRequest{EnvironmentPublisherGrantSelection: selection, Manager: manager},
			ExpectedRevision:                        params.ExpectedRevision, ExpectedConfigurationHash: params.ExpectedConfigurationHash}, GrantID: grant,
	}); err != nil {
		environmentPublisherGrantProblem(r.Context(), w, "revoke environment publisher grant", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func environmentPublisherGrantResponse(input controlstate.EnvironmentPublisherGrantState) controlv1.EnvironmentPublisherGrantState {
	result := controlv1.EnvironmentPublisherGrantState{TeamId: input.TeamID, ProjectKey: input.ProjectKey, EnvironmentId: input.EnvironmentID, PublisherIdentityId: input.PublisherIdentityID,
		ServiceId: input.ServiceID, MutationRevision: input.MutationRevision, ConfigurationHash: input.ConfigurationHash}
	if grant := input.Grant; grant != nil {
		result.Grant = &controlv1.EnvironmentPublisherGrant{Id: grant.ID, CreatedAt: grant.CreatedAt, ExpiresAt: grant.ExpiresAt, RevokedAt: grant.RevokedAt}
		if grant.CreatedByIdentityID != "" {
			result.Grant.CreatedByIdentityId = new(grant.CreatedByIdentityID)
		}
		if grant.CreatedByMachineID != "" {
			result.Grant.CreatedByMachineId = new(grant.CreatedByMachineID)
		}
		if grant.ProvisioningGrantID != "" {
			result.Grant.ProvisioningGrantId = new(grant.ProvisioningGrantID)
		}
	}
	return result
}
