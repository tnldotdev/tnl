package public

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type ApplicationRegistrationStore interface {
	RegisterApplication(context.Context, controlstate.RegisterApplicationRequest, time.Time) (controlstate.ApplicationRegistration, error)
}

func (h *handler) RegisterApplication(w http.ResponseWriter, r *http.Request, params controlv1.RegisterApplicationParams) {
	w.Header().Set("Cache-Control", "no-store")
	var body controlv1.RegisterApplicationRequest
	if decodeJSON(w, r, &body) != nil || !naming.ValidServiceName(body.Name) || len(body.Grants) < 1 || len(body.Grants) > 64 ||
		!body.Ownership.Valid() || len(params.IdempotencyKey) == 0 || len(params.IdempotencyKey) > 256 {
		writeProblem(w, 400, controlv1.InvalidRequest, "select a name, ownership and explicit application grants")
		return
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(body.PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(public) != body.PublicKey {
		writeProblem(w, 400, controlv1.InvalidRequest, "supply one Ed25519 application public key")
		return
	}
	request := controlstate.RegisterApplicationRequest{TeamID: body.TeamId, Name: body.Name, Ownership: string(body.Ownership), PublicKey: public, IdempotencyKey: params.IdempotencyKey, Grants: make([]controlstate.ApplicationGrantRequest, 0, len(body.Grants))}
	for _, grant := range body.Grants {
		scope, valid := publisherScope(body.TeamId, grant.PublicUrlId, grant.DomainId, grant.ServiceId)
		if !valid || !grant.Operation.Valid() || (grant.Operation == controlv1.ApplicationAllocate) != (scope.Kind == "namespace") || scope.Kind == "namespace" && !h.config.DNSAutomation {
			writeProblem(w, 400, controlv1.InvalidRequest, "select an exact resource and its application operation")
			return
		}
		request.Grants = append(request.Grants, controlstate.ApplicationGrantRequest{Scope: scope, Operation: controlstate.ApplicationOperation(grant.Operation), ExpiresAt: grant.ExpiresAt})
	}
	if h.dependencies.Applications == nil {
		writeProblem(w, 503, controlv1.Unavailable, "application registration is unavailable")
		return
	}
	_, _, editor, ok := h.publisherEditor(w, r, body.TeamId)
	if !ok {
		return
	}
	request.ActingIdentityID = editor
	registered, err := h.dependencies.Applications.RegisterApplication(r.Context(), request, time.Now())
	if err != nil {
		switch {
		case errors.Is(err, controlstate.ErrApplicationIdempotency), errors.Is(err, controlstate.ErrAuthorityConflict):
			writeProblem(w, 409, controlv1.Conflict, "application registration conflicts with its saved request or grants")
		case errors.Is(err, controlstate.ErrApplicationRegistration):
			writeProblem(w, 403, controlv1.Forbidden, "application registration is not authorized")
		default:
			publisherProblem(w, "register application", err)
		}
		return
	}
	result := controlv1.RegisteredApplication{ClientId: registered.ID, KeyId: registered.KeyID, TeamId: registered.TeamID, Name: registered.Name, Ownership: controlv1.RegisteredApplicationOwnership(registered.Ownership), Grants: make([]controlv1.PublisherGrant, 0, len(registered.Grants))}
	for _, grant := range registered.Grants {
		wire := controlv1.PublisherGrant{Id: grant.ID, Kind: controlv1.PublisherGrantKind(grant.Scope.Kind), Operation: controlv1.ApplicationOperation(grant.Operation), CreatedAt: grant.CreatedAt, ExpiresAt: grant.ExpiresAt, RevokedAt: grant.RevokedAt}
		if grant.Scope.PublicURLID != "" {
			wire.PublicUrlId = &grant.Scope.PublicURLID
		}
		if grant.Scope.ServiceID != "" {
			wire.ServiceId = &grant.Scope.ServiceID
		}
		if grant.Scope.DomainID != "" {
			wire.DomainId = &grant.Scope.DomainID
		}
		if grant.Scope.Namespace != "" {
			wire.Namespace = &grant.Scope.Namespace
		}
		result.Grants = append(result.Grants, wire)
	}
	writeJSON(w, http.StatusCreated, result)
}
