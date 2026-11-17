package public

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/api/serviceaccess"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (h *handler) authenticatePublisher(w http.ResponseWriter, r *http.Request) (PublisherIdentityStore, controlstate.PublisherIdentity, bool) {
	store, ok := h.dependencies.PublisherIdentities, h.dependencies.PublisherIdentities != nil
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "publisher authentication is unavailable")
		return nil, controlstate.PublisherIdentity{}, false
	}
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return nil, controlstate.PublisherIdentity{}, false
	}
	p, err := store.AuthenticatePublisherAccess(r.Context(), token, publisherRequestSource(r), time.Now())
	if err != nil {
		switch {
		case failure.Only(err, controlstate.ErrPublisherIdentity), failure.Only(err, pgx.ErrNoRows):
			writeBearerProblem(w)
		case failure.Only(err, controlstate.ErrServiceAccess):
			writeProblem(w, http.StatusForbidden, controlv1.Forbidden, "publisher permission denied")
		case controlstate.IsUnavailable(err):
			writeUnavailableProblem(r.Context(), w, "authenticate publisher", "publisher authentication is unavailable", failure.ServerUnavailable, err)
		default:
			writeInternalStateProblem(r.Context(), w, "authenticate publisher", err)
		}
		return nil, controlstate.PublisherIdentity{}, false
	}
	*r = *r.WithContext(observability.AuthenticatedServerScope(r.Context(), observability.Identity{
		TeamID: p.Scope.TeamID, PublisherIdentityID: p.ID, ServiceID: p.Scope.ServiceID,
	}, observability.Fields{Component: "control"}))
	return store, p, true
}

func publisherAllocationInput(w http.ResponseWriter, r *http.Request) (controlstate.AllocateServiceRequest, bool) {
	var b struct {
		Invocation    string                                    `json:"invocation_id"`
		Configuration *controlstate.ProjectServiceConfiguration `json:"configuration"`
		ExpiresAt     *time.Time                                `json:"expires_at"`
	}
	if decodeJSONLimited(w, r, &b, 2<<20) != nil || b.Configuration == nil || !opaqueid.Valid(b.Invocation, opaqueid.InvocationPrefix) {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid temporary service declaration")
		return controlstate.AllocateServiceRequest{}, false
	}
	return controlstate.AllocateServiceRequest{Invocation: b.Invocation, Configuration: *b.Configuration, ExpiresAt: b.ExpiresAt}, true
}

func (h *handler) AllocatePublisherService(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !h.config.DNSAutomation {
		writeProblem(w, 409, controlv1.Conflict, "namespace allocation requires automated DNS")
		return
	}
	store, p, ok := h.authenticatePublisher(w, r)
	if !ok {
		return
	}
	b, ok := publisherAllocationInput(w, r)
	if !ok {
		return
	}
	service, err := store.AllocatePublisherService(r.Context(), p, b, time.Now())
	if err != nil {
		writeControlStateProblem(r.Context(), w, "allocate publisher service", err)
		return
	}
	writeJSON(w, 201, serviceaccess.Service(service))
}

func (h *handler) DeletePublisherService(w http.ResponseWriter, r *http.Request, id controlv1.ServiceID) {
	w.Header().Set("Cache-Control", "no-store")
	store, p, ok := h.authenticatePublisher(w, r)
	if !ok {
		return
	}
	if err := store.DeletePublisherService(r.Context(), p, id, time.Now()); err != nil {
		writeControlStateProblem(r.Context(), w, "delete allocated service", err)
		return
	}
	w.WriteHeader(204)
}
