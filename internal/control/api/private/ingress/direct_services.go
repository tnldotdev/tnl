package ingress

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

type directServiceStore interface {
	AdmitDirectServiceVisitor(context.Context, controlstate.IngressLeaseIdentity, string, string, int, netip.Addr, time.Time) (controlstate.DirectVisitorAdmission, error)
	DirectServiceVisitorStatus(context.Context, controlstate.IngressLeaseIdentity, string, time.Time) (controlstate.DirectVisitorStatus, error)
	CloseDirectServiceVisitor(context.Context, controlstate.IngressLeaseIdentity, string, time.Time) error
	PromoteDirectServiceVisitor(context.Context, controlstate.IngressLeaseIdentity, string, time.Time) error
}

func (s *service) directServices() (directServiceStore, error) {
	store, ok := s.store.(directServiceStore)
	if !ok {
		return nil, serviceapi.NewProblemError(http.StatusServiceUnavailable, "unavailable", "direct service admission is unavailable")
	}
	return store, nil
}

func (s *service) AdmitDirectServiceVisitor(ctx context.Context, id string, body ingressv1.DirectServiceVisitorClaim) (ingressv1.DirectServiceVisitorAdmission, error) {
	var result ingressv1.DirectServiceVisitorAdmission
	lease, ok := ingressLeaseIdentity(id, body.IngressRunId, body.IngressLeaseRevision)
	source, sourceOK := privateSource(body.ObservedSourceIp)
	if !ok || !sourceOK {
		return result, serviceapi.NewProblemError(400, "invalid_request", "invalid direct service admission")
	}
	store, err := s.directServices()
	if err != nil {
		return result, err
	}
	admitted, err := store.AdmitDirectServiceVisitor(ctx, lease, body.IngressPoolId, body.VisitorConnectionId, body.DestinationPort, source, s.now())
	if err != nil {
		return result, s.privateStateError(ctx, err)
	}
	return ingressv1.DirectServiceVisitorAdmission{ServiceId: admitted.ServiceID, ServiceRunId: admitted.RunID, RunNumber: admitted.RunNumber, VisitorConnectionId: admitted.ConnectionID, ExpiresAt: admitted.ExpiresAt, ConnectedRelays: privateRelayResponses(admitted.Relays)}, nil
}

func (s *service) DirectServiceVisitorStatus(ctx context.Context, id string, body ingressv1.DirectServiceVisitorLookup) (ingressv1.DirectServiceVisitorStatus, error) {
	var result ingressv1.DirectServiceVisitorStatus
	lease, ok := ingressLeaseIdentity(id, body.IngressRunId, body.IngressLeaseRevision)
	if !ok {
		return result, serviceapi.NewProblemError(400, "invalid_request", "invalid direct service lease")
	}
	store, err := s.directServices()
	if err != nil {
		return result, err
	}
	status, err := store.DirectServiceVisitorStatus(ctx, lease, body.VisitorConnectionId, s.now())
	if errors.Is(err, controlstate.ErrServiceAccess) || errors.Is(err, controlstate.ErrIngressLeaseStale) {
		return ingressv1.DirectServiceVisitorStatus{State: ingressv1.DirectVisitorDenied, ValidUntil: s.now()}, nil
	}
	if err != nil {
		return result, s.privateStateError(ctx, err)
	}
	return ingressv1.DirectServiceVisitorStatus{State: ingressv1.DirectServiceVisitorStatusState(status.State), ValidUntil: status.ValidUntil}, nil
}

func (s *service) PromoteDirectServiceVisitor(ctx context.Context, id string, body ingressv1.DirectServiceVisitorLookup) error {
	lease, ok := ingressLeaseIdentity(id, body.IngressRunId, body.IngressLeaseRevision)
	if !ok {
		return serviceapi.NewProblemError(400, "invalid_request", "invalid direct service lease")
	}
	store, err := s.directServices()
	if err != nil {
		return err
	}
	return s.privateStateError(ctx, store.PromoteDirectServiceVisitor(ctx, lease, body.VisitorConnectionId, s.now()))
}

func (s *service) CloseDirectServiceVisitor(ctx context.Context, id string, body ingressv1.DirectServiceVisitorLookup) error {
	lease, ok := ingressLeaseIdentity(id, body.IngressRunId, body.IngressLeaseRevision)
	if !ok {
		return serviceapi.NewProblemError(400, "invalid_request", "invalid direct service lease")
	}
	store, err := s.directServices()
	if err != nil {
		return err
	}
	return s.privateStateError(ctx, store.CloseDirectServiceVisitor(ctx, lease, body.VisitorConnectionId, s.now()))
}

func (s generatedServer) AdmitDirectServiceVisitor(w http.ResponseWriter, r *http.Request, id ingressv1.IngressID) {
	var body ingressv1.DirectServiceVisitorClaim
	if !serviceapi.DecodeJSON(w, r, &body) {
		return
	}
	result, err := s.handler.service.AdmitDirectServiceVisitor(r.Context(), id, body)
	if !s.handler.writeServiceError(w, r, err) {
		serviceapi.WriteJSON(w, http.StatusOK, result)
	}
}

func (s generatedServer) DirectServiceVisitorStatus(w http.ResponseWriter, r *http.Request, id ingressv1.IngressID) {
	var body ingressv1.DirectServiceVisitorLookup
	if !serviceapi.DecodeJSON(w, r, &body) {
		return
	}
	result, err := s.handler.service.DirectServiceVisitorStatus(r.Context(), id, body)
	if !s.handler.writeServiceError(w, r, err) {
		serviceapi.WriteJSON(w, http.StatusOK, result)
	}
}

func (s generatedServer) CloseDirectServiceVisitor(w http.ResponseWriter, r *http.Request, id ingressv1.IngressID) {
	var body ingressv1.DirectServiceVisitorLookup
	if !serviceapi.DecodeJSON(w, r, &body) {
		return
	}
	if !s.handler.writeServiceError(w, r, s.handler.service.CloseDirectServiceVisitor(r.Context(), id, body)) {
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s generatedServer) PromoteDirectServiceVisitor(w http.ResponseWriter, r *http.Request, id ingressv1.IngressID) {
	var body ingressv1.DirectServiceVisitorLookup
	if !serviceapi.DecodeJSON(w, r, &body) {
		return
	}
	if !s.handler.writeServiceError(w, r, s.handler.service.PromoteDirectServiceVisitor(r.Context(), id, body)) {
		w.WriteHeader(http.StatusNoContent)
	}
}
