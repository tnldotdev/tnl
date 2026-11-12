package ingress

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	serverhttp "github.com/tnldotdev/tnl/internal/serverhttp"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

type publicServiceStore interface {
	AdmitPublicServiceVisitor(context.Context, controlstate.IngressLeaseIdentity, string, string, int, netip.Addr, time.Time) (controlstate.PublicServiceVisitorAdmission, error)
	PublicServiceVisitorStatus(context.Context, controlstate.IngressLeaseIdentity, string, time.Time) (controlstate.PublicServiceVisitorStatus, error)
	ClosePublicServiceVisitor(context.Context, controlstate.IngressLeaseIdentity, string, time.Time) error
	PromotePublicServiceVisitor(context.Context, controlstate.IngressLeaseIdentity, string, time.Time) error
}

func (s *service) AdmitPublicServiceVisitor(ctx context.Context, id string, body ingressv1.PublicServiceVisitorClaim) (ingressv1.PublicServiceVisitorAdmission, error) {
	var result ingressv1.PublicServiceVisitorAdmission
	lease, ok := ingressLeaseIdentity(id, body.IngressRunId, body.IngressLeaseRevision)
	source, sourceOK := privateSource(body.ObservedSourceIp)
	if !ok || !sourceOK {
		return result, serverhttp.NewProblemError(400, "invalid_request", "invalid public service admission")
	}
	admitted, err := s.store.AdmitPublicServiceVisitor(ctx, lease, body.IngressPoolId, body.VisitorConnectionId, body.DestinationPort, source, s.now())
	if err != nil {
		return result, s.privateStateError(ctx, err)
	}
	return ingressv1.PublicServiceVisitorAdmission{ServiceId: admitted.ServiceID, ServiceRunId: admitted.RunID, RunNumber: admitted.RunNumber, VisitorConnectionId: admitted.ConnectionID, ExpiresAt: admitted.ExpiresAt, ConnectedRelays: privateRelayResponses(admitted.Relays)}, nil
}

func (s *service) PublicServiceVisitorStatus(ctx context.Context, id string, body ingressv1.PublicServiceVisitorLookup) (ingressv1.PublicServiceVisitorStatus, error) {
	var result ingressv1.PublicServiceVisitorStatus
	lease, ok := ingressLeaseIdentity(id, body.IngressRunId, body.IngressLeaseRevision)
	if !ok {
		return result, serverhttp.NewProblemError(400, "invalid_request", "invalid public service lease")
	}
	status, err := s.store.PublicServiceVisitorStatus(ctx, lease, body.VisitorConnectionId, s.now())
	if errors.Is(err, controlstate.ErrServiceAccess) || errors.Is(err, controlstate.ErrIngressLeaseStale) {
		return ingressv1.PublicServiceVisitorStatus{State: ingressv1.PublicServiceVisitorDenied, ValidUntil: s.now()}, nil
	}
	if err != nil {
		return result, s.privateStateError(ctx, err)
	}
	return ingressv1.PublicServiceVisitorStatus{State: ingressv1.PublicServiceVisitorStatusState(status.State), ValidUntil: status.ValidUntil}, nil
}

func (s *service) PromotePublicServiceVisitor(ctx context.Context, id string, body ingressv1.PublicServiceVisitorLookup) error {
	lease, ok := ingressLeaseIdentity(id, body.IngressRunId, body.IngressLeaseRevision)
	if !ok {
		return serverhttp.NewProblemError(400, "invalid_request", "invalid public service lease")
	}
	return s.privateStateError(ctx, s.store.PromotePublicServiceVisitor(ctx, lease, body.VisitorConnectionId, s.now()))
}

func (s *service) ClosePublicServiceVisitor(ctx context.Context, id string, body ingressv1.PublicServiceVisitorLookup) error {
	lease, ok := ingressLeaseIdentity(id, body.IngressRunId, body.IngressLeaseRevision)
	if !ok {
		return serverhttp.NewProblemError(400, "invalid_request", "invalid public service lease")
	}
	return s.privateStateError(ctx, s.store.ClosePublicServiceVisitor(ctx, lease, body.VisitorConnectionId, s.now()))
}

func (s generatedServer) AdmitPublicServiceVisitor(w http.ResponseWriter, r *http.Request, id ingressv1.IngressID) {
	var body ingressv1.PublicServiceVisitorClaim
	if !serverhttp.DecodeJSON(w, r, &body) {
		return
	}
	result, err := s.handler.service.AdmitPublicServiceVisitor(r.Context(), id, body)
	if !s.handler.writeServiceError(w, r, err) {
		serverhttp.WriteJSON(w, http.StatusOK, result)
	}
}

func (s generatedServer) PublicServiceVisitorStatus(w http.ResponseWriter, r *http.Request, id ingressv1.IngressID) {
	var body ingressv1.PublicServiceVisitorLookup
	if !serverhttp.DecodeJSON(w, r, &body) {
		return
	}
	result, err := s.handler.service.PublicServiceVisitorStatus(r.Context(), id, body)
	if !s.handler.writeServiceError(w, r, err) {
		serverhttp.WriteJSON(w, http.StatusOK, result)
	}
}

func (s generatedServer) ClosePublicServiceVisitor(w http.ResponseWriter, r *http.Request, id ingressv1.IngressID) {
	var body ingressv1.PublicServiceVisitorLookup
	if !serverhttp.DecodeJSON(w, r, &body) {
		return
	}
	if !s.handler.writeServiceError(w, r, s.handler.service.ClosePublicServiceVisitor(r.Context(), id, body)) {
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s generatedServer) PromotePublicServiceVisitor(w http.ResponseWriter, r *http.Request, id ingressv1.IngressID) {
	var body ingressv1.PublicServiceVisitorLookup
	if !serverhttp.DecodeJSON(w, r, &body) {
		return
	}
	if !s.handler.writeServiceError(w, r, s.handler.service.PromotePublicServiceVisitor(r.Context(), id, body)) {
		w.WriteHeader(http.StatusNoContent)
	}
}
