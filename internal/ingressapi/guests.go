package ingressapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

type guestVisitorStore interface {
	ReserveGuestVisitor(context.Context, controlstate.IngressLeaseIdentity, string, string, time.Time) (time.Time, error)
	ReleaseGuestVisitor(context.Context, string, string) error
}

func (s *service) ReserveGuestVisitor(ctx context.Context, ingressID string, body ingressv1.GuestVisitorRequest) (ingressv1.GuestVisitorReservation, error) {
	store, ok := s.store.(guestVisitorStore)
	if !ok {
		return ingressv1.GuestVisitorReservation{}, serviceapi.NewProblemError(http.StatusServiceUnavailable, "unavailable", "Guest visitor admission is unavailable")
	}
	identity, valid := ingressLeaseIdentity(ingressID, body.IngressRunId, body.IngressLeaseRevision)
	if !valid || !serviceapi.ValidIdentifiers(body.PublicUrlId, body.VisitorConnectionId) {
		return ingressv1.GuestVisitorReservation{}, serviceapi.NewProblemError(http.StatusBadRequest, "invalid_request", "Guest visitor identity is invalid")
	}
	expires, err := store.ReserveGuestVisitor(ctx, identity, body.PublicUrlId, body.VisitorConnectionId, s.now())
	switch {
	case errors.Is(err, controlstate.ErrGuestConnectionsFull):
		return ingressv1.GuestVisitorReservation{}, serviceapi.NewProblemError(http.StatusTooManyRequests, "capacity_exhausted", "Guest demo has four active connections")
	case errors.Is(err, controlstate.ErrGuestTrialSpent):
		return ingressv1.GuestVisitorReservation{}, serviceapi.NewProblemError(http.StatusForbidden, "forbidden", "Guest demo trial is exhausted")
	case err != nil:
		return ingressv1.GuestVisitorReservation{}, s.storeError(ctx, err)
	}
	return ingressv1.GuestVisitorReservation{ExpiresAt: expires}, nil
}

func (s *service) ReleaseGuestVisitor(ctx context.Context, ingressID, visitorID string) error {
	store, ok := s.store.(guestVisitorStore)
	if !ok {
		return serviceapi.NewProblemError(http.StatusServiceUnavailable, "unavailable", "Guest visitor admission is unavailable")
	}
	if !serviceapi.ValidIdentifiers(ingressID, visitorID) {
		return serviceapi.NewProblemError(http.StatusBadRequest, "invalid_request", "Guest visitor identity is invalid")
	}
	if err := store.ReleaseGuestVisitor(ctx, visitorID, ingressID); err != nil {
		return s.storeError(ctx, err)
	}
	return nil
}

func (h *handler) reserveGuestVisitor(response http.ResponseWriter, request *http.Request, ingressID string) {
	var body ingressv1.GuestVisitorRequest
	if !serviceapi.DecodeJSON(response, request, &body) {
		return
	}
	reservation, err := h.service.ReserveGuestVisitor(request.Context(), ingressID, body)
	if h.writeServiceError(response, request, err) {
		return
	}
	serviceapi.WriteJSON(response, http.StatusOK, reservation)
}

func (h *handler) releaseGuestVisitor(response http.ResponseWriter, request *http.Request, ingressID, visitorID string) {
	if h.writeServiceError(response, request, h.service.ReleaseGuestVisitor(request.Context(), ingressID, visitorID)) {
		return
	}
	response.WriteHeader(http.StatusNoContent)
}
