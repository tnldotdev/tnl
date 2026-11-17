package public

import (
	"context"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/api/serviceaccess"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// trial dispatch recognizes a bearer only for direct service sharing or cleanup.
// it grants no human authority; state repeats authentication under its own locks.
// issuance may be disabled while existing trials still need cleanup.
func (h *handler) guestServiceCredential(w http.ResponseWriter, r *http.Request) (controlstate.GuestCredential, bool, bool) {
	token, present := requestBearerToken(r)
	if !present || h.guests == nil {
		return controlstate.GuestCredential{}, false, true
	}
	_, err := h.guests.GuestTrialByAccessToken(r.Context(), credentials.AccessToken(token))
	if failure.Only(err, controlstate.ErrGuestUnknown) {
		return controlstate.GuestCredential{}, false, true
	}
	if err != nil {
		if r.Context().Err() != nil {
			return controlstate.GuestCredential{}, false, false
		}
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "could not check guest trial")
		return controlstate.GuestCredential{}, false, false
	}
	credential, ok := guestRequestCredential(w, r)
	return credential, true, ok
}

func guestRequestCredential(w http.ResponseWriter, r *http.Request) (controlstate.GuestCredential, bool) {
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return controlstate.GuestCredential{}, false
	}
	address, err := guestRequestAddress(r)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid client address")
		return controlstate.GuestCredential{}, false
	}
	return controlstate.GuestCredential{Token: credentials.AccessToken(token), SourceIP: address}, true
}

func guestProblem(ctx context.Context, w http.ResponseWriter, operation string, err error) {
	if ctx.Err() != nil {
		return
	}
	switch {
	case errors.Is(err, controlstate.ErrGuestUnknown):
		writeBearerProblem(w)
	case errors.Is(err, authorization.ErrGuestIPChanged):
		writeProblem(w, http.StatusForbidden, controlv1.GuestIpChanged, "your IP changed since this guest trial started; run tnl auth login to continue")
	case errors.Is(err, controlstate.ErrGuestTrialSpent),
		errors.Is(err, controlstate.ErrShareInvalid), errors.Is(err, controlstate.ErrShareStale),
		errors.Is(err, controlstate.ErrShareIdempotency), errors.Is(err, controlstate.ErrShareLimit):
		writeControlStateProblem(ctx, w, operation, err)
	case errors.Is(err, controlstate.ErrProjectConfigurationInvalid), errors.Is(err, controlstate.ErrServiceAccess),
		errors.Is(err, controlstate.ErrServiceConflict):
		serviceVisitorError(ctx, w, operation, err)
	case errors.Is(err, controlstate.ErrPublisherIdentity), errors.Is(err, controlstate.ErrPublisherEnrollment), errors.Is(err, pgx.ErrNoRows):
		publisherProblem(ctx, w, operation, err)
	default:
		if !serviceaccess.WriteCredentialDeliveryProblem(w, err) {
			writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "guest operation is unavailable")
		}
	}
}
