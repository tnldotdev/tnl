package service

import (
	"time"

	"github.com/tnldotdev/tnl/internal/policy/controloutage"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// acceptServingConfirmation converts control's serving facts before the run or
// its observations can use them. assignment/revision checks remain in Bound.
func acceptServingConfirmation(previous controloutage.Confirmation, started time.Time, state controlv1.ServiceRunState, now time.Time) (controloutage.Confirmation, controlv1.ServiceRunState, error) {
	next, err := previous.Confirm(started, state.ObservedAt, state.PublisherExpiresAt, now)
	if err != nil {
		return previous, state, err
	}
	state.PublisherExpiresAt = next.Deadline
	return next, state, nil
}
