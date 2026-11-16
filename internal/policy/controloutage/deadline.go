// package controloutage defines the operator's serving allowance and converts
// authenticated control observations to conservative local deadlines. it owns
// no refresh workers, connection detection, or authority decisions.
package controloutage

import (
	"errors"
	"time"
)

const DefaultTolerance = 5 * time.Minute

var ErrDeadline = errors.New("control serving deadline is invalid or expired")

// Confirmation retains both control's evidence and its accepted local deadline.
// revision and identity checks remain with the owner.
type Confirmation struct {
	ObservedAt, ValidUntil, Deadline time.Time
}

func (previous Confirmation) Confirm(startedAt, observedAt, validUntil, now time.Time) (Confirmation, error) {
	deadline, err := LocalDeadline(startedAt, observedAt, validUntil, now)
	if err != nil {
		return Confirmation{}, err
	}
	if !previous.Deadline.IsZero() {
		if !now.Before(previous.Deadline) || observedAt.Before(previous.ObservedAt) {
			return Confirmation{}, ErrDeadline
		}
		if !observedAt.After(previous.ObservedAt) || !validUntil.After(previous.ValidUntil) {
			deadline = minDeadline(deadline, previous.Deadline.Add(min(0, validUntil.Sub(previous.ValidUntil))))
		}
	}
	if !now.Before(deadline) {
		return Confirmation{}, ErrDeadline
	}
	return Confirmation{ObservedAt: observedAt, ValidUntil: validUntil, Deadline: deadline}, nil
}

func minDeadline(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// LocalDeadline spends response latency from the request's local start time.
// observedAt and validUntil must come from the same authenticated response.
// callers retain revision, identity, and request-order fences; a failed call
// must never replace a previously accepted deadline.
func LocalDeadline(startedAt, observedAt, validUntil, now time.Time) (time.Time, error) {
	duration := validUntil.Sub(observedAt)
	if startedAt.IsZero() || observedAt.IsZero() || now.Before(startedAt) ||
		duration <= 0 || !observedAt.Add(duration).Equal(validUntil) {
		return time.Time{}, ErrDeadline
	}
	deadline := startedAt.Add(duration)
	if !now.Before(deadline) {
		return time.Time{}, ErrDeadline
	}
	return deadline, nil
}
