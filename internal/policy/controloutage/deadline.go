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
