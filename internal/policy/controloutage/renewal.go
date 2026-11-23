package controloutage

import (
	"math/rand/v2"
	"time"
)

const DefaultServiceRunLease = 90 * time.Second

// RenewalDelay uses the granted lifetime, not a second local lease policy.
// the configured interval is an upper bound; jitter spreads fleet renewals.
func RenewalDelay(maximum time.Duration, renewedAt, expiresAt time.Time) time.Duration {
	delay := min(maximum, expiresAt.Sub(renewedAt)/3)
	if delay <= 0 {
		return max(time.Millisecond, maximum)
	}
	return max(time.Millisecond, time.Duration(float64(delay)*(0.8+rand.Float64()*0.2)))
}
