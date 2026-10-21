// package applicationlimits owns validation shared by control and publishers.
package applicationlimits

import (
	"errors"
	"time"
)

// Limits applies to one publication. zero values select protocol defaults;
// Requests is an optional lifetime total, not a replenishing quota.
type Limits struct {
	Requests     int
	RateRequests int
	RatePer      time.Duration
	RateBurst    int
	Concurrency  int
}

func (l Limits) Valid() bool {
	return Valid(l.Requests, l.RateRequests, l.Concurrency, l.RatePer) &&
		l.RateBurst >= 0 && (l.RateBurst == 0 || l.RateRequests > 0)
}

func (l Limits) Validate() error {
	if !l.Valid() {
		return errors.New("application limits must be positive and rate requires count and period")
	}
	return nil
}

func (l Limits) Defaults(tcp bool) Limits {
	if l.Concurrency == 0 {
		l.Concurrency = 64
		if tcp {
			l.Concurrency = 24
		}
	}
	if l.RateRequests == 0 && l.RatePer == 0 {
		l.RateRequests, l.RatePer, l.RateBurst = 60, time.Second, 60
		if tcp {
			l.RateRequests, l.RateBurst = 10, 20
		}
	}
	if l.RateBurst == 0 {
		l.RateBurst = l.RateRequests
	}
	return l
}

// Valid checks numeric limits after input-specific parsing. zero requests means
// no lifetime cap; zero rate and concurrency select publisher defaults.
func Valid(requests, rateRequests, concurrency int, ratePer time.Duration) bool {
	return requests >= 0 && rateRequests >= 0 && concurrency >= 0 && ratePer >= 0 &&
		(rateRequests == 0) == (ratePer == 0)
}
