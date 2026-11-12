package state

import "time"

// authorization clocks keep entry-time issuance budgets separate from current
// authority checks. elapsed database waits spend the original request's budget.
type authorizationClock struct{ entered, started time.Time }

func newAuthorizationClock(now time.Time) authorizationClock {
	// a real request timestamp already carries its monotonic entry clock. do
	// not restart that clock after proof preparation: doing so subtracts the
	// preparation time and can mistake a concurrent renewal for clock rollback.
	// synthetic/database timestamps have no monotonic reading; keep their
	// explicit epoch and measure only work performed after entering this call.
	if now != now.Round(0) {
		return authorizationClock{entered: now, started: now}
	}
	return authorizationClock{entered: now, started: time.Now()}
}

func (c authorizationClock) current() time.Time { return c.entered.Add(time.Since(c.started)) }
