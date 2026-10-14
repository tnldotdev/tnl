// package applicationlimits owns validation shared by control and publishers.
package applicationlimits

import "time"

// Valid checks the numeric limits after input-specific parsing. zero requests
// leaves the lifetime total uncapped; zero rate and concurrency select publisher defaults.
func Valid(requests, rateRequests, concurrency int, ratePer time.Duration) bool {
	return requests >= 0 && rateRequests >= 0 && concurrency >= 0 && ratePer >= 0 &&
		(rateRequests == 0) == (ratePer == 0)
}
