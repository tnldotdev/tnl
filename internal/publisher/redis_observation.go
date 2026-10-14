package publisher

import (
	"time"

	"github.com/tnldotdev/tnl/internal/inspection"
)

// RedisObservation is one completed command without its arguments or reply body.
type RedisObservation struct {
	ReceivedAt time.Time
	Command    string
	Result     inspection.Result
	Duration   time.Duration
}
