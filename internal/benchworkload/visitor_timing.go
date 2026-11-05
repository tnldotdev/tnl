package benchworkload

import "time"

// VisitorTimings is an opt-in, caller-preallocated diagnostic buffer. Run owns
// its entries until workers join. each offset uses the same monotonic epoch;
// JSON wall-clock adjustments cannot change slot identity or elapsed times.
type VisitorTimings struct {
	Start    time.Time              `json:"phase_start"`
	Requests []VisitorRequestTiming `json:"requests"`
}

type VisitorRequestTiming struct {
	Slot                   int           `json:"slot"`
	ResultIndex            int           `json:"result_index"`
	Scheduled              time.Duration `json:"scheduled_ns"`
	Offered                time.Duration `json:"offered_ns"`
	Missed                 bool          `json:"missed"`
	QueueExpired           bool          `json:"queue_expired"`
	Started                time.Duration `json:"started_ns"`
	Completed              time.Duration `json:"completed_ns"`
	RequestReturned        time.Duration `json:"request_returned_ns"`
	CollectorWaitStarted   time.Duration `json:"collector_wait_started_ns"`
	CollectorAcquired      time.Duration `json:"collector_acquired_ns"`
	CallbackStarted        time.Duration `json:"callback_started_ns"`
	CallbackCompleted      time.Duration `json:"callback_completed_ns"`
	CollectorUnlockStarted time.Duration `json:"collector_unlock_started_ns"`
	CollectorReleased      time.Duration `json:"collector_released_ns"`
}
