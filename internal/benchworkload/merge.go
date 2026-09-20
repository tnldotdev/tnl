package benchworkload

import "errors"

func (r *VisitorResult) Merge(other VisitorResult) error {
	for _, count := range []int{other.Scheduled, other.Started, other.Completed, other.Successes, other.Failures, other.Timeouts, other.Missed, other.QueueExpired, other.Workers, other.QueueSlots, other.Rate} {
		if count < 0 {
			return errors.New("negative visitor count")
		}
	}
	if other.Scheduled != other.Started+other.Missed+other.QueueExpired || other.Started != other.Completed || other.Completed != other.Successes+other.Failures || other.Timeouts > other.Failures {
		return errors.New("inconsistent visitor accounting")
	}
	for _, pair := range [][2]*Histogram{{&r.QueueDelay, &other.QueueDelay}, {&r.DNS, &other.DNS}, {&r.Connect, &other.Connect}, {&r.TLS, &other.TLS}, {&r.FirstByte, &other.FirstByte}, {&r.Total, &other.Total}} {
		if err := pair[0].Merge(*pair[1]); err != nil {
			return err
		}
	}
	if r.StartedAt.IsZero() || other.StartedAt.Before(r.StartedAt) {
		r.StartedAt = other.StartedAt
	}
	r.OfferDuration = max(r.OfferDuration, other.OfferDuration)
	r.DrainDuration = max(r.DrainDuration, other.DrainDuration)
	r.Workers += other.Workers
	r.QueueSlots += other.QueueSlots
	r.Rate += other.Rate
	r.Scheduled += other.Scheduled
	r.Started += other.Started
	r.Completed += other.Completed
	r.Successes += other.Successes
	r.Failures += other.Failures
	r.Timeouts += other.Timeouts
	r.Missed += other.Missed
	r.QueueExpired += other.QueueExpired
	r.Bytes += other.Bytes
	for _, sample := range other.FailuresSample {
		if len(r.FailuresSample) < 8 {
			r.FailuresSample = append(r.FailuresSample, sample)
		}
	}
	return nil
}
