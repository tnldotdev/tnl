package benchworkload

import (
	"errors"
	"slices"
)

func (r *VisitorResult) Merge(other VisitorResult) error {
	for _, count := range []int{other.Scheduled, other.Started, other.Completed, other.Successes, other.Failures, other.Timeouts, other.Missed, other.QueueExpired, other.Workers, other.QueueSlots, other.Rate} {
		if count < 0 {
			return errors.New("negative visitor count")
		}
	}
	if other.Scheduled != other.Started+other.Missed+other.QueueExpired || other.Started != other.Completed || other.Completed != other.Successes+other.Failures || other.Timeouts > other.Failures {
		return errors.New("inconsistent visitor accounting")
	}
	staged := *r
	for _, histogram := range []*Histogram{&staged.QueueDelay, &staged.DNS, &staged.Connect, &staged.TLS, &staged.FirstByte, &staged.Total} {
		histogram.BoundsMilliseconds = slices.Clone(histogram.BoundsMilliseconds)
		histogram.Counts = slices.Clone(histogram.Counts)
	}
	staged.FailuresSample = slices.Clone(staged.FailuresSample)
	for _, pair := range [][2]*Histogram{{&staged.QueueDelay, &other.QueueDelay}, {&staged.DNS, &other.DNS}, {&staged.Connect, &other.Connect}, {&staged.TLS, &other.TLS}, {&staged.FirstByte, &other.FirstByte}, {&staged.Total, &other.Total}} {
		if err := pair[0].Merge(*pair[1]); err != nil {
			return err
		}
	}
	if staged.StartedAt.IsZero() || other.StartedAt.Before(staged.StartedAt) {
		staged.StartedAt = other.StartedAt
	}
	staged.OfferDuration = max(staged.OfferDuration, other.OfferDuration)
	staged.DrainDuration = max(staged.DrainDuration, other.DrainDuration)
	staged.Workers += other.Workers
	staged.QueueSlots += other.QueueSlots
	staged.Rate += other.Rate
	staged.Scheduled += other.Scheduled
	staged.Started += other.Started
	staged.Completed += other.Completed
	staged.Successes += other.Successes
	staged.Failures += other.Failures
	staged.Timeouts += other.Timeouts
	staged.Missed += other.Missed
	staged.QueueExpired += other.QueueExpired
	staged.Bytes += other.Bytes
	for _, sample := range other.FailuresSample {
		if len(staged.FailuresSample) < 8 {
			staged.FailuresSample = append(staged.FailuresSample, sample)
		}
	}
	*r = staged
	return nil
}
