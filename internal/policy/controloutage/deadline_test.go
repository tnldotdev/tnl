package controloutage

import (
	"errors"
	"testing"
	"time"
)

func TestLocalDeadlineSpendsLatencyWithoutControlClockExtension(t *testing.T) {
	started := time.Now()
	for _, offset := range []time.Duration{-time.Hour, 0, time.Hour} {
		t.Run(offset.String(), func(t *testing.T) {
			observed := started.Add(offset)
			deadline, err := LocalDeadline(started, observed, observed.Add(DefaultTolerance), started.Add(2*time.Second))
			if err != nil || !deadline.Equal(started.Add(DefaultTolerance)) {
				t.Fatalf("deadline = %v, error = %v", deadline, err)
			}
			if remaining := deadline.Sub(started.Add(2 * time.Second)); remaining != DefaultTolerance-2*time.Second {
				t.Fatalf("response latency extended allowance: %v", remaining)
			}
		})
	}
}

func TestLocalDeadlineHonorsEarlierActualExpiry(t *testing.T) {
	started := time.Now()
	observed := started.Add(time.Hour)
	for _, earlier := range []time.Duration{time.Second, 3 * time.Second, time.Minute} {
		fixedExpiry := observed.Add(earlier)
		deadline, err := LocalDeadline(started, observed, fixedExpiry, started)
		if err != nil || !deadline.Equal(started.Add(earlier)) {
			t.Fatalf("earlier expiry %v: %v, %v", earlier, deadline, err)
		}
		if _, err := LocalDeadline(started, observed, fixedExpiry, started.Add(earlier)); !errors.Is(err, ErrDeadline) {
			t.Fatalf("expired response accepted: %v", err)
		}
	}
}

func TestLocalDeadlineRejectsInvalidAndLateObservations(t *testing.T) {
	started := time.Now()
	for _, test := range []struct {
		name                          string
		started, observed, until, now time.Time
	}{
		{"missing request", time.Time{}, started, started.Add(time.Second), started},
		{"missing observation", started, time.Time{}, started.Add(time.Second), started},
		{"backward local time", started, started, started.Add(time.Second), started.Add(-time.Second)},
		{"zero duration", started, started, started, started},
		{"negative duration", started, started, started.Add(-time.Second), started},
		{"latency spends allowance", started, started, started.Add(time.Second), started.Add(time.Second)},
		{"response after expiry", started, started, started.Add(time.Second), started.Add(2 * time.Second)},
		{"unrepresentable duration", started, started, started.AddDate(1000, 0, 0), started},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := LocalDeadline(test.started, test.observed, test.until, test.now); !errors.Is(err, ErrDeadline) {
				t.Fatalf("invalid observation accepted: %v", err)
			}
		})
	}
}
