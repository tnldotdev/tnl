package state

import (
	"testing"
	"time"
)

func TestAuthorizationClockRetainsRealRequestEntry(t *testing.T) {
	// model a request timestamp captured before preparing its signed proof.
	// no sleep is needed: the monotonic timestamp itself contains the elapsed
	// second. restarting the clock here incorrectly loses that whole second.
	entered := time.Now().Add(-time.Second)
	before := time.Now()
	clock := newAuthorizationClock(entered)
	if got := clock.current(); got.Before(before) {
		t.Fatalf("lost real request elapsed time: %s < %s", got, before)
	}
	// tests and persisted values deliberately use another epoch. do not replace
	// those explicit deadlines with wall-clock time.
	synthetic := time.Unix(1700000000, 0)
	got := newAuthorizationClock(synthetic).current()
	if got.Before(synthetic) || got.After(synthetic.Add(time.Second)) {
		t.Fatal("lost synthetic epoch", got)
	}
}
