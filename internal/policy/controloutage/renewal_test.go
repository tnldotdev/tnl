package controloutage

import (
	"testing"
	"time"
)

func TestRenewalUsesGrantedLifetimeAndBoundedJitter(t *testing.T) {
	now := time.Now()
	for range 100 {
		delay := RenewalDelay(time.Hour, now, now.Add(3*time.Second))
		if delay < 800*time.Millisecond || delay > time.Second {
			t.Fatal("renewal followed a local duration instead of the granted lease", delay)
		}
		delay = RenewalDelay(100*time.Millisecond, now, now.Add(time.Minute))
		if delay < 80*time.Millisecond || delay > 100*time.Millisecond {
			t.Fatal("configured maximum was not respected", delay)
		}
	}
	if delay := RenewalDelay(time.Second, now, now); delay != time.Second {
		t.Fatal("invalid lifetime created a tight renewal loop", delay)
	}
}
