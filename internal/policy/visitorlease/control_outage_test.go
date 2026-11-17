package visitorlease

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestRepeatedControlObservationCannotRestartServingClock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, update, key := fixture(t)
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		original, _, _ := lease.Current()
		var stopped atomic.Int64
		guard, err := lease.Bind(admission(t, lease, key, "first", time.Now().Add(time.Minute)),
			netip.MustParseAddr("192.0.2.1"), func() { stopped.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		defer guard.Close()
		for range 3 {
			time.Sleep(3 * time.Second)
			if err := lease.Apply(lease.Begin(), update); err != nil {
				t.Fatal(err)
			}
			current, enabled, _ := lease.Current()
			if !enabled || !current.ValidUntil.Equal(original.ValidUntil) || !current.ObservedAt.Equal(original.ObservedAt) {
				t.Fatal("repeated observation restarted its serving allowance")
			}
			if !current.AuthorityTime(time.Now()).Equal(original.AuthorityTime(time.Now())) {
				t.Fatal("repeated observation restarted the credential expiry clock")
			}
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if stopped.Load() != 1 {
			t.Fatal("repeated observations kept active traffic past its original deadline")
		}
		if err := lease.Apply(lease.Begin(), update); !errors.Is(err, ErrUpdate) {
			t.Fatal("expired observation revived authority", err)
		}
	})
}

func TestRepeatedControlObservationStillAppliesLearnedDisablement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, update, key := fixture(t)
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		var stopped atomic.Int64
		guard, err := lease.Bind(admission(t, lease, key, "first", time.Now().Add(time.Minute)),
			netip.MustParseAddr("192.0.2.1"), func() { stopped.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		defer guard.Close()
		time.Sleep(time.Second)
		update.Enabled = false
		update.View.VisitorPolicyRevision++
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		if _, enabled, _ := lease.Current(); enabled || stopped.Load() != 1 {
			t.Fatal("deadline fence hid learned disablement")
		}
	})
}

func TestRepeatedControlObservationHonorsShorterIssuedDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, update, key := fixture(t)
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		original, _, _ := lease.Current()
		var stopped atomic.Int64
		guard, err := lease.Bind(admission(t, lease, key, "first", time.Now().Add(time.Minute)),
			netip.MustParseAddr("192.0.2.1"), func() { stopped.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		defer guard.Close()
		time.Sleep(3 * time.Second)
		update.View.ValidUntil = update.View.ObservedAt.Add(5 * time.Second)
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		current, enabled, _ := lease.Current()
		if !enabled || !current.ValidUntil.Equal(original.ObservedAt.Add(5*time.Second)) {
			t.Fatal("shorter deadline was anchored to the later request")
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if stopped.Load() != 1 {
			t.Fatal("earlier issued expiry did not stop active traffic")
		}
	})
}

func TestPolicyLeaseRepeatedAbsoluteExpiryCannotRecoverSpentLatency(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, update, key := fixture(t)
		first := lease.Begin()
		until := first.StartedAt.Add(time.Minute)
		update.View.ObservedAt, update.View.ValidUntil = first.StartedAt, until
		if err := lease.Apply(first, update); err != nil {
			t.Fatal(err)
		}
		var stopped atomic.Int64
		guard, err := lease.Bind(admission(t, lease, key, "first", until.Add(time.Hour)), netip.MustParseAddr("192.0.2.1"), func() { stopped.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		defer guard.Close()
		time.Sleep(2 * time.Second)
		later := lease.Begin()
		// control observed this call earlier than its local request start because
		// the first request spent more time waiting before observation.
		update.View.ObservedAt = first.StartedAt.Add(time.Second)
		if err := lease.Apply(later, update); err != nil {
			t.Fatal(err)
		}
		view, enabled, _ := lease.Current()
		if !enabled || !view.ValidUntil.Equal(until) {
			t.Fatal("unchanged absolute authority acquired another local second", view.ValidUntil, until)
		}
		time.Sleep(time.Until(until))
		synctest.Wait()
		if stopped.Load() != 1 {
			t.Fatal("repeated absolute expiry retained traffic")
		}
	})
}

func TestPolicyLeaseFreshPolicyCannotReanchorAcceptedCredentialExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, update, key := fixture(t)
		first := lease.Begin()
		control := first.StartedAt.Add(time.Second)
		update.View.ObservedAt, update.View.ValidUntil = control, control.Add(time.Minute)
		time.Sleep(2 * time.Second)
		if err := lease.Apply(first, update); err != nil {
			t.Fatal(err)
		}
		permission := admission(t, lease, key, "first", control.Add(4*time.Second))
		var stopped atomic.Int64
		guard, err := lease.Bind(permission, netip.MustParseAddr("192.0.2.1"), func() { stopped.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		defer guard.Close()
		time.Sleep(time.Second)
		// a faster, successful policy response is fresh policy evidence, not a
		// renewal of the same signed token's already accepted local deadline.
		update.View.ObservedAt = first.StartedAt.Add(3500 * time.Millisecond)
		update.View.ValidUntil = update.View.ObservedAt.Add(time.Minute)
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if stopped.Load() != 1 {
			t.Fatal("fresh policy moved the accepted credential deadline")
		}
		if err := guard.Renew(permission); err == nil {
			t.Fatal("expired guard was revived")
		}
	})
}
