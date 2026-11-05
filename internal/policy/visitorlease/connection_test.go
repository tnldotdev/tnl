package visitorlease

import (
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestConnectionBoundClosesIdleTransportWithoutRevivingExpiredGuard(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, update, _ := fixture(t)
		update.BoundConnections = true
		update.View.ValidUntil = time.Now().Add(3 * time.Second)
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		var stopped atomic.Int64
		guard, err := lease.BindConnection(func() { stopped.Add(1) })
		if err != nil || guard == nil {
			t.Fatal("restricted policy did not bind transport lifetime", err)
		}
		defer guard.Close()
		time.Sleep(time.Second)
		pending := lease.Begin()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if stopped.Load() != 1 {
			t.Fatal("idle connection survived its local bound")
		}
		update.View.ObservedAt, update.View.ValidUntil = pending.StartedAt, pending.StartedAt.Add(10*time.Second)
		if err := lease.Apply(pending, update); !errors.Is(err, ErrUpdate) {
			t.Fatal("expired guard accepted in-flight renewal", err)
		}
		fresh := lease.Begin()
		update.View.ObservedAt, update.View.ValidUntil = fresh.StartedAt, fresh.StartedAt.Add(10*time.Second)
		if err := lease.Apply(fresh, update); err != nil {
			t.Fatal(err)
		}
		time.Sleep(11 * time.Second)
		synctest.Wait()
		if stopped.Load() != 1 {
			t.Fatal("fresh snapshot revived an expired connection")
		}
	})
}

func TestOrdinaryPolicyRetainsRequestLevelConnectionLifetime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, update, _ := fixture(t)
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		var stopped atomic.Int64
		guard, err := lease.BindConnection(func() { stopped.Add(1) })
		if err != nil || guard != nil {
			t.Fatal("ordinary transport acquired a guest lifetime", err)
		}
		time.Sleep(11 * time.Second)
		synctest.Wait()
		if stopped.Load() != 0 {
			t.Fatal("ordinary connection lifetime changed")
		}
	})
}
