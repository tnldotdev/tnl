package visitorlease

import (
	"bytes"
	"crypto/ed25519"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func reservationPermission(t *testing.T, lease *Lease, source string) *Guard {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{'k'}, 32))
	permission := admission(t, lease, key, "first", time.Now().Add(time.Minute))
	guard, err := lease.Bind(permission, netip.MustParseAddr(source), func() {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(guard.Close)
	return guard
}

func nextReservation(t *testing.T, update Update, old tunnelv1.StreamReservation, sequence uint64) tunnelv1.StreamReservation {
	t.Helper()
	old.Sequence = sequence
	old.VisitorConnectionID = "vc_" + strings.Repeat(string(rune('E'+sequence)), 22)
	signReservationFixture(t, update.Allocations[old.AllocationID].ReservationKey, &old, old.SourceIP)
	return old
}

func TestReservationPreparedClaimsConsumeReplayAndProtectCommittedVisitor(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, update, header := allocationFixture(t)
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		source := netip.MustParseAddr(header.SourceIP)
		var stopped atomic.Int32
		old, err := lease.PrepareReservationFrom(header, source, func() {
			// callbacks may reenter the lease; no lease mutex covers stop work.
			lease.Current()
			stopped.Add(1)
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := old.Commit(nil); err == nil {
			t.Fatal("capacity proof substituted for visitor permission")
		}
		forged := nextReservation(t, update, header, 4)
		forged.Sequence++
		if _, err := lease.PrepareReservationFrom(forged, source, func() {}); err == nil {
			t.Fatal("forged sequence changed replay evidence")
		}
		newer := nextReservation(t, update, header, 3)
		current, err := lease.PrepareReservationFrom(newer, source, func() {})
		if err != nil || stopped.Load() != 1 {
			t.Fatal("newer ingress use did not replace only the pending claim", err)
		}
		old.Close()
		old.Close()
		permission := reservationPermission(t, lease, header.SourceIP)
		if err := old.Commit(permission); err == nil {
			t.Fatal("superseded setup committed permission")
		}
		for _, sequence := range []uint64{1, 2, 3} {
			if _, err := lease.PrepareReservationFrom(nextReservation(t, update, header, sequence), source, func() {}); err == nil {
				t.Fatal("equal or out-of-order reservation escaped the watermark", sequence)
			}
		}
		if err := current.Commit(reservationPermission(t, lease, "198.51.100.1")); err == nil {
			t.Fatal("permission crossed the source binding")
		}
		if err := current.Commit(permission); err != nil {
			t.Fatal("stale release cleared the current claim", err)
		}
		if _, err := lease.PrepareReservationFrom(nextReservation(t, update, header, 4), source, func() {}); err == nil {
			t.Fatal("newer capacity claim evicted an authorized visitor")
		}
		current.Close()
		if _, err := lease.PrepareReservationFrom(newer, source, func() {}); err == nil {
			t.Fatal("release forgot consumed setup replay evidence")
		}
		if stopped.Load() != 1 {
			t.Fatal("old cleanup invoked stop twice")
		}
	})
}

func TestReservationPreparedCommitRechecksCurrentPermissionAndExpiry(t *testing.T) {
	for _, change := range []string{"closed permission", "policy revision", "allocation expiry", "closed lease", "missing source"} {
		t.Run(change, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				lease, update, header := allocationFixture(t)
				if err := lease.Apply(lease.Begin(), update); err != nil {
					t.Fatal(err)
				}
				permission := reservationPermission(t, lease, header.SourceIP)
				if err := permission.AllowRenewal(); err != nil {
					t.Fatal(err)
				}
				claim, err := lease.PrepareReservation(header, func() {})
				if err != nil {
					t.Fatal(err)
				}
				defer claim.Close()
				if change != "missing source" {
					if err := claim.BindSource(netip.MustParseAddr(header.SourceIP)); err != nil {
						t.Fatal(err)
					}
				}
				switch change {
				case "closed permission":
					permission.Close()
				case "policy revision":
					update.View.VisitorPolicyRevision++
					if err := lease.Apply(lease.Begin(), update); err != nil {
						t.Fatal(err)
					}
				case "allocation expiry":
					time.Sleep(10 * time.Second)
					synctest.Wait()
				case "closed lease":
					lease.Close()
				}
				if err := claim.Commit(permission); err == nil {
					t.Fatal("commit accepted stale or incomplete authority")
				}
			})
		})
	}
}

func TestReservationPreparedCommitRacesNewIngressSequence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for range 32 {
			lease, update, header := allocationFixture(t)
			if err := lease.Apply(lease.Begin(), update); err != nil {
				t.Fatal(err)
			}
			permission := reservationPermission(t, lease, header.SourceIP)
			old, err := lease.PrepareReservationFrom(header, netip.MustParseAddr(header.SourceIP), func() {})
			if err != nil {
				t.Fatal(err)
			}
			newer := nextReservation(t, update, header, 2)
			var workers sync.WaitGroup
			var oldErr, newErr error
			var next *ReservationGuard
			workers.Go(func() { oldErr = old.Commit(permission) })
			workers.Go(func() {
				next, newErr = lease.PrepareReservationFrom(newer, netip.MustParseAddr(header.SourceIP), func() {})
			})
			workers.Wait()
			if (oldErr == nil) == (newErr == nil) {
				t.Fatal("commit and supersession both won or both lost", oldErr, newErr)
			}
			old.Close()
			if next != nil {
				if err := next.Commit(permission); err != nil {
					t.Fatal("old release damaged the winning claim", err)
				}
				next.Close()
			}
			lease.Close()
		}
	})
}
