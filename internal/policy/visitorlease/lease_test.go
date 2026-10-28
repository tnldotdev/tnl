package visitorlease

import (
	"crypto/ed25519"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func fixture(t *testing.T) (*Lease, Update, ed25519.PrivateKey) {
	t.Helper()
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: "url_" + strings.Repeat("A", 22)}
	lease, err := New(scope, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lease.Close)
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", 32)))
	now := time.Now()
	update := Update{View: visitortoken.View{Issuer: "https://control.example.test", Scope: scope, Hostname: "preview.example.test", Port: 443, VisitorPolicyRevision: 1,
		ObservedAt: now, ValidUntil: now.Add(visitortoken.PolicyLifetime)}.WithVerificationKeys(map[string]ed25519.PublicKey{"first": key.Public().(ed25519.PublicKey)}), KeyRevision: 1, Enabled: true, Snapshot: true}
	return lease, update, key
}

func admission(t *testing.T, lease *Lease, key ed25519.PrivateKey, id string, expires time.Time) visitortoken.VerifiedPermission {
	t.Helper()
	view, enabled, _ := lease.Current()
	if !enabled {
		t.Fatal("policy was not prepared")
	}
	permission := visitortoken.Permission{Scope: view.Scope, Hostname: view.Hostname, Port: view.Port, VisitorPolicyRevision: view.VisitorPolicyRevision, Subject: visitortoken.Browser{IdentityID: "ident_" + strings.Repeat("A", 22), SessionID: "cs_" + strings.Repeat("B", 22)}, ExpiresAt: expires}
	token, err := visitortoken.Sign(view.Issuer, id, key, permission, view.AuthorityTime(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	verified, err := visitortoken.VerifyBearer(token, view, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func TestPolicyLeaseOutageExpiresTrafficAndFencesDelayedRenewal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, update, key := fixture(t)
		first := lease.Begin()
		update.View.ObservedAt, update.View.ValidUntil = first.StartedAt, first.StartedAt.Add(10*time.Second)
		time.Sleep(2 * time.Second)
		if err := lease.Apply(first, update); err != nil {
			t.Fatal(err)
		}
		permission := admission(t, lease, key, "first", time.Now().Add(time.Minute))
		var stopped atomic.Int64
		guard, err := lease.Bind(permission, netip.MustParseAddr("192.0.2.1"), func() { stopped.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		defer guard.Close()
		time.Sleep(6 * time.Second)
		delayed := lease.Begin()
		update.View.ObservedAt, update.View.ValidUntil = time.Now(), time.Now().Add(10*time.Second)
		time.Sleep(3 * time.Second)
		synctest.Wait()
		if stopped.Load() != 1 {
			t.Fatal("expired policy did not stop active traffic exactly once")
		}
		if _, enabled, _ := lease.Current(); enabled {
			t.Fatal("process lease or token outlived expired visitor policy")
		}
		if err := lease.Apply(delayed, update); !errors.Is(err, ErrUpdate) {
			t.Fatal("delayed renewal restored expired authority", err)
		}
		recovery := lease.Begin()
		if !recovery.Snapshot {
			t.Fatal("outage recovery did not require a snapshot")
		}
		update.View.ObservedAt, update.View.ValidUntil = time.Now(), time.Now().Add(10*time.Second)
		if err := lease.Apply(recovery, update); err != nil {
			t.Fatal("fresh snapshot could not recover new admissions", err)
		}
		if stopped.Load() != 1 {
			t.Fatal("snapshot revived an old admission")
		}
	})
}

func TestPolicyRenewableGuardCannotExtendItsLastConfirmedRevisionDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, update, key := fixture(t)
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		var stopped atomic.Int64
		guard, err := lease.Bind(admission(t, lease, key, "first", time.Now().Add(time.Minute)), netip.MustParseAddr("192.0.2.1"), func() { stopped.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		defer guard.Close()
		if err := guard.AllowRenewal(); err != nil {
			t.Fatal(err)
		}
		for range 4 {
			time.Sleep(2 * time.Second)
			update.View.VisitorPolicyRevision = 2
			update.View.ObservedAt, update.View.ValidUntil = time.Now(), time.Now().Add(10*time.Second)
			if err := lease.Apply(lease.Begin(), update); err != nil {
				t.Fatal(err)
			}
			if stopped.Load() != 0 {
				t.Fatal("revision refresh canceled an explicitly renewing request before its prior deadline")
			}
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if stopped.Load() != 1 {
			t.Fatal("unrelated fresh policy extended an old permission beyond ten seconds")
		}
		if err := guard.AllowRenewal(); err == nil {
			t.Fatal("expired admission was revived by registering renewal")
		}
	})
}

func TestPolicyLeaseRejectsMissingAndOutOfOrderUpdates(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, update, _ := fixture(t)
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
		older := lease.Begin()
		time.Sleep(time.Second)
		newer := lease.Begin()
		update.Snapshot, update.AfterRevision, update.Events = false, 1, []int64{2, 3}
		update.View.VisitorPolicyRevision = 3
		update.View.ObservedAt, update.View.ValidUntil = time.Now(), time.Now().Add(10*time.Second)
		if err := lease.Apply(newer, update); err != nil {
			t.Fatal(err)
		}
		before, _, _ := lease.Current()
		update.View.VisitorPolicyRevision, update.Events = 2, []int64{2}
		if err := lease.Apply(older, update); !errors.Is(err, ErrUpdate) {
			t.Fatal("old response replaced newer authority", err)
		}
		missing := lease.Begin()
		update.AfterRevision, update.View.VisitorPolicyRevision, update.Events = 3, 5, []int64{5}
		if err := lease.Apply(missing, update); !errors.Is(err, ErrUpdate) {
			t.Fatal("renewal skipped a covered update", err)
		}
		after, _, _ := lease.Current()
		if !after.ValidUntil.Equal(before.ValidUntil) || after.VisitorPolicyRevision != 3 {
			t.Fatal("failed update extended the last confirmed deadline")
		}
		update.Snapshot = true
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal("complete snapshot could not recover compacted events", err)
		}
	})
}

func TestPolicyKeyRevocationCancelsOnlyAffectedAdmissions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, update, first := fixture(t)
		second := ed25519.NewKeyFromSeed([]byte(strings.Repeat("b", 32)))
		update.View = update.View.WithVerificationKeys(map[string]ed25519.PublicKey{"first": first.Public().(ed25519.PublicKey), "second": second.Public().(ed25519.PublicKey)})
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		var revoked, unrelated atomic.Int64
		one, err := lease.Bind(admission(t, lease, first, "first", time.Now().Add(time.Minute)), netip.MustParseAddr("192.0.2.1"), func() { revoked.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		defer one.Close()
		two, err := lease.Bind(admission(t, lease, second, "second", time.Now().Add(time.Minute)), netip.MustParseAddr("192.0.2.1"), func() { unrelated.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		defer two.Close()
		update.Snapshot, update.AfterRevision, update.KeyRevision = false, 1, 2
		update.View = update.View.WithVerificationKeys(map[string]ed25519.PublicKey{"second": second.Public().(ed25519.PublicKey)})
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		if revoked.Load() != 1 || unrelated.Load() != 0 {
			t.Fatal("revocation crossed the affected admission boundary")
		}
		lease.Close()
		if unrelated.Load() != 1 {
			t.Fatal("shutdown retained an admission")
		}
		view, enabled, _ := lease.Current()
		if enabled || !view.ValidUntil.IsZero() {
			t.Fatal("closed owner retained a usable policy view")
		}
	})
}

func TestPolicyLeaseRejectsUnverifiedEvidence(t *testing.T) {
	lease, update, _ := fixture(t)
	if err := lease.Apply(lease.Begin(), update); err != nil {
		t.Fatal(err)
	}
	guard, err := lease.Bind(visitortoken.VerifiedPermission{}, netip.MustParseAddr("192.0.2.1"), func() {})
	if guard != nil || !errors.Is(err, visitortoken.ErrPolicy) {
		t.Fatal("zero verified evidence bound a visitor guard", err)
	}
}

func TestPolicyLeaseOwnsAppliedIPValue(t *testing.T) {
	lease, update, key := fixture(t)
	var hashKey [32]byte
	hashKey[0] = 1
	policy := func(prefix string) ippolicy.Policy {
		t.Helper()
		entry, err := ippolicy.Hash(hashKey, netip.MustParsePrefix(prefix))
		if err != nil {
			t.Fatal(err)
		}
		value, err := ippolicy.New(hashKey, []ippolicy.Entry{entry})
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	caller := policy("192.0.2.0/24")
	update.IP = &caller
	if err := lease.Apply(lease.Begin(), update); err != nil {
		t.Fatal(err)
	}
	permission := admission(t, lease, key, "first", time.Now().Add(time.Minute))
	var stopped atomic.Int64
	guard, err := lease.Bind(permission, netip.MustParseAddr("192.0.2.1"), func() { stopped.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	if outside, err := lease.Bind(permission, netip.MustParseAddr("198.51.100.1"), func() {}); outside != nil || !errors.Is(err, visitortoken.ErrPolicy) {
		t.Fatal("initial restricted policy admitted an outside source")
	}
	caller = policy("198.51.100.0/24")
	allowed, err := lease.Bind(permission, netip.MustParseAddr("192.0.2.1"), func() {})
	if err != nil {
		t.Fatal("caller replaced the installed IP allowlist", err)
	}
	allowed.Close()
	outside, err := lease.Bind(permission, netip.MustParseAddr("198.51.100.1"), func() {})
	if outside != nil || !errors.Is(err, visitortoken.ErrPolicy) {
		t.Fatal("caller broadened installed IP policy")
	}
	if stopped.Load() != 0 {
		t.Fatal("caller mutation canceled installed traffic")
	}
	// only a new authenticated application replaces the snapshot and cancels
	// admissions no longer allowed by that observation.
	if err := lease.Apply(lease.Begin(), update); err != nil {
		t.Fatal(err)
	}
	if stopped.Load() != 1 {
		t.Fatal("authenticated IP replacement did not cancel affected traffic once")
	}
	outside, err = lease.Bind(permission, netip.MustParseAddr("198.51.100.1"), func() {})
	if err != nil {
		t.Fatal("new authenticated policy did not take effect", err)
	}
	outside.Close()
}

func TestPolicyLeaseIPNilAndEmptyRemainDistinct(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(map[bool]string{false: "no filter", true: "empty deny all"}[empty], func(t *testing.T) {
			lease, update, key := fixture(t)
			if empty {
				var hashKey [32]byte
				hashKey[0] = 1
				value, err := ippolicy.New(hashKey, nil)
				if err != nil {
					t.Fatal(err)
				}
				update.IP = &value
			}
			if err := lease.Apply(lease.Begin(), update); err != nil {
				t.Fatal(err)
			}
			guard, err := lease.Bind(admission(t, lease, key, "first", time.Now().Add(time.Minute)), netip.MustParseAddr("192.0.2.1"), func() {})
			if empty {
				if guard != nil || !errors.Is(err, visitortoken.ErrPolicy) {
					t.Fatal("empty policy did not deny traffic")
				}
			} else {
				if err != nil {
					t.Fatal("nil IP policy installed a filter", err)
				}
				guard.Close()
			}
		})
	}
}

func TestPolicyLeaseCallerIPReplacementAfterApplyDoesNotRaceBind(t *testing.T) {
	lease, update, key := fixture(t)
	var hashKey [32]byte
	hashKey[0] = 1
	entry, err := ippolicy.Hash(hashKey, netip.MustParsePrefix("192.0.2.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	original, err := ippolicy.New(hashKey, []ippolicy.Entry{entry})
	if err != nil {
		t.Fatal(err)
	}
	deny, err := ippolicy.New(hashKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	caller := original
	update.IP = &caller
	if err := lease.Apply(lease.Begin(), update); err != nil {
		t.Fatal(err)
	}
	permission := admission(t, lease, key, "first", time.Now().Add(time.Minute))
	start, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		<-start // caller owns its value again only after Apply has returned.
		for range 1000 {
			caller = deny
			caller = original
		}
	}()
	close(start)
	for range 1000 {
		guard, err := lease.Bind(permission, netip.MustParseAddr("192.0.2.1"), func() {})
		if err != nil {
			t.Error("caller mutation changed installed admission")
			break
		}
		guard.Close()
	}
	<-done
}

func TestPolicyClockSkewAndSlowRepliesDoNotExtendExpiry(t *testing.T) {
	for _, skew := range []time.Duration{-time.Hour, time.Hour} {
		synctest.Test(t, func(t *testing.T) {
			lease, update, key := fixture(t)
			request := lease.Begin()
			control := request.StartedAt.Add(skew)
			update.View.ObservedAt, update.View.ValidUntil = control, control.Add(10*time.Second)
			time.Sleep(2 * time.Second)
			if err := lease.Apply(request, update); err != nil {
				t.Fatal(err)
			}
			permission := admission(t, lease, key, "first", control.Add(3*time.Second))
			var expired atomic.Bool
			guard, err := lease.Bind(permission, netip.MustParseAddr("192.0.2.1"), func() { expired.Store(true) })
			if err != nil {
				t.Fatal(err)
			}
			defer guard.Close()
			time.Sleep(time.Second)
			synctest.Wait()
			if !expired.Load() {
				t.Fatal("clock skew or response completion extended token expiry")
			}
			view, enabled, _ := lease.Current()
			if !enabled || !view.ValidUntil.Equal(request.StartedAt.Add(10*time.Second)) {
				t.Fatal("policy deadline was anchored to response completion")
			}
		})
	}
}
