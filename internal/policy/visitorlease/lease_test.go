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
	update := Update{View: visitortoken.View{Issuer: "https://control.example.test", Scope: scope, Hostname: "preview.example.test", Port: 443, VisitorPolicyRevision: 1,
		ObservedAt: time.Now(), ValidUntil: time.Now().Add(visitortoken.PolicyLifetime)}.WithVerificationKeys(map[string]ed25519.PublicKey{"first": key.Public().(ed25519.PublicKey)}), KeyRevision: 1, Enabled: true, Snapshot: true}
	return lease, update, key
}

func TestLeaseRejectsUnverifiedEvidence(t *testing.T) {
	lease, update, _ := fixture(t)
	started := lease.Begin()
	update.View.ObservedAt, update.View.ValidUntil = started.StartedAt, started.StartedAt.Add(visitortoken.PolicyLifetime)
	if err := lease.Apply(started, update); err != nil {
		t.Fatal(err)
	}
	if _, err := lease.Bind(visitortoken.VerifiedPermission{}, netip.MustParseAddr("192.0.2.1"), func() {}); err == nil {
		t.Fatal("unsigned facts entered a current visitor lease")
	}
}

func TestPolicyFutureRenewalWaitsForCoverageWithoutExtendingPriorDeadline(t *testing.T) {
	for _, covered := range []bool{false, true} {
		t.Run(map[bool]string{false: "uncovered", true: "covered"}[covered], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				lease, update, key := fixture(t)
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
				if err := guard.AllowRenewal(); err != nil {
					t.Fatal(err)
				}
				prior, err := guard.Deadline()
				if err != nil {
					t.Fatal(err)
				}
				futureFacts := permission.Facts()
				futureFacts.VisitorPolicyRevision = 2
				futureFacts.ExpiresAt = time.Now().Add(2 * time.Minute)
				future := signedAdmission(t, lease, key, "first", futureFacts)
				if err := guard.Renew(future); err != nil {
					t.Fatal("verified future permission could not wait for policy", err)
				}
				if got, err := guard.Deadline(); err != nil || !got.Equal(prior) {
					t.Fatal("pending renewal extended old authority", err)
				}
				time.Sleep(2 * time.Second)
				update.View.ObservedAt, update.View.ValidUntil = time.Now(), time.Now().Add(10*time.Second)
				if covered {
					update.View.VisitorPolicyRevision = 2
				}
				if err := lease.Apply(lease.Begin(), update); err != nil {
					t.Fatal(err)
				}
				deadline, err := guard.Deadline()
				if err != nil || covered && !deadline.After(prior) || !covered && !deadline.Equal(prior) {
					t.Fatal("policy coverage did not govern renewal activation", err)
				}
				time.Sleep(8*time.Second + time.Millisecond)
				synctest.Wait()
				if (stopped.Load() == 0) != covered {
					t.Fatal("future permission revived or extended an uncovered admission")
				}
				if !covered && guard.Renew(future) == nil {
					t.Fatal("late renewal revived expired traffic")
				}
			})
		})
	}
}

func TestPolicyNativeMetadataFenceRejectsPendingRenewal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, update, key := fixture(t)
		update.View.MetadataRevision = 1
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		permission := admission(t, lease, key, "first", time.Now().Add(time.Minute))
		var stopped atomic.Int64
		guard, err := lease.BindNative(permission, netip.MustParseAddr("192.0.2.1"), 1, func() { stopped.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		defer guard.Close()
		if err := guard.AllowRenewal(); err != nil {
			t.Fatal(err)
		}
		futureFacts := permission.Facts()
		futureFacts.VisitorPolicyRevision = 2
		if err := guard.Renew(signedAdmission(t, lease, key, "first", futureFacts)); err != nil {
			t.Fatal(err)
		}
		update.View.MetadataRevision, update.View.VisitorPolicyRevision = 2, 2
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		if stopped.Load() != 1 {
			t.Fatal("permission renewal moved an active stream to changed service metadata")
		}
	})
}

func admission(t *testing.T, lease *Lease, key ed25519.PrivateKey, id string, expires time.Time) visitortoken.VerifiedPermission {
	t.Helper()
	view, enabled, _ := lease.Current()
	if !enabled {
		t.Fatal("policy was not prepared")
	}
	permission := visitortoken.Permission{Scope: view.Scope, Hostname: view.Hostname, Port: view.Port, VisitorPolicyRevision: view.VisitorPolicyRevision, Subject: visitortoken.Browser{IdentityID: "ident_" + strings.Repeat("A", 22), SessionID: "cs_" + strings.Repeat("B", 22)}, ExpiresAt: expires}
	return signedAdmission(t, lease, key, id, permission)
}

func signedAdmission(t *testing.T, lease *Lease, key ed25519.PrivateKey, id string, permission visitortoken.Permission) visitortoken.VerifiedPermission {
	t.Helper()
	view, enabled, _ := lease.Current()
	if !enabled {
		t.Fatal("policy was not prepared")
	}
	token, err := visitortoken.Sign(view.Issuer, id, key, permission, view.AuthorityTime(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	verified, err := visitortoken.VerifyBearerRenewalProof(token, view, time.Now())
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
