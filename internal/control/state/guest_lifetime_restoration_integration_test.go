package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func TestIntegrationGuestRestoredExactCloseReturnsAndSingleSettlement(t *testing.T) {
	f, _ := guestAuthorityFixture(t, true)
	if _, err := f.heartbeat(f.now.Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	before := f.stored(t)
	ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	const callers = 8
	start := make(chan struct{})
	results := make(chan error, callers)
	for range callers {
		workers.Go(func() {
			<-start
			results <- f.database.CloseServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.now.Add(11*time.Second))
		})
	}
	close(start)
	for index := range callers {
		if err := awaitIntegrationResult(t, ctx, results); err != nil {
			t.Errorf("exact-token concurrent close %d returned an error: %v", index, err)
		}
	}
	workers.Wait()
	after := f.stored(t)
	want := before.UsedReadyNs + int64(before.ServingUntil.Time.Sub(before.ActiveReadyAt.Time))
	if after.UsedReadyNs != want || after.ActiveServiceRunID.Valid || after.ActiveReadyAt.Valid ||
		!after.ServingUntil.Time.Equal(before.ServingUntil.Time) {
		t.Fatalf("concurrent close did not settle the issued tail exactly once: %+v, want used=%d", after, want)
	}
	for range 2 {
		if err := f.database.CloseServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.now.Add(12*time.Second)); err != nil {
			t.Error("exact-token close retry returned an error", err)
		}
	}
	retried := f.stored(t)
	if retried.UsedReadyNs != after.UsedReadyNs || retried.ActiveServiceRunID.Valid ||
		!retried.ServingUntil.Time.Equal(after.ServingUntil.Time) {
		t.Fatal("close retry charged the guest again or changed issued authority")
	}
}

func TestIntegrationGuestRestoredOldRunAndPreparationCannotReviveAfterReplacement(t *testing.T) {
	f, _ := guestAuthorityFixture(t, true)
	oldRun, oldPreparation := f.run, f.prep
	issued := f.stored(t)
	if err := f.database.CloseServiceRun(f.ctx, f.service.ID, oldRun.RunID, oldRun.Token, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	at := issued.ServingUntil.Time.Add(time.Second)
	f.prepareAndStart(t, "restored-replacement", at)
	f.ready(t, at)
	if f.run.RunID == oldRun.RunID || f.run.RunNumber != oldRun.RunNumber+1 {
		t.Fatal("replacement reused the old run identity or number")
	}
	before := f.stored(t)
	if _, err := f.database.HeartbeatServiceRun(f.ctx, f.service.ID, oldRun.RunID, oldRun.Token, at,
		ServiceRunHealth{Healthy: true, StreamCapacity: 32}); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("old guest run heartbeat revived authority after replacement", err)
	}
	if _, err := f.database.StartServiceRun(f.ctx, f.service.ID, oldRun.RunID, oldRun.RunNumber, f.publisher, at); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("old guest start replay revived authority after replacement", err)
	}
	if _, err := f.database.PrepareServiceRun(f.ctx, f.service.ID, f.publisher, oldPreparation.IdempotencyKey, at,
		ServiceRunRequest{Metadata: f.service.ServiceMetadata}); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("old guest preparation key recovered serving authority", err)
	}
	if after := f.stored(t); !reflect.DeepEqual(after, before) || after.ActiveServiceRunID.String != f.run.RunID {
		t.Fatal("old-run denials changed the replacement or its guest accounting")
	}
	if _, err := f.heartbeat(at.Add(time.Second)); err != nil {
		t.Fatal("old-run rejection damaged the current guest publication", err)
	}
}

func TestIntegrationGuestRestoredPublisherOnlyFiveSecondPolicyAndPostCloseDenial(t *testing.T) {
	f, guest := guestAuthorityFixture(t, true)
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: f.service.ID}
	raw := bytes.Repeat([]byte{9}, 32)
	share, err := f.database.CreateGuestShare(t.Context(), guestCredentialForTest(guest), f.service.ID,
		"restored-five-second-share", "", sha256.Sum256(raw), guest.ExpiresAt, f.now)
	if err != nil {
		t.Fatal(err)
	}
	source := ShareTokenSource{ShareID: share.ID, Secret: base64.RawURLEncoding.EncodeToString(raw)}
	before := f.stored(t)
	horizon := before.ServingUntil.Time
	// observe the last five seconds of the actually issued fixed lease; do
	// not introduce a caller-selected five-second or arbitrary long lease.
	at := horizon.Add(-5 * time.Second)
	if !at.After(before.ActiveReadyAt.Time) || !before.ReadyDeadline.Time.After(horizon) || !guest.ExpiresAt.After(horizon) {
		t.Fatal("publisher lease is not the unique limiting guest authority")
	}
	policy, err := f.database.ReadPublisherVisitorPolicy(f.ctx, scope, f.run.RunID, f.run.RunNumber, f.run.Token, 0, at)
	if err != nil || policy.Policy.ConnectionDeadline == nil || !policy.Policy.ConnectionDeadline.Equal(horizon) ||
		!policy.Policy.ValidUntil.Equal(horizon) || !policy.Policy.ObservedAt.Before(horizon) ||
		policy.Policy.ObservedAt.Add(visitortoken.PolicyLifetime).Before(horizon) {
		t.Fatal("publisher-only five-second policy escaped the fixed issued deadline", policy.Policy, err)
	}
	issued, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, at)
	// signed visitor tokens retain whole seconds, never a rounded-up lease.
	if err != nil || !issued.Permission.ExpiresAt.Equal(horizon.Truncate(time.Second)) {
		t.Fatal("visitor token did not retain the exact publisher-only wire deadline", issued.Permission.ExpiresAt, horizon, err)
	}
	admission, err := readIngressServiceRun(t.Context(), f.database, f.ingress.IngressLeaseIdentity, f.service.ID, f.run.RunID, at)
	if err != nil || !admission.ValidUntil.After(at) || admission.ValidUntil.After(horizon) {
		t.Fatal("ingress admission exceeded the publisher-only deadline", admission, err)
	}
	for _, expired := range []time.Time{horizon, horizon.Add(time.Second)} {
		if _, err := f.database.ReadPublisherVisitorPolicy(f.ctx, scope, f.run.RunID, f.run.RunNumber, f.run.Token, 0, expired); err == nil {
			t.Error("expired guest run returned publisher policy")
		}
		if _, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, expired); !errors.Is(err, ErrVisitorPermission) {
			t.Error("expired publisher lease issued a visitor token", err)
		}
	}
	if err := f.database.CloseServiceRun(f.ctx, f.service.ID, f.run.RunID, f.run.Token, horizon.Add(2*time.Second)); err != nil {
		t.Fatal("exact-token close after publisher expiry failed", err)
	}
	settled := f.stored(t)
	want := before.UsedReadyNs + int64(horizon.Sub(before.ActiveReadyAt.Time))
	if settled.UsedReadyNs != want || settled.ActiveServiceRunID.Valid {
		t.Fatal("late close charged beyond issued publisher authority", settled)
	}
	if _, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, horizon.Add(3*time.Second)); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("closed guest run issued a final visitor token", err)
	}
	if after := f.stored(t); !reflect.DeepEqual(after, settled) {
		t.Fatal("post-close token denial mutated settled guest accounting")
	}
}

func TestIntegrationGuestRestoredExpiryOverridesOverlongPersistedPublisherLease(t *testing.T) {
	for _, bound := range []string{"credential", "ready"} {
		t.Run(bound, func(t *testing.T) {
			age := time.Duration(0)
			if bound == "credential" {
				age = GuestLifetime - 10*time.Second
			}
			f, guest := guestAuthorityFixture(t, false, age)
			if bound == "ready" {
				if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.guest_trials SET used_ready_ns=$2 WHERE id=$1`,
					guest.ID, int64(GuestReadyAllowance-2*time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			f.ready(t, f.now)
			before := f.stored(t)
			deadline := before.ReadyDeadline.Time
			reason := "ready_limit"
			if bound == "credential" {
				deadline, reason = guest.ExpiresAt, "expired"
			}
			// a corrupted or legacy persisted lease must not bypass the
			// independent guest fence. this is not a requested long lease.
			if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.service_runs SET publisher_expires_at=$2 WHERE id=$1`,
				f.run.RunID, deadline.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			var overlong bool
			if err := f.database.pool.QueryRow(t.Context(), `SELECT closed_at IS NULL AND publisher_expires_at>$2
				FROM control.service_runs WHERE id=$1`, f.run.RunID, deadline).Scan(&overlong); err != nil ||
				!overlong || !before.ActiveServiceRunID.Valid || before.ServingUntil.Time.After(deadline) {
				t.Fatal("fixture did not retain an open overlong run with separately bounded guest authority", err)
			}
			count, err := f.database.ExpireServiceRuns(t.Context(), deadline)
			if err != nil {
				t.Fatal(err)
			}
			var closed, deleted int
			if err := f.database.pool.QueryRow(t.Context(), `SELECT
				(SELECT count(*) FROM control.service_runs WHERE id=$1 AND state='closed' AND closed_at IS NOT NULL AND NOT assignments_open),
				(SELECT count(*) FROM control.services WHERE id=$2 AND deleted_at IS NOT NULL)`,
				f.run.RunID, f.service.ID).Scan(&closed, &deleted); err != nil || closed != 1 || count != 1+deleted {
				t.Fatalf("guest expiry closed/deleted/count=%d/%d/%d, want one run plus actual service cleanup: %v", closed, deleted, count, err)
			}
			after := f.stored(t)
			want := min(int64(GuestReadyAllowance), before.UsedReadyNs+int64(before.ServingUntil.Time.Sub(before.ActiveReadyAt.Time)))
			if after.ActiveServiceRunID.Valid || after.EndReason.String != reason || after.UsedReadyNs != want {
				t.Fatalf("guest expiry bypassed its own fence or settled the overlong lease: %+v, want reason=%s used=%d", after, reason, want)
			}
			if count, err := f.database.ExpireServiceRuns(t.Context(), deadline); err != nil || count != 0 {
				t.Fatalf("repeated guest expiry count=%d, want 0: %v", count, err)
			}
			if repeated := f.stored(t); !reflect.DeepEqual(repeated, after) {
				t.Fatal("repeated expiry settled guest authority twice")
			}
		})
	}
}

func TestIntegrationGuestRestoredPreparationPolicyUsesRemainingReadyAllowance(t *testing.T) {
	f, guest := guestAuthorityFixture(t, false)
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.guest_trials SET used_ready_ns=$2 WHERE id=$1`,
		guest.ID, int64(GuestReadyAllowance-6*time.Second)); err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: f.service.ID}
	for _, elapsed := range []time.Duration{time.Second, 4 * time.Second, 7 * time.Second} {
		at := f.now.Add(elapsed)
		run, err := f.heartbeat(at)
		if err != nil {
			t.Fatal(err)
		}
		policy, err := f.database.ReadPublisherVisitorPolicy(f.ctx, scope, f.run.RunID, f.run.RunNumber, f.run.Token, 0, at)
		want := minTime(run.ExpiresAt, policy.Policy.ObservedAt.Add(6*time.Second)).Truncate(time.Microsecond)
		if err != nil || policy.Policy.ConnectionDeadline == nil || !policy.Policy.ConnectionDeadline.Equal(want) ||
			policy.Policy.ConnectionDeadline.After(policy.Policy.ObservedAt.Add(6*time.Second)) ||
			policy.Policy.ValidUntil.After(*policy.Policy.ConnectionDeadline) {
			t.Fatal("preparation policy ignored the remaining ready allowance", policy.Policy, err)
		}
		before := f.stored(t)
		if before.UsedReadyNs != int64(GuestReadyAllowance-6*time.Second) ||
			before.ActiveReadyAt.Valid || before.ReadyDeadline.Valid || before.ServingUntil.Valid {
			t.Fatal("preparation policy observation charged ready time", before)
		}
	}
}
