package state

import (
	"crypto/sha256"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestIntegrationGuestTrialRequiresProvisionedIngressPool(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "guest_ingress_requirement")
	guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateGuestTrial(t.Context(), guest, "routes.example.test", now); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("unprovisioned ingress issued a guest trial: %v", err)
	}
	var trials, reservations int
	if err := d.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM control.guest_trials),
		(SELECT count(*) FROM control.managed_label_reservations WHERE label=$1)`, guest.NamespaceLabel).
		Scan(&trials, &reservations); err != nil || trials != 0 || reservations != 0 {
		t.Fatalf("failed issuance retained authority: %d/%d, %v", trials, reservations, err)
	}
	if err := d.EnsurePrimaryIngressPool(t.Context(), "192.0.2.10", "", now); err != nil {
		t.Fatal(err)
	}
	trial, err := d.CreateGuestTrial(t.Context(), guest, "routes.example.test", now)
	if err != nil || trial.IngressPoolID != PrimaryIngressPoolID {
		t.Fatalf("explicit ingress provisioning did not authorize the pinned trial: %+v, %v", trial, err)
	}
}

func TestIntegrationGuestTrialCredentialAndOneCurrentService(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "guest_trial")
	guest := newGuestTrialForTest(t, d, now)
	now = guestOperationTime(guest)
	credential := guestCredentialForTest(guest)
	var storedTrial string
	if err := d.pool.QueryRow(t.Context(), `SELECT row_to_json(trial)::text FROM control.guest_trials trial WHERE id=$1`, guest.ID).Scan(&storedTrial); err != nil || strings.Contains(storedTrial, guest.SourceIP.String()) {
		t.Fatalf("trial stored plaintext source: %v", err)
	}
	request := AllocateGuestDemoServiceRequest{Credential: credential, IdempotencyKey: "first", Target: guestLoopbackTarget(t), Now: now}
	first, err := d.AllocateGuestDemoService(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.GuestID != guest.ID || first.TeamID != "" || first.Endpoint == nil || first.Endpoint.Port != 443 ||
		!first.Ephemeral || first.ExpiresAt == nil || !first.ExpiresAt.Equal(guest.ExpiresAt) ||
		!first.CreatedAt.Equal(now) ||
		first.Endpoint.Hostname != "demo-1."+guest.NamespaceLabel+".routes.example.test" {
		t.Fatalf("allocation invented ownership or endpoint: %+v", first)
	}
	normalized := request
	normalized.Target += "/"
	recovered, err := d.AllocateGuestDemoService(t.Context(), normalized)
	if err != nil || recovered.ID != first.ID || !recovered.ExpiresAt.Equal(*first.ExpiresAt) {
		t.Fatalf("lost response recovery changed service: %+v, %v", recovered, err)
	}
	changed := request
	changed.Target = guestLoopbackTarget(t)
	if _, err := d.AllocateGuestDemoService(t.Context(), changed); !errors.Is(err, ErrServiceConflict) {
		t.Fatalf("changed request recovered original allocation: %v", err)
	}
	stored, err := d.GuestTrialByAccessToken(t.Context(), guest.Token)
	if err != nil || stored.ID != guest.ID || stored.NamespaceLabel != guest.NamespaceLabel {
		t.Fatalf("guest credential = %+v, %v", stored, err)
	}
	share, err := d.CreateGuestShare(t.Context(), credential, first.ID, "first-share", "trial", sha256.Sum256([]byte("reviewer-secret")), guest.ExpiresAt, now)
	if err != nil || share.GuestID != guest.ID || share.TeamID != "" || share.CreatedByIdentityID != "" ||
		share.Scope != "guest" || share.Label != "trial" || share.PreviewID != "" || len(share.ServiceIDs) != 1 ||
		share.ServiceIDs[0] != first.ID || !share.ExpiresAt.Equal(guest.ExpiresAt) {
		t.Fatalf("guest share = %+v, %v", share, err)
	}
	var delivery *CredentialDeliveryUnavailable
	if _, err := d.CreateGuestShare(t.Context(), credential, first.ID, "first-share", "trial", sha256.Sum256([]byte("other-secret")), guest.ExpiresAt, now); !errors.As(err, &delivery) || delivery.ResourceID != share.ID {
		t.Fatalf("share secret redelivery = %v", err)
	}
	short, err := d.CreateGuestShare(t.Context(), credential, first.ID, "short-share", "", sha256.Sum256([]byte("short-lived")), now.Add(time.Hour), now)
	if err != nil || !short.ExpiresAt.Equal(now.Add(time.Hour).UTC().Truncate(time.Microsecond)) {
		t.Fatalf("short share = %+v, %v", short, err)
	}
	if _, err := d.CreateGuestShare(t.Context(), credential, first.ID, "short-share", "", sha256.Sum256([]byte("short-lived")), now.Add(2*time.Hour), now); !errors.Is(err, ErrShareIdempotency) {
		t.Fatalf("changed share expiry = %v", err)
	}
	capped, err := d.CreateGuestShare(t.Context(), credential, first.ID, "capped-share", "", sha256.Sum256([]byte("capped")), now.Add(4*24*time.Hour), now)
	if err != nil || !capped.ExpiresAt.Equal(guest.ExpiresAt) {
		t.Fatalf("trial-bound share = %+v, %v", capped, err)
	}
	other := mustOpaqueID(t, opaqueid.ServicePrefix)
	if _, err := d.CreateGuestShare(t.Context(), credential, other, "other-share", "", sha256.Sum256([]byte("secret")), guest.ExpiresAt, now); !errors.Is(err, ErrShareStale) {
		t.Fatalf("shared unrelated service: %v", err)
	}
	q := controlstatedb.New(d.pool)
	if _, err := q.GetActiveShareForService(t.Context(), controlstatedb.GetActiveShareForServiceParams{ShareID: share.ID, ServiceID: first.ID, Now: timestamptz(now)}); err != nil {
		t.Fatal(err)
	}
	var pool, owner string
	var fakePrincipals, portClaims int
	if err := d.pool.QueryRow(t.Context(), `SELECT ingress_pool_id,guest_id,
		(SELECT count(*) FROM control.identities),(SELECT count(*) FROM control.service_port_claims)
		FROM control.services WHERE id=$1`, first.ID).Scan(&pool, &owner, &fakePrincipals, &portClaims); err != nil ||
		pool != PrimaryIngressPoolID || owner != guest.ID || fakePrincipals != 0 || portClaims != 0 {
		t.Fatalf("guest depended on fabricated identity or port: %s %s %d %d, %v", pool, owner, fakePrincipals, portClaims, err)
	}
	second := request
	second.IdempotencyKey, second.Now = "second", now.Add(time.Second)
	if _, err := d.AllocateGuestDemoService(t.Context(), second); !errors.Is(err, ErrServiceConflict) {
		t.Fatalf("allocated second current service: %v", err)
	}
	if err := d.DeleteGuestService(t.Context(), first.ID, credential, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AllocateGuestDemoService(t.Context(), request); !errors.Is(err, ErrServiceConflict) {
		t.Fatalf("terminal allocation was recreated: %v", err)
	}
	second.Now = now.Add(3 * time.Second)
	replacement, err := d.AllocateGuestDemoService(t.Context(), second)
	if err != nil || replacement.ID == first.ID || replacement.Endpoint.Hostname != "demo-2."+guest.NamespaceLabel+".routes.example.test" {
		t.Fatalf("replacement = %+v, %v", replacement, err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.guest_trials SET used_ready_ns=$2 WHERE id=$1`, guest.ID, int64(GuestReadyAllowance)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AllocateGuestDemoService(t.Context(), second); err != nil {
		t.Fatalf("READY exhaustion blocked recovery for cleanup: %v", err)
	}
	if err := d.DeleteGuestService(t.Context(), replacement.ID, credential, now.Add(4*time.Second)); err != nil {
		t.Fatalf("READY exhaustion blocked deletion: %v", err)
	}
	for range 2 {
		if err := d.DeleteGuestService(t.Context(), replacement.ID, credential, now.Add(4*time.Second)); err != nil {
			t.Fatalf("deletion was not idempotent: %v", err)
		}
	}
	second.IdempotencyKey, second.Now = "spent", now.Add(4*time.Second)
	if _, err := d.AllocateGuestDemoService(t.Context(), second); !errors.Is(err, ErrGuestTrialSpent) {
		t.Fatalf("spent trial allocated service: %v", err)
	}
	if _, err := q.GetActiveShareForService(t.Context(), controlstatedb.GetActiveShareForServiceParams{ShareID: share.ID, ServiceID: first.ID, Now: timestamptz(second.Now)}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("ended trial retained share: %v", err)
	}
}

func TestIntegrationGuestIssuanceSerializesOneNetwork(t *testing.T) {
	d, databaseURL, now := newControlStateIntegrationDatabaseWithURL(t, "guest_issuance")
	enableGuestTestIngress(t, d)
	other, err := Open(t.Context(), databaseURL, testStorageKey, "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Close)
	const callers = 40
	results := make(chan error, callers)
	var workers sync.WaitGroup
	for index := range callers {
		workers.Go(func() {
			guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
			if err == nil {
				owner := d
				if index%2 == 1 {
					owner = other
				}
				_, err = owner.CreateGuestTrial(t.Context(), guest, "routes.example.test", now)
			}
			results <- err
		})
	}
	workers.Wait()
	allowed, limited := 0, 0
	for range callers {
		err := <-results
		switch {
		case err == nil:
			allowed++
		case errors.Is(err, ErrGuestIssuance):
			limited++
		default:
			t.Fatal(err)
		}
	}
	if allowed != 32 || limited != callers-32 {
		t.Fatalf("allowed=%d limited=%d", allowed, limited)
	}
}

func TestIntegrationGuestTrialTracksReadyTime(t *testing.T) {
	f, _ := guestAuthorityFixture(t, true)
	before := f.stored(t)
	if err := f.database.CloseServiceRun(f.ctx, f.service.ID, f.run.RunID, f.run.Token, f.now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := time.Duration(f.stored(t).UsedReadyNs); got != before.ServingUntil.Time.Sub(before.ActiveReadyAt.Time) {
		t.Fatalf("settled READY time = %s", got)
	}
}

func TestIntegrationGuestHeartbeatRejectsExhaustedTrialAndCleanupRecordsOutcome(t *testing.T) {
	f, guest := guestAuthorityFixture(t, false)
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.guest_trials SET used_ready_ns=$2 WHERE id=$1`, guest.ID, int64(GuestReadyAllowance-2*time.Second)); err != nil {
		t.Fatal(err)
	}
	f.ready(t, f.now)
	deadline := f.stored(t).ReadyDeadline.Time
	if _, err := f.heartbeat(deadline); err == nil {
		t.Fatal("expired READY horizon renewed")
	}
	if closed, err := f.database.ExpireServiceRuns(t.Context(), deadline.Add(time.Second)); err != nil || closed != 1 {
		t.Fatalf("closed=%d, %v", closed, err)
	}
	stored := f.stored(t)
	if stored.ActiveServiceRunID.Valid || stored.EndReason.String != "ready_limit" {
		t.Fatalf("exhausted trial retained authority: %+v", stored)
	}
	stats, err := f.database.RecentGuestTrialStats(t.Context(), deadline.Add(time.Second))
	if err != nil || stats.Issued != 1 || stats.ReadyLimit != 1 || stats.Expired != 0 {
		t.Fatalf("trial totals=%+v, %v", stats, err)
	}
}

func TestIntegrationGuestExpiryRevokesCredentialAndForgetsIPDigests(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "guest_expiry")
	guest := newGuestTrialForTest(t, d, now)
	request := AllocateGuestDemoServiceRequest{Credential: guestCredentialForTest(guest), IdempotencyKey: "last", Target: guestLoopbackTarget(t), Now: guest.ExpiresAt.Add(-time.Second)}
	if _, err := d.AllocateGuestDemoService(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	request.Now = guest.ExpiresAt
	if _, err := d.AllocateGuestDemoService(t.Context(), request); !errors.Is(err, ErrGuestTrialSpent) {
		t.Fatalf("expired trial recovered authority: %v", err)
	}
	if _, err := d.ExpireServiceRuns(t.Context(), guest.ExpiresAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if removed, err := d.ForgetGuestPrivateState(t.Context(), guest.ExpiresAt.Add(time.Second)); err != nil || removed != 3 {
		t.Fatalf("scrubbed=%d, %v", removed, err)
	}
	if _, err := d.GuestTrialByAccessToken(t.Context(), guest.Token); !errors.Is(err, ErrGuestUnknown) {
		t.Fatalf("expired credential remains: %v", err)
	}
	var scrubbed bool
	if err := d.pool.QueryRow(t.Context(), `SELECT source_ip_digest IS NULL AND source_ip_key_id IS NULL AND issuance_ip_digest IS NULL
		AND credential_id IS NULL AND credential_hash IS NULL AND end_reason='expired' AND ended_at=expires_at
		FROM control.guest_trials WHERE id=$1`, guest.ID).Scan(&scrubbed); err != nil || !scrubbed {
		t.Fatalf("private trial state remains: %t, %v", scrubbed, err)
	}
	stats, err := d.RecentGuestTrialStats(t.Context(), guest.ExpiresAt.Add(time.Second))
	if err != nil || stats.Issued != 0 || stats.Allocated != 1 || stats.Expired != 1 {
		t.Fatalf("expiry totals=%+v, %v", stats, err)
	}
}

func TestIntegrationGuestExpiryClosesRunWithoutHeartbeat(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "ready_time_spent", true: "trial_expired"}[expired], func(t *testing.T) {
			age := time.Duration(0)
			if expired {
				age = GuestLifetime - 10*time.Second
			}
			f, guest := guestAuthorityFixture(t, false, age)
			at, reason := guest.ExpiresAt.Add(time.Second), "expired"
			if !expired {
				if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.guest_trials SET used_ready_ns=$2 WHERE id=$1`, guest.ID, int64(GuestReadyAllowance-2*time.Second)); err != nil {
					t.Fatal(err)
				}
				f.ready(t, f.now)
				at, reason = f.stored(t).ReadyDeadline.Time.Add(time.Second), "ready_limit"
			}
			want := 1
			if expired {
				want = 2 // the fixed trial expiration also deletes its service
			}
			if changed, err := f.database.ExpireServiceRuns(t.Context(), at); err != nil || changed != want {
				t.Fatalf("expired run/service count=%d, want %d: %v", changed, want, err)
			}
			if stored := f.stored(t); stored.EndReason.String != reason || stored.ActiveServiceRunID.Valid {
				t.Fatalf("trial outcome=%+v", stored)
			}
		})
	}
}
