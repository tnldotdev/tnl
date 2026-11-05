package state

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/workloadproof"
)

func TestIntegrationWorkloadOptionalHardDuration(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "workload_optional_duration")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	policy := r.Configuration.Workloads["test"]
	policy.MaxDurationSeconds = 0
	r.Configuration.Workloads["test"] = policy
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	exchange, key := workloadExchange(t, r, now)
	session, err := d.ExchangeWorkload(ctx, exchange, now)
	if err != nil || session.ExpiresAt != nil || !session.LeaseExpiresAt.Equal(now.Add(WorkloadLease)) {
		t.Fatal("omitted duration did not preserve independent proof and lease bounds", err)
	}
	current := session
	freshAt := func(at time.Time) ExchangeWorkloadRequest {
		fresh := exchange
		fresh.Execution.GitHub = new(*exchange.Execution.GitHub)
		fresh.Execution.IssuedAt, fresh.Execution.NotBefore, fresh.Execution.ExpiresAt = at.Unix(), at.Unix(), at.Add(5*time.Minute).Unix()
		fresh.Execution.GitHub.IssuedAt, fresh.Execution.GitHub.NotBefore, fresh.Execution.GitHub.ExpiresAt = fresh.Execution.IssuedAt, fresh.Execution.NotBefore, fresh.Execution.ExpiresAt
		fresh.Execution.GitHub.JTI = fmt.Sprintf("rotating-proof-%d", at.Unix())
		signWorkloadRequest(&fresh, key)
		return fresh
	}
	// cross both former limits without skipping a permission-lease fence.
	for step := time.Minute; step <= 6*time.Hour+time.Minute; step += time.Minute {
		at := now.Add(step)
		if !current.IdentityExpiresAt.After(at.Add(WorkloadLease)) {
			fresh := freshAt(at)
			current, err = d.AttachWorkloadAssertion(ctx, session.ID, session.Credential, fresh.Execution, ed25519.Sign(key, workloadproof.Attach(session.ID, fresh.Execution.AssertionDigest)), at)
			if err != nil {
				t.Fatal("continuous proof refresh failed", step, err)
			}
		}
		current, err = d.RenewWorkloadSession(ctx, current.ID, current.Credential, signWorkloadRenewal(current, key), now.Add(step))
		if err != nil || current.ExpiresAt != nil || current.ID != session.ID || current.Credential != session.Credential || !reflect.DeepEqual(current.ServiceIDs, session.ServiceIDs) {
			t.Fatal("uncapped renewal acquired a default limit or changed authority", step, err)
		}
	}
	at := now.Add(6*time.Hour + 70*time.Second)
	fresh := freshAt(at)
	attach := func(at time.Time) (WorkloadSession, error) {
		return d.AttachWorkloadAssertion(ctx, session.ID, session.Credential, fresh.Execution, ed25519.Sign(key, workloadproof.Attach(session.ID, fresh.Execution.AssertionDigest)), at)
	}
	refreshed, err := attach(at)
	if err != nil || refreshed.ExpiresAt != nil || !refreshed.IdentityExpiresAt.Equal(at.Add(5*time.Minute)) || refreshed.RenewalSequence != current.RenewalSequence {
		t.Fatal("proof refresh changed an uncapped session's renewal clock", err)
	}
	for _, service := range refreshed.ServiceIDs {
		authorized, err := d.CheckWorkloadService(ctx, session.Credential, service, at)
		if err != nil || authorized.ValidUntil.After(refreshed.LeaseExpiresAt) || authorized.ValidUntil.After(refreshed.IdentityExpiresAt) {
			t.Fatal("uncapped visitor authority escaped the accepted lease", err)
		}
	}
	r.ExpectedRevision, r.Now = applied.Revision, at
	policy.MaxDurationSeconds = int((6*time.Hour + 2*time.Minute) / time.Second)
	policy.Services = []string{"api"}
	r.Configuration.Workloads["test"] = policy
	applied, err = d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	narrowed, err := attach(at.Add(time.Second))
	want := now.Add(6*time.Hour + 2*time.Minute)
	if err != nil || narrowed.ExpiresAt == nil || !narrowed.ExpiresAt.Equal(want) || narrowed.LeaseExpiresAt.After(want) || len(narrowed.ServiceIDs) != 1 {
		t.Fatal("apply did not anchor a new hard limit to original session creation", err)
	}
	r.ExpectedRevision, r.Now = applied.Revision, at.Add(2*time.Second)
	policy.MaxDurationSeconds, policy.Services = 0, []string{"api", "db"}
	r.Configuration.Workloads["test"] = policy
	if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	retained, err := attach(at.Add(3 * time.Second))
	if err != nil || retained.ExpiresAt == nil || !retained.ExpiresAt.Equal(want) || len(retained.ServiceIDs) != 1 {
		t.Fatal("omitting a later cap widened existing authority", err)
	}
	if _, err := attach(want); !errors.Is(err, ErrWorkloadExpired) {
		t.Fatal("fresh proof revived the absolute hard deadline", err)
	}
	if _, err := d.RenewWorkloadSession(ctx, session.ID, session.Credential, signWorkloadRenewal(retained, key), want); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("key renewal revived the absolute hard deadline", err)
	}
}

func TestIntegrationWorkloadOptionalDurationMigration(t *testing.T) {
	d, url, now := newControlStateIntegrationDatabaseWithURL(t, "workload_duration_migration")
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	if _, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	exchange, _ := workloadExchange(t, r, now)
	session, err := d.ExchangeWorkload(t.Context(), exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	provider := workloadTestMigrationProvider(t, url)
	if _, err := provider.DownTo(t.Context(), 3); err != nil {
		t.Fatal(err)
	}
	if err := d.Readiness(t.Context()); err == nil {
		t.Fatal("serving accepted the old mandatory-cap schema")
	}
	if err := Migrate(t.Context(), url); err != nil {
		t.Fatal(err)
	}
	recovered, err := d.ExchangeWorkload(t.Context(), exchange, now)
	if err != nil || !reflect.DeepEqual(recovered, session) {
		t.Fatal("migration removed or extended a retained session's hard cap", err)
	}
}

func TestIntegrationWorkloadUncappedRetention(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "workload_uncapped_retention")
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	policy := r.Configuration.Workloads["test"]
	policy.MaxDurationSeconds = 0
	r.Configuration.Workloads["test"] = policy
	if _, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	exchange, _ := workloadExchange(t, r, now)
	session, err := d.ExchangeWorkload(t.Context(), exchange, now)
	if err != nil || session.ExpiresAt != nil {
		t.Fatal("fixture was not uncapped", err)
	}
	if _, err := d.CleanupWorkloads(t.Context(), session.IdentityExpiresAt.Add(WorkloadHistoryRetention+time.Second), 100); err != nil {
		t.Fatal(err)
	}
	var retained bool
	if err := d.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM control.workload_sessions WHERE id=$1)`, session.ID).Scan(&retained); err != nil || retained {
		t.Fatal("expired uncapped session leaked its credential and replay state", err)
	}
}
