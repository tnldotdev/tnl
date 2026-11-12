package state

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestIntegrationWorkloadOptionalHardDuration(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "workload_optional_duration")
	ctx := t.Context()
	f := newRetainedVisitorFixture(t, d, now, retainedGitHubTrust(), 0, false)
	r, applied := f.project, f.environment
	exchange, key := retainedVisitorPreparation(t, f, now)
	prepared, err := d.PrepareEnvironmentVisitor(ctx, exchange, now)
	session := prepared.Session
	if err != nil || session.ExpiresAt != nil || !session.LeaseExpiresAt.Equal(now.Add(WorkloadLease)) {
		t.Fatal("omitted duration did not preserve independent proof and lease bounds", err)
	}
	current := session
	freshAt := func(at time.Time) PrepareEnvironmentVisitorRequest {
		fresh := exchange
		fresh.Proof.Execution.GitHub = new(*exchange.Proof.Execution.GitHub)
		fresh.Proof.Execution.IssuedAt, fresh.Proof.Execution.NotBefore, fresh.Proof.Execution.ExpiresAt = at.Unix(), at.Unix(), at.Add(5*time.Minute).Unix()
		fresh.Proof.Execution.GitHub.IssuedAt, fresh.Proof.Execution.GitHub.NotBefore, fresh.Proof.Execution.GitHub.ExpiresAt = fresh.Proof.Execution.IssuedAt, fresh.Proof.Execution.NotBefore, fresh.Proof.Execution.ExpiresAt
		fresh.Proof.Execution.GitHub.JTI = fmt.Sprintf("rotating-proof-%d", at.Unix())
		signRetainedVisitorPreparation(&fresh, key)
		return fresh
	}
	// cross both former limits without skipping a permission-lease fence.
	for step := time.Minute; step <= 6*time.Hour+time.Minute; step += time.Minute {
		at := now.Add(step)
		if !current.IdentityExpiresAt.After(at.Add(WorkloadLease)) {
			fresh := freshAt(at)
			proof, signature, audience := retainedVisitorAssertion(t, d, session, key, fresh.Proof.Execution)
			current, err = d.AttachEnvironmentVisitorAssertion(ctx, session.ID, session.Credential, proof, signature, audience, at)
			if err != nil {
				t.Fatal("continuous proof refresh failed", step, err)
			}
		}
		current, err = d.RenewEnvironmentVisitorSession(ctx, current.ID, current.Credential, signWorkloadRenewal(current, key), now.Add(step))
		if err != nil || current.ExpiresAt != nil || current.ID != session.ID || current.Credential != session.Credential || !reflect.DeepEqual(current.ServiceIDs, session.ServiceIDs) {
			t.Fatal("uncapped renewal acquired a default limit or changed authority", step, err)
		}
	}
	at := now.Add(6*time.Hour + 70*time.Second)
	fresh := freshAt(at)
	proof, signature, audience := retainedVisitorAssertion(t, d, session, key, fresh.Proof.Execution)
	attach := func(at time.Time) (WorkloadSession, error) {
		return d.AttachEnvironmentVisitorAssertion(ctx, session.ID, session.Credential, proof, signature, audience, at)
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
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
	applied, err = d.ApplyEnvironment(ctx, ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: applied.ID, ExpectedRevision: applied.MutationRevision, DefinitionRevision: definition.Revision, Targets: EnvironmentTargets{"api": {Address: "api.internal:3000"}}}, Now: at})
	if err != nil {
		t.Fatal(err)
	}
	want := now.Add(6*time.Hour + 2*time.Minute)
	// seed the durable session owner's narrowed deadline, anchored to original
	// creation. permissions are immutable; an environment cannot edit this fact.
	if _, err := d.pool.Exec(ctx, `UPDATE control.workload_sessions SET expires_at=created_at+($2::bigint*interval '1 second'),lease_expires_at=LEAST(lease_expires_at,created_at+($2::bigint*interval '1 second')) WHERE id=$1`, session.ID, int64((6*time.Hour+2*time.Minute)/time.Second)); err != nil {
		t.Fatal(err)
	}
	narrowed, err := attach(at.Add(time.Second))
	if err != nil || narrowed.ExpiresAt == nil || !narrowed.ExpiresAt.Equal(want) || narrowed.LeaseExpiresAt.After(want) || len(narrowed.ServiceIDs) != 1 {
		t.Fatal("attachment changed the creation-anchored hard deadline", err)
	}
	definition = environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}, "db": {Protocol: "postgres"}})
	if _, err := d.ApplyEnvironment(ctx, ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: applied.ID, ExpectedRevision: applied.MutationRevision, DefinitionRevision: definition.Revision, Targets: f.environment.Targets}, Now: at.Add(2 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	retained, err := attach(at.Add(3 * time.Second))
	if err != nil || retained.ExpiresAt == nil || !retained.ExpiresAt.Equal(want) || len(retained.ServiceIDs) != 1 {
		t.Fatal("omitting a later cap widened existing authority", err)
	}
	if _, err := attach(want); !errors.Is(err, ErrWorkloadExpired) {
		t.Fatal("fresh proof revived the absolute hard deadline", err)
	}
	if _, err := d.RenewEnvironmentVisitorSession(ctx, session.ID, session.Credential, signWorkloadRenewal(retained, key), want); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("key renewal revived the absolute hard deadline", err)
	}
}

func TestIntegrationWorkloadOptionalDurationMigration(t *testing.T) {
	d, url, now := newControlStateIntegrationDatabaseWithURL(t, "workload_duration_migration")
	f := newRetainedVisitorFixture(t, d, now, retainedGitHubTrust(), 3600, false)
	exchange, _ := retainedVisitorPreparation(t, f, now)
	prepared, err := d.PrepareEnvironmentVisitor(t.Context(), exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	session := prepared.Session
	if err := Migrate(t.Context(), url); err != nil {
		t.Fatal(err)
	}
	recovered, err := d.PrepareEnvironmentVisitor(t.Context(), exchange, now)
	if err != nil || !reflect.DeepEqual(recovered.Session, session) {
		t.Fatal("migration removed or extended a retained session's hard cap", err)
	}
}

func TestIntegrationWorkloadUncappedRetention(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "workload_uncapped_retention")
	f := newRetainedVisitorFixture(t, d, now, retainedGitHubTrust(), 0, false)
	exchange, _ := retainedVisitorPreparation(t, f, now)
	prepared, err := d.PrepareEnvironmentVisitor(t.Context(), exchange, now)
	session := prepared.Session
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
