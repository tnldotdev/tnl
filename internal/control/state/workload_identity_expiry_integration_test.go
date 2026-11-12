package state

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestIntegrationWorkloadIdentityExpiryAndRefresh(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "workload_identity_expiry")
	ctx := t.Context()
	f := newRetainedVisitorFixture(t, d, now, retainedGitHubTrust(), 3600, false)
	r, applied := f.project, f.environment
	exchange, key := retainedVisitorPreparation(t, f, now)
	exchange.Proof.Execution.ExpiresAt = now.Add(45 * time.Second).Unix()
	exchange.Proof.Execution.GitHub.ExpiresAt = exchange.Proof.Execution.ExpiresAt
	signRetainedVisitorPreparation(&exchange, key)
	prepared, err := d.PrepareEnvironmentVisitor(ctx, exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	session := prepared.Session
	if !session.IdentityExpiresAt.Equal(now.Add(45*time.Second)) || !session.LeaseExpiresAt.Equal(session.IdentityExpiresAt) || !session.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatal("initial lease did not honor proof expiry independently of the fixed window")
	}
	renewed, err := d.RenewEnvironmentVisitorSession(ctx, session.ID, session.Credential, signWorkloadRenewal(session, key), now.Add(31*time.Second))
	if err != nil || !renewed.LeaseExpiresAt.Equal(session.IdentityExpiresAt) {
		t.Fatal("signed key renewal outlived platform proof", err)
	}
	fresh := exchange
	fresh.Proof.Execution.GitHub = new(*exchange.Proof.Execution.GitHub)
	fresh.Proof.Execution.IssuedAt, fresh.Proof.Execution.NotBefore, fresh.Proof.Execution.ExpiresAt = now.Add(35*time.Second).Unix(), now.Add(35*time.Second).Unix(), now.Add(335*time.Second).Unix()
	fresh.Proof.Execution.GitHub.IssuedAt, fresh.Proof.Execution.GitHub.NotBefore, fresh.Proof.Execution.GitHub.ExpiresAt = fresh.Proof.Execution.IssuedAt, fresh.Proof.Execution.NotBefore, fresh.Proof.Execution.ExpiresAt
	fresh.Proof.Execution.GitHub.JTI = "fresh-proof"
	signRetainedVisitorPreparation(&fresh, key)
	attach := func(request PrepareEnvironmentVisitorRequest, at time.Time) (WorkloadSession, error) {
		proof, signature, audience := retainedVisitorAssertion(t, d, session, key, request.Proof.Execution)
		return d.AttachEnvironmentVisitorAssertion(ctx, session.ID, session.Credential, proof, signature, audience, at)
	}
	refreshed, err := attach(fresh, now.Add(35*time.Second))
	if err != nil || !refreshed.IdentityExpiresAt.Equal(now.Add(335*time.Second)) || !refreshed.LeaseExpiresAt.Equal(now.Add(121*time.Second)) || !refreshed.ExpiresAt.Equal(*session.ExpiresAt) || refreshed.ID != session.ID || refreshed.Subject != session.Subject || refreshed.Credential != session.Credential || refreshed.RenewalSequence != renewed.RenewalSequence {
		t.Fatalf("same-identity refresh: identity=%s want=%s lease=%s want=%s fixed=%s want=%s sequence=%d want=%d err=%v", refreshed.IdentityExpiresAt, now.Add(335*time.Second), refreshed.LeaseExpiresAt, now.Add(121*time.Second), refreshed.ExpiresAt, session.ExpiresAt, refreshed.RenewalSequence, renewed.RenewalSequence, err)
	}
	if older, err := attach(exchange, now.Add(36*time.Second)); err != nil || !reflect.DeepEqual(older, refreshed) {
		t.Fatal("older still-valid proof shortened or extended current authority", err)
	}
	if retry, err := attach(fresh, now.Add(65*time.Second)); err != nil || !reflect.DeepEqual(retry, refreshed) {
		t.Fatal("replayed platform proof moved the accepted renewal clock", err)
	}
	wrong := fresh
	wrong.Proof.Execution.GitHub = new(*fresh.Proof.Execution.GitHub)
	wrong.Proof.Execution.GitHub.CheckRunID, wrong.Proof.Execution.GitHub.JTI = "999", "other-execution"
	signRetainedVisitorPreparation(&wrong, key)
	if _, err := attach(wrong, now.Add(66*time.Second)); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("another execution extended this identity", err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.workload_sessions SET lease_expires_at=identity_expires_at+interval '1 second' WHERE id=$1`, session.ID); err == nil {
		t.Fatal("schema allowed a lease beyond verified identity expiry")
	}
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
	if _, err := d.ApplyEnvironment(ctx, ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: applied.ID, ExpectedRevision: applied.MutationRevision, DefinitionRevision: definition.Revision, Targets: EnvironmentTargets{"api": {Address: "api.internal:3000"}}}, Now: now}); err != nil {
		t.Fatal(err)
	}
	narrowed, err := attach(fresh, now.Add(67*time.Second))
	if err != nil || len(narrowed.ServiceIDs) != 1 || !narrowed.IdentityExpiresAt.Equal(refreshed.IdentityExpiresAt) {
		t.Fatal("proof refresh restored narrowed service rights", err)
	}
	authorization, err := d.CheckWorkloadService(ctx, session.Credential, narrowed.ServiceIDs[0], now.Add(68*time.Second))
	if err != nil || authorization.ValidUntil.After(narrowed.LeaseExpiresAt) || authorization.ValidUntil.After(narrowed.IdentityExpiresAt) {
		t.Fatal("visitor authority outlived the proof-bound lease", err)
	}
	if next, err := d.RenewEnvironmentVisitorSession(ctx, session.ID, session.Credential, signWorkloadRenewal(narrowed, key), now.Add(69*time.Second)); err != nil || !next.LeaseExpiresAt.Equal(now.Add(159*time.Second)) || len(next.ServiceIDs) != 1 {
		t.Fatal("fresh signed renewal did not retain proof and scope", err)
	}
}

func TestIntegrationWorkloadIdentityExpiryCannotResurrect(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "workload_identity_terminal")
	f := newRetainedVisitorFixture(t, d, now, retainedGitHubTrust(), 3600, false)
	exchange, key := retainedVisitorPreparation(t, f, now)
	exchange.Proof.Execution.ExpiresAt, exchange.Proof.Execution.GitHub.ExpiresAt = now.Add(45*time.Second).Unix(), now.Add(45*time.Second).Unix()
	signRetainedVisitorPreparation(&exchange, key)
	prepared, err := d.PrepareEnvironmentVisitor(t.Context(), exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	session := prepared.Session
	fresh := exchange
	fresh.Proof.Execution.GitHub = new(*exchange.Proof.Execution.GitHub)
	fresh.Proof.Execution.ExpiresAt, fresh.Proof.Execution.GitHub.ExpiresAt = now.Add(5*time.Minute).Unix(), now.Add(5*time.Minute).Unix()
	fresh.Proof.Execution.GitHub.JTI = "fresh-after-expiry"
	signRetainedVisitorPreparation(&fresh, key)
	proof, signature, audience := retainedVisitorAssertion(t, d, session, key, fresh.Proof.Execution)
	for _, at := range []time.Time{session.IdentityExpiresAt, session.IdentityExpiresAt.Add(time.Second)} {
		if _, err := d.RenewEnvironmentVisitorSession(t.Context(), session.ID, session.Credential, signWorkloadRenewal(session, key), at); !errors.Is(err, ErrWorkloadDenied) {
			t.Fatal("key renewal revived expired platform identity", err)
		}
		if _, err := d.AttachEnvironmentVisitorAssertion(t.Context(), session.ID, session.Credential, proof, signature, audience, at); !errors.Is(err, ErrWorkloadExpired) {
			t.Fatal("fresh proof revived an expired session", err)
		}
		if _, err := d.PrepareEnvironmentVisitor(t.Context(), fresh, at); !errors.Is(err, ErrWorkloadExpired) {
			t.Fatal("exchange retry revived expired identity", err)
		}
		if _, err := d.CheckWorkloadService(t.Context(), session.Credential, session.ServiceIDs[0], at); !errors.Is(err, ErrWorkloadDenied) {
			t.Fatal("expired proof retained service access", err)
		}
	}
}

func TestIntegrationWorkloadIdentityExpiryMigration(t *testing.T) {
	d, url, now := newControlStateIntegrationDatabaseWithURL(t, "workload_identity_migration")
	f := newRetainedVisitorFixture(t, d, now, retainedGitHubTrust(), 3600, false)
	exchange, key := retainedVisitorPreparation(t, f, now)
	exchange.Proof.Execution.ExpiresAt, exchange.Proof.Execution.GitHub.ExpiresAt = now.Add(45*time.Second).Unix(), now.Add(45*time.Second).Unix()
	signRetainedVisitorPreparation(&exchange, key)
	prepared, err := d.PrepareEnvironmentVisitor(t.Context(), exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	session := prepared.Session
	// the initial schema must reject a lease beyond its verified identity.
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.workload_sessions SET lease_expires_at=$2 WHERE id=$1`, session.ID, now.Add(90*time.Second)); err == nil {
		t.Fatal("baseline accepted a lease beyond identity expiry")
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.workload_sessions SET renewal_sequence=1 WHERE id=$1`, session.ID); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(t.Context(), url); err != nil {
		t.Fatal(err)
	}
	recovery, err := d.PrepareEnvironmentVisitor(t.Context(), exchange, now)
	recovered := recovery.Session
	if err != nil || recovered.ID != session.ID || recovered.Credential != session.Credential || recovered.RenewalSequence != 1 || !recovered.ExpiresAt.Equal(*session.ExpiresAt) || !recovered.IdentityExpiresAt.Equal(now.Add(45*time.Second)) || !recovered.LeaseExpiresAt.Equal(recovered.IdentityExpiresAt) || !reflect.DeepEqual(recovered.ServiceIDs, session.ServiceIDs) {
		t.Fatal("repeat migration changed identity expiry or session authority", err)
	}
}
