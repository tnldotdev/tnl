package state

import (
	"crypto/ed25519"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/workloadproof"
)

func TestIntegrationWorkloadIdentityExpiryAndRefresh(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "workload_identity_expiry")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	exchange, key := workloadExchange(t, r, now)
	exchange.Execution.ExpiresAt = now.Add(45 * time.Second).Unix()
	exchange.Execution.GitHub.ExpiresAt = exchange.Execution.ExpiresAt
	signWorkloadRequest(&exchange, key)
	session, err := d.ExchangeWorkload(ctx, exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	if !session.IdentityExpiresAt.Equal(now.Add(45*time.Second)) || !session.LeaseExpiresAt.Equal(session.IdentityExpiresAt) || !session.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatal("initial lease did not honor proof expiry independently of the fixed window")
	}
	renewed, err := d.RenewWorkloadSession(ctx, session.ID, session.Credential, signWorkloadRenewal(session, key), now.Add(31*time.Second))
	if err != nil || !renewed.LeaseExpiresAt.Equal(session.IdentityExpiresAt) {
		t.Fatal("signed key renewal outlived platform proof", err)
	}
	fresh := exchange
	fresh.Execution.GitHub = new(*exchange.Execution.GitHub)
	fresh.Execution.IssuedAt, fresh.Execution.NotBefore, fresh.Execution.ExpiresAt = now.Add(35*time.Second).Unix(), now.Add(35*time.Second).Unix(), now.Add(335*time.Second).Unix()
	fresh.Execution.GitHub.IssuedAt, fresh.Execution.GitHub.NotBefore, fresh.Execution.GitHub.ExpiresAt = fresh.Execution.IssuedAt, fresh.Execution.NotBefore, fresh.Execution.ExpiresAt
	fresh.Execution.GitHub.JTI = "fresh-proof"
	signWorkloadRequest(&fresh, key)
	attach := func(request ExchangeWorkloadRequest, at time.Time) (WorkloadSession, error) {
		return d.AttachWorkloadAssertion(ctx, session.ID, session.Credential, request.Execution, ed25519.Sign(key, workloadproof.Attach(session.ID, request.Execution.AssertionDigest)), at)
	}
	refreshed, err := attach(fresh, now.Add(35*time.Second))
	if err != nil || !refreshed.IdentityExpiresAt.Equal(now.Add(335*time.Second)) || !refreshed.LeaseExpiresAt.Equal(now.Add(121*time.Second)) || !refreshed.ExpiresAt.Equal(*session.ExpiresAt) || refreshed.ID != session.ID || refreshed.Subject != session.Subject || refreshed.Credential != session.Credential || refreshed.RenewalSequence != renewed.RenewalSequence {
		t.Fatal("same-identity refresh changed the session or moved the renewal budget", err)
	}
	if older, err := attach(exchange, now.Add(36*time.Second)); err != nil || !reflect.DeepEqual(older, refreshed) {
		t.Fatal("older still-valid proof shortened or extended current authority", err)
	}
	if retry, err := attach(fresh, now.Add(65*time.Second)); err != nil || !reflect.DeepEqual(retry, refreshed) {
		t.Fatal("replayed platform proof moved the accepted renewal clock", err)
	}
	if replayed, err := d.ExchangeWorkload(ctx, fresh, now.Add(65*time.Second)); err != nil || !reflect.DeepEqual(replayed, refreshed) {
		t.Fatal("exchanging an attached rotated proof changed the session or extended its lease", err)
	}
	wrong := fresh
	wrong.Execution.GitHub = new(*fresh.Execution.GitHub)
	wrong.Execution.GitHub.CheckRunID, wrong.Execution.GitHub.JTI = "999", "other-execution"
	signWorkloadRequest(&wrong, key)
	if _, err := attach(wrong, now.Add(66*time.Second)); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("another execution extended this identity", err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.workload_sessions SET lease_expires_at=identity_expires_at+interval '1 second' WHERE id=$1`, session.ID); err == nil {
		t.Fatal("schema allowed a lease beyond verified identity expiry")
	}
	r.ExpectedRevision = applied.Revision
	policy := r.Configuration.Workloads["test"]
	policy.Services = []string{"api"}
	r.Configuration.Workloads["test"] = policy
	if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
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
	if next, err := d.RenewWorkloadSession(ctx, session.ID, session.Credential, signWorkloadRenewal(narrowed, key), now.Add(69*time.Second)); err != nil || !next.LeaseExpiresAt.Equal(now.Add(159*time.Second)) || len(next.ServiceIDs) != 1 {
		t.Fatal("fresh signed renewal did not retain proof and scope", err)
	}
}

func TestIntegrationWorkloadIdentityExpiryCannotResurrect(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "workload_identity_terminal")
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	if _, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	exchange, key := workloadExchange(t, r, now)
	exchange.Execution.ExpiresAt, exchange.Execution.GitHub.ExpiresAt = now.Add(45*time.Second).Unix(), now.Add(45*time.Second).Unix()
	signWorkloadRequest(&exchange, key)
	session, err := d.ExchangeWorkload(t.Context(), exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	fresh := exchange
	fresh.Execution.GitHub = new(*exchange.Execution.GitHub)
	fresh.Execution.ExpiresAt, fresh.Execution.GitHub.ExpiresAt = now.Add(5*time.Minute).Unix(), now.Add(5*time.Minute).Unix()
	fresh.Execution.GitHub.JTI = "fresh-after-expiry"
	signWorkloadRequest(&fresh, key)
	for _, at := range []time.Time{session.IdentityExpiresAt, session.IdentityExpiresAt.Add(time.Second)} {
		if _, err := d.RenewWorkloadSession(t.Context(), session.ID, session.Credential, signWorkloadRenewal(session, key), at); !errors.Is(err, ErrWorkloadDenied) {
			t.Fatal("key renewal revived expired platform identity", err)
		}
		if _, err := d.AttachWorkloadAssertion(t.Context(), session.ID, session.Credential, fresh.Execution, ed25519.Sign(key, workloadproof.Attach(session.ID, fresh.Execution.AssertionDigest)), at); !errors.Is(err, ErrWorkloadExpired) {
			t.Fatal("fresh proof revived an expired session", err)
		}
		if _, err := d.ExchangeWorkload(t.Context(), fresh, at); !errors.Is(err, ErrWorkloadExpired) {
			t.Fatal("exchange retry revived expired identity", err)
		}
		if _, err := d.CheckWorkloadService(t.Context(), session.Credential, session.ServiceIDs[0], at); !errors.Is(err, ErrWorkloadDenied) {
			t.Fatal("expired proof retained service access", err)
		}
	}
}

func TestIntegrationWorkloadIdentityExpiryMigration(t *testing.T) {
	d, url, now := newControlStateIntegrationDatabaseWithURL(t, "workload_identity_migration")
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	if _, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	exchange, key := workloadExchange(t, r, now)
	exchange.Execution.ExpiresAt, exchange.Execution.GitHub.ExpiresAt = now.Add(45*time.Second).Unix(), now.Add(45*time.Second).Unix()
	signWorkloadRequest(&exchange, key)
	session, err := d.ExchangeWorkload(t.Context(), exchange, now)
	if err != nil {
		t.Fatal(err)
	}
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
	recovered, err := d.ExchangeWorkload(t.Context(), exchange, now)
	if err != nil || recovered.ID != session.ID || recovered.Credential != session.Credential || recovered.RenewalSequence != 1 || !recovered.ExpiresAt.Equal(*session.ExpiresAt) || !recovered.IdentityExpiresAt.Equal(now.Add(45*time.Second)) || !recovered.LeaseExpiresAt.Equal(recovered.IdentityExpiresAt) || !reflect.DeepEqual(recovered.ServiceIDs, session.ServiceIDs) {
		t.Fatal("repeat migration changed identity expiry or session authority", err)
	}
}
