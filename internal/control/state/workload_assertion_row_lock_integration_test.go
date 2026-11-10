package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
)

func TestIntegrationWorkloadAssertionExpiryDuringSessionRowLock(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "workload_assertion_row_lock")
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	trust := oidc.WorkloadTrust{Provider: "vercel", Issuer: "https://oidc.vercel.com/acme", JWKSURL: "https://oidc.vercel.com/acme/.well-known/jwks", Audience: "https://vercel.com/acme", Claims: map[string]string{"owner": "acme", "owner_id": "team_one", "project_id": "prj_store", "environment": "production"}}
	r.Configuration.Workloads = map[string]ProjectWorkload{"test": {Provider: "vercel", Trust: trust, Grants: config.ServiceVisitGrants("api"), MaxDurationSeconds: 3600}}
	if _, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	exchange, key := workloadExchange(t, r, now)
	// a reusable provider isolates the session update: GitHub's assertion insert
	// can instead wait on this row while checking its foreign key.
	exchange.Execution = oidc.WorkloadExecution{Provider: "vercel", Issuer: trust.Issuer, Audience: trust.Audience, TrustDigest: trust.Digest(), Subject: "owner:acme:project:store:environment:production", IssuedAt: now.Unix(), NotBefore: now.Unix(), ExpiresAt: now.Add(45 * time.Second).Unix(), Vercel: &oidc.VercelExecution{Owner: "acme", OwnerID: "team_one", Project: "store", ProjectID: "prj_store", Environment: "production"}}
	signWorkloadRequest(&exchange, key)
	session, err := d.ExchangeWorkload(t.Context(), exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	if !session.LeaseExpiresAt.Equal(session.IdentityExpiresAt) || !session.IdentityExpiresAt.Equal(now.Add(45*time.Second)) {
		t.Fatal("initial session was not capped by the old platform proof")
	}
	fresh := exchange
	fresh.Execution.ExpiresAt = now.Add(5 * time.Minute).Unix()
	signWorkloadRequest(&fresh, key)
	signature := ed25519.Sign(key, workloadproof.Attach(session.ID, fresh.Execution.AssertionDigest))
	saved := func() []byte {
		t.Helper()
		var value []byte
		if err := d.pool.QueryRow(t.Context(), `SELECT to_jsonb(w)::text FROM control.workload_sessions w WHERE id=$1`, session.ID).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := saved()

	gate, err := d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	// storage rotation takes this row lock without the team lock. hold only
	// the session row so the applied-project lock cannot hide the write wait.
	var locked string
	if err := gate.QueryRow(t.Context(), `SELECT id FROM control.workload_sessions WHERE id=$1 FOR UPDATE`, session.ID).Scan(&locked); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	entered := make(chan time.Time, 1)
	done := make(chan error, 1)
	var attached WorkloadSession
	// the supplied authorization clock starts one second before proof expiry;
	// elapsed real time crosses that boundary without a 45-second test wait.
	at := session.IdentityExpiresAt.Add(-time.Second)
	workers.Go(func() {
		entered <- time.Now()
		var err error
		attached, err = d.AttachWorkloadAssertion(ctx, session.ID, session.Credential, fresh.Execution, signature, at)
		done <- err
	})
	pid := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
	var query string
	if err := d.pool.QueryRow(ctx, `SELECT query FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&query); err != nil {
		t.Fatal(err)
	}
	t.Logf("attachment blocked on session row: %s", strings.Join(strings.Fields(query), " "))
	started := awaitIntegrationResult(t, ctx, entered)
	timer := time.NewTimer(time.Until(started.Add(time.Second + 50*time.Millisecond)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	releasedAt := at.Add(time.Since(started))
	if !releasedAt.After(session.IdentityExpiresAt) || !releasedAt.Before(now.Add(WorkloadLease)) {
		t.Fatal("row lock was not released after old proof expiry and before the renewal budget")
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	err = awaitIntegrationResult(t, ctx, done)
	if !errors.Is(err, ErrWorkloadExpired) {
		t.Errorf("attachment revived session after row-lock wait: err=%v; old identity/lease=%s; release=%s; returned identity=%s; returned lease=%s", err, session.IdentityExpiresAt.Format(time.RFC3339Nano), releasedAt.Format(time.RFC3339Nano), attached.IdentityExpiresAt.Format(time.RFC3339Nano), attached.LeaseExpiresAt.Format(time.RFC3339Nano))
	}
	if !bytes.Equal(before, saved()) {
		t.Error("denied attachment changed the expired session")
	}
	if _, err := d.CheckWorkloadService(ctx, session.Credential, session.ServiceIDs[0], releasedAt); !errors.Is(err, ErrWorkloadDenied) {
		t.Errorf("expired session retained service access after row-lock wait: %v", err)
	}
}
