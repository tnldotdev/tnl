package state

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func retentionWorkload(t *testing.T, d *Database, f retainedVisitorFixture, at time.Time, n int) (WorkloadSession, PrepareEnvironmentVisitorRequest, ed25519.PrivateKey) {
	t.Helper()
	request, key := retainedVisitorPreparation(t, f, at)
	request.Proof.Execution.GitHub.CheckRunID = fmt.Sprint(1000 + n)
	request.Proof.Execution.GitHub.JTI = fmt.Sprint(n)
	signRetainedVisitorPreparation(&request, key)
	prepared, err := d.PrepareEnvironmentVisitor(t.Context(), request, at)
	if err != nil {
		t.Fatal(err)
	}
	return prepared.Session, request, key
}

func drainWorkloadHistory(t *testing.T, d *Database, now time.Time, limit int) int64 {
	t.Helper()
	var total int64
	for range 100 {
		before := workloadHistoryCounts(t, d)
		if err := d.ExpireVisitorPermissions(t.Context(), now); err != nil {
			t.Fatal(err)
		}
		if after := workloadHistoryCounts(t, d)["workload_assertions"]; after != before["workload_assertions"] {
			t.Fatalf("visitor permission worker bypassed workload retention: assertions %d -> %d", before["workload_assertions"], after)
		}
		n, err := d.CleanupWorkloads(t.Context(), now, limit)
		if err != nil || n < 0 || n > int64(6*limit) {
			t.Fatalf("bounded cleanup: removed=%d err=%v", n, err)
		}
		var deleted int64
		for table, after := range workloadHistoryCounts(t, d) {
			delta := before[table] - after
			if delta < 0 || delta > int64(limit) {
				t.Fatalf("cleanup exceeded %s budget: removed=%d limit=%d", table, delta, limit)
			}
			deleted += delta
		}
		if deleted != n {
			t.Fatalf("reported progress differs from committed deletions: reported=%d actual=%d", n, deleted)
		}
		total += n
		if n == 0 {
			return total
		}
	}
	t.Fatal("cleanup did not converge")
	return 0
}

func workloadHistoryCounts(t *testing.T, d *Database) map[string]int64 {
	t.Helper()
	counts := map[string]int64{}
	for _, table := range []string{"workload_sessions", "workload_session_services", "workload_assertions", "workload_client_certificates", "workload_audit", "public_service_visitors"} {
		var count int64
		if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.`+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		counts[table] = count
	}
	return counts
}

func requireWorkloadStored(t *testing.T, d *Database, id string, want bool) {
	t.Helper()
	var found bool
	if err := d.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM control.workload_sessions WHERE id=$1)`, id).Scan(&found); err != nil || found != want {
		t.Fatalf("session retained=%t want=%t err=%v", found, want, err)
	}
}

func TestIntegrationWorkloadRetentionReplayAndStop(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "workload_retention_replay")
	f := newRetainedVisitorFixture(t, d, now, retainedGitHubTrust(), 3600, false)
	active, activeRequest, _ := retentionWorkload(t, d, f, now, 1)
	expired, expiredRequest, expiredKey := retentionWorkload(t, d, f, now.Add(-2*time.Minute), 2)
	revoked, revokedRequest, revokedKey := retentionWorkload(t, d, f, now, 3)
	old, oldRequest, oldKey := retentionWorkload(t, d, f, now.Add(-40*24*time.Hour), 4)
	if err := d.RevokeEnvironmentVisitorSession(t.Context(), revoked.ID, revoked.Credential, now); err != nil {
		t.Fatal(err)
	}
	if n := drainWorkloadHistory(t, d, now, 1); n == 0 {
		t.Fatal("old history was not collected")
	}
	for _, s := range []WorkloadSession{active, expired, revoked} {
		requireWorkloadStored(t, d, s.ID, true)
	}
	requireWorkloadStored(t, d, old.ID, false)
	if retry, err := d.PrepareEnvironmentVisitor(t.Context(), activeRequest, now); err != nil || retry.Session.ID != active.ID || retry.Session.Credential != active.Credential {
		t.Fatal("cleanup broke authenticated lost-response recovery", err)
	}
	for _, test := range []struct {
		name                                   string
		session                                WorkloadSession
		request                                PrepareEnvironmentVisitorRequest
		key                                    ed25519.PrivateKey
		prepareWant, renewWant, attachmentWant error
	}{
		{"expired lease with valid source", expired, expiredRequest, expiredKey, ErrWorkloadExpired, ErrWorkloadExpired, ErrWorkloadExpired},
		{"revoked", revoked, revokedRequest, revokedKey, ErrWorkloadDenied, ErrWorkloadDenied, ErrWorkloadDenied},
		{"collected with expired source", old, oldRequest, oldKey, ErrMachineDenied, ErrWorkloadDenied, ErrWorkloadDenied},
	} {
		if _, err := d.PrepareEnvironmentVisitor(t.Context(), test.request, now); !errors.Is(err, test.prepareWant) {
			t.Fatalf("%s: preparation error=%v want=%v", test.name, err, test.prepareWant)
		}
		if _, err := d.RenewEnvironmentVisitorSession(t.Context(), test.session.ID, test.session.Credential, signWorkloadRenewal(test.session, test.key), now); !errors.Is(err, test.renewWant) {
			t.Fatalf("%s: renewal error=%v want=%v", test.name, err, test.renewWant)
		}
		// a fresh assertion for the same job still cannot attach to an expired,
		// revoked, or collected session, even with the original bound key.
		fresh := test.request.Proof.Execution
		fresh.GitHub = new(*activeRequest.Proof.Execution.GitHub)
		fresh.GitHub.CheckRunID = test.request.Proof.Execution.GitHub.CheckRunID
		fresh.IssuedAt, fresh.NotBefore, fresh.ExpiresAt = fresh.GitHub.IssuedAt, fresh.GitHub.NotBefore, fresh.GitHub.ExpiresAt
		proof, signature, audience := retainedVisitorAssertionForPreparation(test.request, test.session, test.key, fresh)
		if _, err := d.AttachEnvironmentVisitorAssertion(t.Context(), test.session.ID, test.session.Credential, proof, signature, audience, now); !errors.Is(err, test.attachmentWant) {
			t.Fatalf("%s: attachment error=%v want=%v", test.name, err, test.attachmentWant)
		}
		if err := d.RevokeEnvironmentVisitorSession(t.Context(), test.session.ID, "wlc_wrong", now); !errors.Is(err, ErrWorkloadDenied) {
			t.Fatal("stop accepted unverifiable ownership", err)
		}
	}
	// cleanup cannot release the original nonce's admitted key and execution.
	// independent sessions are not subject-global ownership or reauthorization.
	foreign, foreignKey := retainedVisitorPreparation(t, f, now)
	foreign.Nonce = activeRequest.Nonce
	foreign.Proof.Execution.GitHub.CheckRunID = "9999"
	foreign.Proof.Execution.GitHub.JTI = activeRequest.Proof.Execution.GitHub.JTI
	signRetainedVisitorPreparation(&foreign, foreignKey)
	if _, err := d.PrepareEnvironmentVisitor(t.Context(), foreign, now); !errors.Is(err, ErrWorkloadConflict) {
		t.Fatal("cleanup released the active nonce's execution/key binding", err)
	}
	foreign.Nonce = revokedRequest.Nonce
	foreign.Proof.Execution.GitHub = new(*revokedRequest.Proof.Execution.GitHub)
	foreign.Proof.Execution.GitHub.JTI = "fresh-revoked-job"
	signRetainedVisitorPreparation(&foreign, foreignKey)
	if _, err := d.PrepareEnvironmentVisitor(t.Context(), foreign, now); !errors.Is(err, ErrWorkloadConflict) {
		t.Fatal("cleanup released job ownership", err)
	}
	for range 2 {
		for _, s := range []WorkloadSession{expired, revoked} {
			if err := d.RevokeEnvironmentVisitorSession(t.Context(), s.ID, s.Credential, now.Add(time.Second)); err != nil {
				t.Fatal("authenticated expired/revoked stop was not idempotent", err)
			}
		}
		if err := d.RevokeEnvironmentVisitorSession(t.Context(), old.ID, old.Credential, now); !errors.Is(err, ErrWorkloadDenied) {
			t.Fatal("collected credential was reported as authenticated", err)
		}
	}
}

func TestIntegrationWorkloadRetentionAssertionBoundary(t *testing.T) {
	d, at := newControlStateIntegrationDatabase(t, "workload_retention_boundary")
	trust := oidc.WorkloadTrust{Provider: "oidc", Issuer: "https://issuer.example/workloads", JWKSURL: "https://issuer.example/keys", Audience: "test", Claims: map[string]string{"sub": "worker"}}
	f := newRetainedVisitorFixture(t, d, at, retainedGitHubTrust(), 10, false)
	github, _, _ := retentionWorkload(t, d, f, at, 1)
	machine, err := d.RegisterMachineIdentity(t.Context(), RegisterMachineRequest{TeamID: f.project.TeamID, ActorID: f.project.ActorID, Name: "long-assertion", ProofKind: "oidc", Trust: trust}, at)
	if err != nil {
		t.Fatal(err)
	}
	permission, err := d.CreateEnvironmentVisitorPermission(t.Context(), EnvironmentVisitorPermission{MachineID: machine.ID, TeamID: f.project.TeamID, ProjectKey: f.project.ProjectKey, Scope: EnvironmentPermissionScope{EnvironmentIDs: []string{f.environment.ID}}, Services: []string{"api"}, MaxDurationSeconds: 10, ExpiresAt: at.Add(24 * time.Hour)}, f.project.ActorID, at)
	if err != nil {
		t.Fatal(err)
	}
	f.machine, f.permission = machine, permission
	request, key := retainedVisitorPreparation(t, f, at)
	request.Services = map[string]string{"api": "http"}
	request.Nonce = "long_assertion_nonce"
	request.Proof.Execution = oidc.WorkloadExecution{Provider: "oidc", Issuer: trust.Issuer, Audience: trust.Audience, TrustDigest: trust.Digest(), Subject: "worker", IssuedAt: at.Unix(), NotBefore: at.Unix(), ExpiresAt: at.Add(12 * time.Hour).Unix(), Claims: map[string]string{}}
	signRetainedVisitorPreparation(&request, key)
	prepared, err := d.PrepareEnvironmentVisitor(t.Context(), request, at)
	if err != nil {
		t.Fatal(err)
	}
	reusable := prepared.Session
	// the absolute ten-second window is older than retention, but both kinds
	// of original assertion still pin their nonce/job record beyond that window.
	first := at.Add(WorkloadHistoryRetention + time.Minute)
	drainWorkloadHistory(t, d, first, 1)
	for _, s := range []WorkloadSession{github, reusable} {
		requireWorkloadStored(t, d, s.ID, true)
	}
	// expiry exactly at the cutoff remains retained; one second later the
	// GitHub replay record and session become collectible, but the reusable
	// provider's original twelve-hour assertion still pins its own session.
	boundary := at.Add(WorkloadHistoryRetention + 5*time.Minute)
	drainWorkloadHistory(t, d, boundary, 1)
	requireWorkloadStored(t, d, github.ID, true)
	drainWorkloadHistory(t, d, boundary.Add(time.Second), 1)
	requireWorkloadStored(t, d, github.ID, false)
	requireWorkloadStored(t, d, reusable.ID, true)
	boundary = at.Add(WorkloadHistoryRetention + 12*time.Hour)
	drainWorkloadHistory(t, d, boundary, 1)
	requireWorkloadStored(t, d, reusable.ID, true)
	drainWorkloadHistory(t, d, boundary.Add(time.Second), 1)
	requireWorkloadStored(t, d, reusable.ID, false)
	if _, err := d.PrepareEnvironmentVisitor(t.Context(), request, boundary.Add(time.Second)); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("collected reusable assertion resurrected its nonce", err)
	}
}

func TestIntegrationWorkloadRetentionReferencesAndBatches(t *testing.T) {
	d, now, _, leases := newPublishRunPrerequisites(t)
	ctx := t.Context()
	f := newRetainedVisitorFixture(t, d, now, retainedGitHubTrust(), 3600, false)
	replica := enrollTestEnvironment(t, d, f.project, f.environment)
	access := environmentAssignmentAccess(t, d, replica, replica.assignments.Services[0], now)
	service, err := d.GetServiceForPublisher(ctx, replica.assignments.Services[0].ServiceID, access.PublisherIdentity, now)
	if err != nil {
		t.Fatal(err)
	}
	run := readyAppliedServiceRun(t, d, access, replica.private, service, leases, now, &replica.assignments.Environment)
	var sessions []WorkloadSession
	var visitors []string
	var certificates [][]byte
	for i := range 9 {
		// the oldest rows are deliberately blocked. LIMIT must be applied only
		// after checking references, or these rows starve the eligible tail.
		at := now.Add(-time.Duration(50-i) * 24 * time.Hour)
		s, preparation, _ := retentionWorkload(t, d, f, at, i)
		sessions = append(sessions, s)
		visitor := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
		cert := sha256.Sum256([]byte(fmt.Sprint("certificate-", i)))
		visitors, certificates = append(visitors, visitor), append(certificates, cert[:])
		if _, err := d.pool.Exec(ctx, `INSERT INTO control.workload_client_certificates VALUES($1,$2,$3,$1,'certificate',$4)`, cert[:], s.ID, service.ID, s.ExpiresAt); err != nil {
			t.Fatal(err)
		}
		// retained child records are a defensive cleanup fixture, like the
		// certificate and admission below. canonical visitor preparation does not
		// make an OIDC token globally exclusive to one admitted nonce/session.
		jti := sha256.Sum256([]byte(fmt.Sprint("retained-assertion-", i)))
		if _, err := d.pool.Exec(ctx, `INSERT INTO control.workload_assertions(jti_digest,assertion_digest,workload_session_id,expires_at) VALUES($1,$2,$3,$4)`, jti[:], preparation.Proof.Execution.AssertionDigest[:], s.ID, time.Unix(preparation.Proof.Execution.ExpiresAt, 0)); err != nil {
			t.Fatal(err)
		}
		if _, err := d.pool.Exec(ctx, `INSERT INTO control.public_service_visitors(workload_session_id,visitor_connection_id,service_id,service_run_id,run_number,ingress_id,ingress_run_id,ingress_lease_revision,destination_port,source_ip,certificate_digest,valid_until,created_at) VALUES($1,$2,$3,$4,$5,'retention','old-run',1,12345,'192.0.2.1',$6,$7,$8)`, s.ID, visitor, service.ID, run.RunID, run.RunNumber, cert[:], s.LeaseExpiresAt, at); err != nil {
			t.Fatal(err)
		}
	}
	// retained live decisions, certificate, and JTI each pin a different old
	// subject. these defensive seeds also exercise stale dependent deadlines.
	if _, err := d.pool.Exec(ctx, `UPDATE control.public_service_visitors SET valid_until=$2 WHERE visitor_connection_id=$1`, visitors[0], now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	direct := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
	if _, err := d.pool.Exec(ctx, `INSERT INTO control.public_service_visitors(workload_session_id,visitor_connection_id,service_id,service_run_id,run_number,ingress_id,ingress_run_id,ingress_lease_revision,destination_port,source_ip,certificate_digest,valid_until,created_at) VALUES($1,$2,$3,$4,$5,'retention','old-run',1,12345,'192.0.2.1',$6,$7,$8)`, sessions[1].ID, direct, service.ID, run.RunID, run.RunNumber, certificates[1], now.Add(time.Minute), now.Add(-49*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.workload_client_certificates SET expires_at=$2 WHERE workload_session_id=$1`, sessions[2].ID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if tag, err := d.pool.Exec(ctx, `UPDATE control.workload_assertions SET expires_at=$2 WHERE workload_session_id=$1`, sessions[3].ID, now.Add(time.Minute)); err != nil || tag.RowsAffected() != 1 {
		t.Errorf("verified GitHub replay record missing: updated=%d want=1 err=%v", tag.RowsAffected(), err)
	}
	// a new revoke event on old history receives the full authored retention.
	if err := d.RevokeEnvironmentVisitorSession(ctx, sessions[4].ID, sessions[4].Credential, now); err != nil {
		t.Fatal(err)
	}
	active, activeRequest, _ := retentionWorkload(t, d, f, now, 100)
	recent, _, _ := retentionWorkload(t, d, f, now.Add(-29*24*time.Hour), 101)
	// a competing cleanup/revoke transaction may hold an eligible row. the
	// public store method must still make progress through the remaining rows.
	locked, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer locked.Rollback(ctx)
	if _, err := locked.Exec(ctx, `SELECT id FROM control.workload_sessions WHERE id=$1 FOR UPDATE`, sessions[5].ID); err != nil {
		t.Fatal(err)
	}
	if n, err := d.CleanupWorkloads(ctx, now, 2); err != nil || n == 0 {
		t.Fatal("locked parent blocked independent cleanup", n, err)
	}
	if err := locked.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if n := drainWorkloadHistory(t, d, now, 2); n == 0 {
		t.Fatal("eligible tail was starved by retained references")
	}
	for i, s := range sessions {
		requireWorkloadStored(t, d, s.ID, i < 5)
	}
	for _, s := range []WorkloadSession{active, recent} {
		requireWorkloadStored(t, d, s.ID, true)
	}
	if retry, err := d.PrepareEnvironmentVisitor(ctx, activeRequest, now); err != nil || retry.Session.Credential != active.Credential || len(retry.Session.ServiceIDs) != 2 {
		t.Fatal("active subject snapshot changed", err)
	}
	var storedVisitor, storedCert, storedDirect bool
	if err := d.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.public_service_visitors WHERE visitor_connection_id=$1),EXISTS(SELECT 1 FROM control.workload_client_certificates WHERE certificate_digest=$2),EXISTS(SELECT 1 FROM control.public_service_visitors WHERE visitor_connection_id=$3)`, visitors[0], certificates[1], direct).Scan(&storedVisitor, &storedCert, &storedDirect); err != nil || !storedVisitor || !storedCert || !storedDirect {
		t.Fatal("live admission references were erased", err)
	}
	// the older run sweeper must neither erase these workload handles early nor
	// fail on their retained FK references when running beside workload cleanup.
	if _, err := d.ExpireServiceRuns(ctx, now); err != nil {
		t.Fatal("shared expiration worker conflicted with retained references", err)
	}
	if n := drainWorkloadHistory(t, d, now, 2); n != 0 {
		t.Fatal("empty sweep was not stable", n)
	}
	// once the decisions and replay fence age out, every dependent table and
	// subject converges without a cascade or manual FK deletion.
	later := now.Add(32 * 24 * time.Hour)
	if n := drainWorkloadHistory(t, d, later, 2); n == 0 {
		t.Fatal("retained history never became collectible")
	}
	for table, count := range workloadHistoryCounts(t, d) {
		if count != 0 {
			t.Fatalf("history did not converge in %s: count=%d", table, count)
		}
	}
}
