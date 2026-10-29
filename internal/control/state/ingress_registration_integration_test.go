package state

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestIntegrationExpiredIngressRunRequiresNewRun(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "expired_ingress")
	registration := IngressRegistration{IngressID: "ingress-expired", IngressRunID: "old-run", ProtocolVersion: 1, ConnectionCapacity: 10}
	lease, err := database.RegisterIngress(t.Context(), registration, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	changed := registration
	changed.IngressPoolID = "other-pool"
	if _, err := database.RegisterIngress(t.Context(), changed, now.Add(time.Second), time.Minute); !errors.Is(err, ErrIngressAlreadyRunning) {
		t.Fatal("live run changed pinned facts", err)
	}
	changed = registration
	changed.IngressRunID = "competing-run"
	if _, err := database.RegisterIngress(t.Context(), changed, now.Add(time.Second), time.Minute); !errors.Is(err, ErrIngressAlreadyRunning) {
		t.Fatal("contender replaced live owner", err)
	}
	current, err := database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: lease.IngressLeaseIdentity}, now.Add(2*time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := database.RegisterIngress(t.Context(), registration, current.LeaseExpiresAt, time.Minute); !errors.Is(err, ErrIngressLeaseStale) {
			t.Fatal("expired run registered again", err)
		}
	}
	registration.IngressRunID = "new-run"
	replacement, err := database.RegisterIngress(t.Context(), registration, current.LeaseExpiresAt, time.Minute)
	if err != nil || replacement.IngressLeaseRevision != lease.IngressLeaseRevision+1 {
		t.Fatal("new owner could not replace expired run", replacement, err)
	}
	if _, err := database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: lease.IngressLeaseIdentity}, current.LeaseExpiresAt.Add(time.Second), time.Minute); !errors.Is(err, ErrIngressLeaseStale) {
		t.Fatal("old owner renewed replacement", err)
	}
	if _, err := database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: replacement.IngressLeaseIdentity}, current.LeaseExpiresAt.Add(time.Second), time.Minute); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationRetiredIngressRunCannotRegisterAfterReplacementExpires(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "retired_ingress")
	a := IngressRegistration{IngressID: "ingress-retried", IngressRunID: "run-a", ProtocolVersion: 1, ConnectionCapacity: 10}
	first, err := database.RegisterIngress(t.Context(), a, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	retried, err := database.RegisterIngress(t.Context(), a, now.Add(time.Second), time.Minute)
	if err != nil || retried.IngressLeaseIdentity != first.IngressLeaseIdentity {
		t.Fatal("live retry changed identity", err)
	}
	b := a
	b.IngressRunID, b.ConnectionCapacity, b.IngressPoolID, b.ConnectorOnly = "run-b", 20, "replacement-pool", true
	b.ServicePorts, b.ConnectorAddress, b.ConnectorTLSServerName = []int32{8443, 9443}, "127.0.0.1:9443", "replacement.example.test"
	if _, err := database.RegisterIngress(t.Context(), b, now.Add(2*time.Second), time.Minute); !errors.Is(err, ErrIngressAlreadyRunning) {
		t.Fatal("contender replaced live owner", err)
	}
	second, err := database.RegisterIngress(t.Context(), b, retried.LeaseExpiresAt, time.Minute)
	if err != nil || second.IngressLeaseRevision != first.IngressLeaseRevision+1 {
		t.Fatal("rejected contender could not later claim expired owner", err)
	}
	second, err = database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: second.IngressLeaseIdentity, ReportedConnections: 3, RoutingTableRevision: 7}, second.RegisteredAt.Add(time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	second, err = database.BeginIngressDrain(t.Context(), second.IngressLeaseIdentity, second.RenewedAt.Add(time.Second), second.LeaseExpiresAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	before := readIngressRegistrationSnapshot(t, database, a.IngressID)
	for range 2 {
		if _, err := database.RegisterIngress(t.Context(), a, second.LeaseExpiresAt, time.Minute); !errors.Is(err, ErrIngressLeaseStale) {
			t.Fatal("retired run registered after replacement expired", err)
		}
		if after := readIngressRegistrationSnapshot(t, database, a.IngressID); after != before {
			t.Fatal("retired replay changed lease or fence inventory", before, after)
		}
	}
	c := a
	c.IngressRunID = "run-c"
	third, err := database.RegisterIngress(t.Context(), c, second.LeaseExpiresAt, time.Minute)
	if err != nil || third.IngressLeaseRevision != second.IngressLeaseRevision+1 {
		t.Fatal("retired replay disturbed replacement", err)
	}
	before = readIngressRegistrationSnapshot(t, database, a.IngressID)
	for _, old := range []IngressRegistration{a, b} {
		if _, err := database.RegisterIngress(t.Context(), old, third.LeaseExpiresAt, time.Minute); !errors.Is(err, ErrIngressLeaseStale) {
			t.Fatal("old run escaped history fence", err)
		}
		if after := readIngressRegistrationSnapshot(t, database, a.IngressID); after != before {
			t.Fatal("old replay changed lease or fences", before, after)
		}
	}
}

func TestIntegrationIngressRunFenceSurvivesRuntimeRowRemoval(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "ingress_fence_retention")
	registration := IngressRegistration{IngressID: "retained", IngressRunID: "run-a", ProtocolVersion: 1, ConnectionCapacity: 10}
	first, err := database.RegisterIngress(t.Context(), registration, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `DELETE FROM control.ingress_leases WHERE ingress_id=$1`, registration.IngressID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.RegisterIngress(t.Context(), registration, first.LeaseExpiresAt, time.Minute); !errors.Is(err, ErrIngressLeaseStale) {
		t.Fatal("runtime row removal revived old run", err)
	}
	var rows int
	if err := database.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.ingress_leases WHERE ingress_id=$1`, registration.IngressID).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("rejected registration did not roll back tentative lease", rows, err)
	}
	registration.IngressRunID = "run-b"
	replacement, err := database.RegisterIngress(t.Context(), registration, first.LeaseExpiresAt, time.Minute)
	if err != nil || replacement.IngressLeaseRevision != first.IngressLeaseRevision+1 {
		t.Fatal("fresh owner lost retained revision history", replacement, err)
	}
}

type ingressRegistrationResult struct {
	lease IngressLease
	err   error
}

func contendIngressRegistrations(t *testing.T, database *Database, registrations [2]IngressRegistration, now time.Time) [2]ingressRegistrationResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	gate, err := database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	var id string
	if err := gate.QueryRow(ctx, `SELECT ingress_id FROM control.ingress_leases WHERE ingress_id=$1 FOR UPDATE`, registrations[0].IngressID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	done := [2]chan error{make(chan error, 1), make(chan error, 1)}
	var results [2]ingressRegistrationResult
	for index, registration := range registrations {
		workers.Go(func() {
			results[index].lease, results[index].err = database.RegisterIngress(ctx, registration, now, time.Minute)
			done[index] <- results[index].err
		})
	}
	pid := waitForPostgresBlock(t, ctx, database, int32(gate.Conn().PgConn().PID()), done[0])
	waitForPostgresBlock(t, ctx, database, pid, done[1])
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for _, result := range done {
		_ = awaitIntegrationResult(t, ctx, result)
	}
	return results
}

func TestIntegrationConcurrentIngressRegistrationRetriesKeepOneRun(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "ingress_retries")
	registration := IngressRegistration{IngressID: "retried", IngressRunID: "same-run", ProtocolVersion: 1, ConnectionCapacity: 10}
	first, err := database.RegisterIngress(t.Context(), registration, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	first, err = database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: first.IngressLeaseIdentity, ReportedConnections: 3, RoutingTableRevision: 7}, now.Add(time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	before := readIngressRegistrationSnapshot(t, database, registration.IngressID)
	at := now.Add(2 * time.Second)
	for _, result := range contendIngressRegistrations(t, database, [2]IngressRegistration{registration, registration}, at) {
		lease := result.lease
		if result.err != nil || lease.IngressLeaseIdentity != first.IngressLeaseIdentity || !lease.RegisteredAt.Equal(first.RegisteredAt) || !lease.RenewedAt.Equal(at) || !lease.LeaseExpiresAt.Equal(at.Add(time.Minute)) || lease.ReportedConnections != first.ReportedConnections || lease.RoutingTableRevision != first.RoutingTableRevision {
			t.Fatal("concurrent retry changed owner state", lease, result.err)
		}
	}
	if after := readIngressRegistrationSnapshot(t, database, registration.IngressID); after.fences != before.fences {
		t.Fatal("exact retry changed fences", before, after)
	}
}

func TestIntegrationConcurrentIngressRegistrationContendersKeepOneOwner(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "ingress_contenders")
	registration := IngressRegistration{IngressID: "contended", IngressRunID: "old", ProtocolVersion: 1, ConnectionCapacity: 10}
	first, err := database.RegisterIngress(t.Context(), registration, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	contenders := [2]IngressRegistration{registration, registration}
	contenders[0].IngressRunID, contenders[0].ConnectionCapacity = "new-a", 20
	contenders[1].IngressRunID, contenders[1].ConnectionCapacity = "new-b", 30
	results := contendIngressRegistrations(t, database, contenders, first.LeaseExpiresAt)
	winner, successes, rejected := -1, 0, 0
	for index, result := range results {
		switch {
		case result.err == nil:
			winner, successes = index, successes+1
			if result.lease.IngressRunID != contenders[index].IngressRunID || result.lease.IngressLeaseRevision != first.IngressLeaseRevision+1 || result.lease.ConnectionCapacity != contenders[index].ConnectionCapacity {
				t.Fatal("contender received another owner", result.lease)
			}
		case errors.Is(result.err, ErrIngressAlreadyRunning):
			rejected++
		default:
			t.Fatal(result.err)
		}
	}
	if successes != 1 || rejected != 1 {
		t.Fatal("contenders did not retain one owner", successes, rejected)
	}
	loser := 1 - winner
	var count, rejectedFences int
	if err := database.pool.QueryRow(t.Context(), `SELECT count(*),count(*) FILTER (WHERE ingress_run_id=$2) FROM control.ingress_run_fences WHERE ingress_id=$1`, registration.IngressID, contenders[loser].IngressRunID).Scan(&count, &rejectedFences); err != nil || count != 2 || rejectedFences != 0 {
		t.Fatal("rejected work retained a fence", count, rejectedFences, err)
	}
	current, err := database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: results[winner].lease.IngressLeaseIdentity}, first.LeaseExpiresAt.Add(time.Second), time.Minute)
	if err != nil || current.ConnectionCapacity != contenders[winner].ConnectionCapacity {
		t.Fatal("loser disturbed owner", err)
	}
	replacement, err := database.RegisterIngress(t.Context(), contenders[loser], current.LeaseExpiresAt, time.Minute)
	if err != nil || replacement.IngressLeaseRevision != current.IngressLeaseRevision+1 {
		t.Fatal("rejected contender could not later replace expired owner", err)
	}
}

type ingressRegistrationSnapshot struct{ lease, fences string }

func readIngressRegistrationSnapshot(t *testing.T, database *Database, id string) ingressRegistrationSnapshot {
	t.Helper()
	var snapshot ingressRegistrationSnapshot
	if err := database.pool.QueryRow(t.Context(), `SELECT to_jsonb(lease)::text,(SELECT COALESCE(jsonb_agg(to_jsonb(fence) ORDER BY ingress_id,ingress_run_id),'[]'::jsonb)::text FROM control.ingress_run_fences AS fence) FROM control.ingress_leases AS lease WHERE ingress_id=$1`, id).Scan(&snapshot.lease, &snapshot.fences); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestIntegrationIngressGuardRejectsWrongRunRevisionAndExpiry(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "ingress_guards")
	lease, err := database.RegisterIngress(t.Context(), IngressRegistration{IngressID: "guarded", IngressRunID: "current", ProtocolVersion: 1, ConnectionCapacity: 10}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	wrongRun, wrongRevision := lease.IngressLeaseIdentity, lease.IngressLeaseIdentity
	wrongRun.IngressRunID = "other"
	wrongRevision.IngressLeaseRevision++
	for _, test := range []struct {
		identity IngressLeaseIdentity
		at       time.Time
	}{{wrongRun, now}, {wrongRevision, now}, {lease.IngressLeaseIdentity, lease.LeaseExpiresAt}} {
		if _, err := database.ReadIngressRoutingTableSnapshot(t.Context(), test.identity, test.at); !errors.Is(err, ErrIngressLeaseStale) {
			t.Fatal("routing read trusted stale ingress source", err)
		}
		if _, err := database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: test.identity}, test.at, time.Minute); !errors.Is(err, ErrIngressLeaseStale) {
			t.Fatal("renewal trusted stale ingress source", err)
		}
	}
}

func TestIntegrationGuestAuthorityShapeRequiresFreshBaseline(t *testing.T) {
	database, url, _ := newControlStateIntegrationDatabaseWithURL(t, "guest_shape")
	// migration tests verify physical schema facts. serving probes require the
	// exact version and identity instead of repeating a catalog fingerprint.
	var fence, deadlines bool
	var retired int
	if err := database.pool.QueryRow(t.Context(), `SELECT
		to_regclass('control.ingress_run_fences') IS NOT NULL,
		(SELECT count(*)=2 FROM pg_attribute WHERE attrelid='control.guest_trials'::regclass
		    AND attname IN ('ready_deadline','serving_until') AND atttypid='timestamptz'::regtype AND NOT attisdropped),
		(SELECT count(*) FROM unnest(ARRAY['control.ingress_usage_runs','control.ingress_usage_reports',
		    'control.public_url_usage_buckets','control.public_url_usage_deliveries','control.visitor_network_hash_keys']) AS retired(name)
		    WHERE to_regclass(name) IS NOT NULL)`).Scan(&fence, &deadlines, &retired); err != nil || !fence || !deadlines || retired != 0 {
		t.Fatal("fresh guest schema lost retained fences/deadlines or restored hosted usage", fence, deadlines, retired, err)
	}
	previous := "tnl-control-fresh-v1-public-reservations-guest-authority"
	if _, err := database.pool.Exec(t.Context(), `ALTER TABLE control.schema_identity DROP CONSTRAINT schema_identity_baseline_id_check`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.schema_identity SET baseline_id=$1 WHERE id=1`, previous); err != nil {
		t.Fatal(err)
	}
	if err := database.Readiness(t.Context()); err == nil {
		t.Fatal("readiness accepted an intermediate guest baseline")
	}
	if err := Migrate(t.Context(), url); err == nil {
		t.Fatal("repeat migration accepted an intermediate guest baseline")
	}
	if opened, err := Open(t.Context(), url, testStorageKey, ""); err == nil {
		opened.Close()
		t.Fatal("serving accepted an intermediate guest baseline")
	}
	var stored string
	if err := database.pool.QueryRow(t.Context(), `SELECT baseline_id FROM control.schema_identity WHERE id=1`).Scan(&stored); err != nil || stored != previous {
		t.Fatal("schema entrypoint relabeled the intermediate baseline", stored, err)
	}
}
