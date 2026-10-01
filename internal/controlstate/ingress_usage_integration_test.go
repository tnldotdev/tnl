package controlstate

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/publicurlusage"
)

func TestIntegrationIngressUsageReplayAndCompletion(t *testing.T) {
	database, base, lease, report := newIngressUsageFixture(t)
	initial := readUsageRun(t, database, lease)
	if !initial.observed.Equal(base) || !initial.expiry.Equal(base.Add(time.Minute)) || initial.complete {
		t.Fatalf("initial usage run = %#v", initial)
	}
	observed := base.Add(20 * time.Second)
	report.ObservedThrough, report.ConnectionAttempts, report.PolicyDenials = observed, 2, 1
	batch := IngressUsageBatch{Reports: []IngressUsageReport{report}, ObservedThrough: &observed}
	for _, at := range []time.Time{base.Add(21 * time.Second), base.Add(22 * time.Second)} {
		if err := database.ReportIngressUsage(t.Context(), lease.IngressLeaseIdentity, batch, at); err != nil {
			t.Fatalf("report/replay: %v", err)
		}
	}
	run := readUsageRun(t, database, lease)
	if !run.observed.Equal(observed) || !run.expiry.Equal(initial.expiry) || run.complete {
		t.Fatalf("reported usage run = %#v", run)
	}
	completeAt := base.Add(30 * time.Second)
	report.ReportRevision, report.Final, report.ConnectionAttempts, report.PolicyDenials, report.ObservedThrough = 2, true, 3, 3, completeAt
	batch = IngressUsageBatch{Reports: []IngressUsageReport{report}, ObservedThrough: &completeAt, Complete: true}
	for _, at := range []time.Time{base.Add(31 * time.Second), base.Add(32 * time.Second)} {
		if err := database.ReportIngressUsage(t.Context(), lease.IngressLeaseIdentity, batch, at); err != nil {
			t.Fatalf("complete/replay: %v", err)
		}
	}
	run = readUsageRun(t, database, lease)
	if !run.observed.Equal(completeAt) || !run.expiry.Equal(initial.expiry) || !run.complete {
		t.Fatalf("completed usage run = %#v", run)
	}
	var denials, attempts int64
	var bucketObserved time.Time
	if err := database.pool.QueryRow(t.Context(), `SELECT policy_denials FROM control.publish_runs WHERE id = 'session_usage'`).Scan(&denials); err != nil || denials != 3 {
		t.Fatalf("session denials = %d, %v", denials, err)
	}
	if err := database.pool.QueryRow(t.Context(), `SELECT connection_attempts, observed_through FROM control.public_url_usage_buckets WHERE public_url_id = 'public_url_usage' AND publish_run_number = 1 AND bucket_start = $1`, base).Scan(&attempts, &bucketObserved); err != nil || attempts != 3 || !bucketObserved.Equal(completeAt) {
		t.Fatalf("bucket attempts/observed = %d/%v, %v", attempts, bucketObserved, err)
	}
	if err := database.ReportIngressUsage(t.Context(), lease.IngressLeaseIdentity, IngressUsageBatch{ObservedThrough: &completeAt}, base.Add(33*time.Second)); !errors.Is(err, ErrIngressUsageReportStale) {
		t.Fatalf("post-completion report: %v", err)
	}
}

func TestIntegrationCompletePublicURLUsageAdvancesObservedThrough(t *testing.T) {
	database, base, lease, report := newIngressUsageFixture(t)
	seedCompletedUsageReport(t, database, base, lease, report)
	if finalized, err := database.FinalizePublicURLUsageBuckets(t.Context(), base.Add(time.Minute), base.Add(time.Minute)); err != nil || finalized != 1 {
		t.Fatalf("finalize public URL usage = %d, %v", finalized, err)
	}
	work, err := database.ClaimPublicURLUsageDeliveries(t.Context(), "usage_worker_complete", 32, base.Add(61*time.Second), time.Minute)
	if err != nil || len(work) != 1 {
		t.Fatalf("claim public URL usage = %#v, %v", work, err)
	}
	if !work[0].Complete || !work[0].ObservedThrough.Equal(work[0].BucketEnd) {
		t.Fatalf("public URL usage complete = %t, observed through = %s, bucket end = %s",
			work[0].Complete, work[0].ObservedThrough, work[0].BucketEnd)
	}
}

func TestIntegrationIngressUsageIncompleteCoverageBlocksFinalization(t *testing.T) {
	database, base, lease, report := newIngressUsageFixture(t)
	seedCompletedUsageReport(t, database, base, lease, report)
	idle, err := database.RegisterIngress(t.Context(), IngressRegistration{IngressID: "ingress_idle", IngressRunID: "run_idle", ProtocolVersion: 1, ConnectionCapacity: 10}, base, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	idle, err = database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: idle.IngressLeaseIdentity}, base.Add(10*time.Second), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	run := readUsageRun(t, database, idle)
	if !run.observed.Equal(base) || !run.expiry.Equal(base.Add(40*time.Second)) || run.complete {
		t.Fatalf("idle renewal changed coverage = %#v", run)
	}
	if count, err := database.FinalizePublicURLUsageBuckets(t.Context(), base.Add(time.Minute), base.Add(time.Minute)); err != nil || count != 0 {
		t.Fatalf("premature finalization = %d, %v", count, err)
	}
	if count, err := database.MarkExpiredIngressUsageRunsIncomplete(t.Context(), base.Add(61*time.Second)); err != nil || count != 1 {
		t.Fatalf("expired incomplete runs = %d, %v", count, err)
	}
	var from, until time.Time
	if err := database.pool.QueryRow(t.Context(), `SELECT incomplete_from, incomplete_until FROM control.ingress_usage_runs WHERE ingress_id = $1 AND ingress_run_id = $2`, idle.IngressID, idle.IngressRunID).Scan(&from, &until); err != nil {
		t.Fatal(err)
	}
	if !from.Equal(base) || !until.Equal(base.Add(40*time.Second)) {
		t.Fatalf("incomplete interval = %v through %v", from, until)
	}
	if count, err := database.FinalizePublicURLUsageBuckets(t.Context(), base.Add(time.Minute), base.Add(62*time.Second)); err != nil || count != 1 {
		t.Fatalf("finalization = %d, %v", count, err)
	}
	deliveries, err := database.ClaimPublicURLUsageDeliveries(t.Context(), "coverage", 1, base.Add(63*time.Second), time.Minute)
	if err != nil || len(deliveries) != 1 || deliveries[0].Complete {
		t.Fatalf("incomplete delivery = %#v, %v", deliveries, err)
	}
}

func TestIntegrationPublicURLUsageDeliveryRecovery(t *testing.T) {
	database, base, lease, report := newIngressUsageFixture(t)
	seedCompletedUsageReport(t, database, base, lease, report)
	if _, err := database.FinalizePublicURLUsageBuckets(t.Context(), base.Add(time.Minute), base.Add(62*time.Second)); err != nil {
		t.Fatal(err)
	}
	claimedAt := base.Add(63 * time.Second)
	first, err := database.ClaimPublicURLUsageDeliveries(t.Context(), "first", 1, claimedAt, 10*time.Second)
	if err != nil || len(first) != 1 {
		t.Fatalf("first delivery = %#v, %v", first, err)
	}
	work := first[0]
	if work.DeliveryKey == "" || work.Attempts != 1 || work.WorkEpoch != 1 || work.TeamID != "team_usage" || work.ActingIdentityID != "identity_usage" || work.ConnectionAttempts != 3 || !work.Complete || work.Checkpoint.VisitorNetworks.Estimate() != 0 {
		t.Fatalf("delivery work = %#v", work)
	}
	if other, err := database.ClaimPublicURLUsageDeliveries(t.Context(), "concurrent", 1, claimedAt.Add(time.Second), time.Minute); err != nil || len(other) != 0 {
		t.Fatalf("concurrent delivery = %#v, %v", other, err)
	}
	reclaimedAt := claimedAt.Add(11 * time.Second)
	reclaimed, err := database.ClaimPublicURLUsageDeliveries(t.Context(), "reclaimed", 1, reclaimedAt, 10*time.Second)
	if err != nil || len(reclaimed) != 1 || reclaimed[0].WorkEpoch != 2 || reclaimed[0].Attempts != 2 {
		t.Fatalf("reclaimed delivery = %#v, %v", reclaimed, err)
	}
	if err := database.CompletePublicURLUsageDelivery(t.Context(), work, reclaimedAt); !errors.Is(err, ErrPublicURLUsageDeliveryWorkStale) {
		t.Fatalf("stale delivery completion: %v", err)
	}
	retryAt := reclaimedAt.Add(5 * time.Second)
	if err := database.RetryPublicURLUsageDelivery(t.Context(), reclaimed[0], retryAt, "receiver unavailable", reclaimedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if early, err := database.ClaimPublicURLUsageDeliveries(t.Context(), "early", 1, retryAt.Add(-time.Microsecond), time.Minute); err != nil || len(early) != 0 {
		t.Fatalf("early retry = %#v, %v", early, err)
	}
	replayed, err := database.ClaimPublicURLUsageDeliveries(t.Context(), "replay", 1, retryAt, time.Minute)
	if err != nil || len(replayed) != 1 || replayed[0].WorkEpoch != 3 || replayed[0].Attempts != 3 {
		t.Fatalf("replayed delivery = %#v, %v", replayed, err)
	}
	replay := replayed[0]
	if replay.DeliveryKey != work.DeliveryKey || replay.SourceRevision != work.SourceRevision || replay.PublicURLID != work.PublicURLID || replay.PublishRunNumber != work.PublishRunNumber || replay.TeamID != work.TeamID || replay.ActingIdentityID != work.ActingIdentityID || !replay.BucketStart.Equal(work.BucketStart) || !replay.BucketEnd.Equal(work.BucketEnd) || !replay.ObservedThrough.Equal(work.ObservedThrough) || replay.ConnectionAttempts != work.ConnectionAttempts || !bytes.Equal(replay.Checkpoint.MarshalBinary(), work.Checkpoint.MarshalBinary()) {
		t.Fatal("retry changed delivery identity or payload")
	}
	if err := database.CompletePublicURLUsageDelivery(t.Context(), replay, retryAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if remaining, err := database.ClaimPublicURLUsageDeliveries(t.Context(), "done", 1, retryAt.Add(time.Hour), time.Minute); err != nil || len(remaining) != 0 {
		t.Fatalf("completed delivery still claimable = %#v, %v", remaining, err)
	}
}

func TestIntegrationPublicURLUsageTerminalRejection(t *testing.T) {
	database, base, lease, report := newIngressUsageFixture(t)
	seedCompletedUsageReport(t, database, base, lease, report)
	if _, err := database.FinalizePublicURLUsageBuckets(t.Context(), base.Add(time.Minute), base.Add(62*time.Second)); err != nil {
		t.Fatal(err)
	}
	claimedAt := base.Add(63 * time.Second)
	claimed, err := database.ClaimPublicURLUsageDeliveries(t.Context(), "first", 1, claimedAt, time.Minute)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim delivery = %#v, %v", claimed, err)
	}
	work := claimed[0]
	if err := database.RejectPublicURLUsageDelivery(t.Context(), work, "invalid_argument", claimedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := database.RetryPublicURLUsageDelivery(t.Context(), work, claimedAt.Add(2*time.Minute), "retry", claimedAt.Add(2*time.Second)); !errors.Is(err, ErrPublicURLUsageDeliveryWorkStale) {
		t.Fatalf("stale rejected work was retried: %v", err)
	}
	var state, lastError string
	if err := database.pool.QueryRow(t.Context(), `SELECT state, last_error FROM control.public_url_usage_deliveries WHERE delivery_key = $1`, work.DeliveryKey).Scan(&state, &lastError); err != nil || state != "rejected" || lastError != "invalid_argument" {
		t.Fatalf("rejection = %q, %q, %v", state, lastError, err)
	}
	if remaining, err := database.ClaimPublicURLUsageDeliveries(t.Context(), "next", 1, claimedAt.Add(24*time.Hour), time.Minute); err != nil || len(remaining) != 0 {
		t.Fatalf("rejected delivery reclaimed = %#v, %v", remaining, err)
	}
	// a newer report revision for the same bucket is a distinct delivery.
	var bucketID, revision int64
	if err := database.pool.QueryRow(t.Context(), `UPDATE control.public_url_usage_buckets SET bucket_revision = bucket_revision + 1 WHERE public_url_id = $1 RETURNING bucket_id, bucket_revision`, work.PublicURLID).Scan(&bucketID, &revision); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `INSERT INTO control.public_url_usage_deliveries (bucket_id, source_revision, delivery_key, state, available_at, created_at) VALUES ($1, $2, 'usage_report_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'pending', $3, $3)`, bucketID, revision, claimedAt.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	newer, err := database.ClaimPublicURLUsageDeliveries(t.Context(), "newer", 1, claimedAt.Add(24*time.Hour), time.Minute)
	if err != nil || len(newer) != 1 || newer[0].SourceRevision != work.SourceRevision+1 || newer[0].DeliveryKey == work.DeliveryKey {
		t.Fatalf("new report revision = %#v, %v", newer, err)
	}
}

func newIngressUsageFixture(t *testing.T) (*Database, time.Time, IngressLease, IngressUsageReport) {
	t.Helper()
	database, now := newControlStateIntegrationDatabase(t, "usage")
	base := now.Truncate(time.Minute)
	seedControlPublicURL(t, database, base, "usage")
	if _, err := database.pool.Exec(t.Context(), `INSERT INTO control.publish_runs (
		id, public_url_id, team_id, acting_identity_id, publish_run_number, idempotency_key, request_digest,
		publish_run_token_id, publish_run_token_digest, policy_revision, certificate_cache_key, certificate_scope,
		certificate_identifiers, certificate_challenge, state, created_at, last_heartbeat_at, publisher_expires_at)
		VALUES ('session_usage', 'public_url_usage', 'team_usage', 'identity_usage', 1, 'usage', decode(repeat('01',32),'hex'),
		'token_usage', decode(repeat('02',32),'hex'), 1, 'usage', 'usage', ARRAY['public-url-usage.example.test'], 'dns-01', 'starting', $1, $1, $2)`, base, base.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	lease, err := database.RegisterIngress(t.Context(), IngressRegistration{IngressID: "ingress_usage", IngressRunID: "run_usage", ProtocolVersion: 1, ConnectionCapacity: 10}, base, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return database, base, lease, IngressUsageReport{PublicURLID: "public_url_usage", PublishRunNumber: 1, BucketStart: base, BucketEnd: base.Add(time.Minute), ReportRevision: 1, HistogramData: (publicurlusage.Checkpoint{}).MarshalBinary()}
}

func seedCompletedUsageReport(t *testing.T, database *Database, base time.Time, lease IngressLease, report IngressUsageReport) {
	t.Helper()
	observed := base.Add(30 * time.Second)
	report.ObservedThrough, report.Final, report.ConnectionAttempts, report.PolicyDenials = observed, true, 3, 3
	if err := database.ReportIngressUsage(t.Context(), lease.IngressLeaseIdentity, IngressUsageBatch{Reports: []IngressUsageReport{report}, ObservedThrough: &observed, Complete: true}, observed); err != nil {
		t.Fatal(err)
	}
}

type usageRun struct {
	observed, expiry time.Time
	complete         bool
}

func readUsageRun(t *testing.T, database *Database, lease IngressLease) usageRun {
	t.Helper()
	var run usageRun
	if err := database.pool.QueryRow(t.Context(), `SELECT observed_through, lease_expires_at, coverage_complete FROM control.ingress_usage_runs WHERE ingress_id = $1 AND ingress_run_id = $2`, lease.IngressID, lease.IngressRunID).Scan(&run.observed, &run.expiry, &run.complete); err != nil {
		t.Fatal(err)
	}
	return run
}
