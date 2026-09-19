package controlstate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

func TestIntegrationIngressUsageReplaySkipsRouteLocks(t *testing.T) {
	for _, lock := range []string{"route", "session"} {
		t.Run(lock, func(t *testing.T) {
			database, base, lease, older := newIngressUsageFixture(t)
			older.ObservedThrough, older.ConnectionAttempts, older.PolicyDenials = base.Add(20*time.Second), 2, 1
			latest := older
			latest.ReportRevision, latest.ConnectionAttempts, latest.PolicyDenials = 3, 4, 2
			latest.ObservedThrough = base.Add(30 * time.Second)
			for _, report := range []IngressUsageReport{older, latest} {
				if err := database.ReportIngressUsage(t.Context(), lease.IngressLeaseIdentity, IngressUsageBatch{Reports: []IngressUsageReport{report}}, base.Add(40*time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			gate, err := database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if lock == "route" {
				_, err = controlstatedb.New(gate).LockRouteForSession(ctx, older.RouteID)
			} else {
				_, err = controlstatedb.New(gate).LockRouteSessionForUsage(ctx, controlstatedb.LockRouteSessionForUsageParams{
					RouteID: older.RouteID, RouteVersion: int64(older.RouteVersion),
				})
			}
			if err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			olderConflict, latestConflict, missing := older, latest, older
			olderConflict.PolicyDenials++
			latestConflict.ConnectionAttempts++
			missing.ReportRevision = 2
			watermark := base.Add(40 * time.Second)
			for _, test := range []struct {
				name   string
				report IngressUsageReport
				want   error
			}{
				{"latest replay", latest, nil},
				{"older replay", older, nil},
				{"latest conflict", latestConflict, ErrIngressUsageReportConflict},
				{"older conflict", olderConflict, ErrIngressUsageReportConflict},
				{"missing revision", missing, ErrIngressUsageReportStale},
			} {
				replayCtx, stop := context.WithTimeout(ctx, 2*time.Second)
				err := database.ReportIngressUsage(replayCtx, lease.IngressLeaseIdentity, IngressUsageBatch{
					Reports: []IngressUsageReport{test.report}, ObservedThrough: &watermark,
				}, base.Add(42*time.Second))
				stop()
				if !errors.Is(err, test.want) {
					t.Fatalf("%s while %s lock is held: got %v, want %v", test.name, lock, err, test.want)
				}
			}
			var lastReported, observed time.Time
			if err := database.pool.QueryRow(ctx, `SELECT last_reported_at, observed_through FROM control.ingress_usage_runs WHERE ingress_id = $1 AND ingress_run_id = $2`, lease.IngressID, lease.IngressRunID).Scan(&lastReported, &observed); err != nil || !lastReported.Equal(base.Add(42*time.Second)) || !observed.Equal(watermark) {
				t.Fatalf("replay did not advance usage run: last reported=%v observed=%v: %v", lastReported, observed, err)
			}

			next := latest
			next.ReportRevision, next.ConnectionAttempts, next.PolicyDenials = 4, 6, 3
			next.ObservedThrough = watermark
			batch := IngressUsageBatch{Reports: []IngressUsageReport{next}, ObservedThrough: &watermark}
			applied := make(chan error, 1)
			workers.Go(func() {
				applied <- database.ReportIngressUsage(ctx, lease.IngressLeaseIdentity, batch, base.Add(43*time.Second))
			})
			writerPID := waitForPostgresBlock(t, ctx, database, int32(gate.Conn().PgConn().PID()), applied)
			// A concurrent copy must wait for the ingress guard, then replay the
			// committed revision instead of applying the same delta twice.
			replayed := make(chan error, 1)
			workers.Go(func() {
				replayed <- database.ReportIngressUsage(ctx, lease.IngressLeaseIdentity, batch, base.Add(44*time.Second))
			})
			waitForPostgresBlock(t, ctx, database, writerPID, replayed)
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			for _, done := range []chan error{applied, replayed} {
				if err := awaitIntegrationResult(t, ctx, done); err != nil {
					t.Fatal(err)
				}
			}
			var attempts, denials, sessionDenials, revision, reports int64
			if err := database.pool.QueryRow(ctx, `
				SELECT buckets.connection_attempts, buckets.policy_denials, sessions.policy_denials, buckets.bucket_revision,
				       (SELECT count(*) FROM control.ingress_usage_reports)
				FROM control.route_usage_buckets AS buckets
				JOIN control.route_sessions AS sessions USING (route_id, route_version)
				WHERE buckets.route_id = $1 AND buckets.route_version = $2 AND buckets.bucket_start = $3
			`, next.RouteID, int64(next.RouteVersion), next.BucketStart).Scan(&attempts, &denials, &sessionDenials, &revision, &reports); err != nil || attempts != 6 || denials != 3 || sessionDenials != 3 || revision != 3 || reports != 3 {
				t.Fatalf("usage after replay/new revision: attempts=%d denials=%d session denials=%d bucket revision=%d reports=%d: %v", attempts, denials, sessionDenials, revision, reports, err)
			}
		})
	}
}

func TestIntegrationIngressUsageFinalizedReplayChecksLiveGuards(t *testing.T) {
	database, base, lease, report := newIngressUsageFixture(t)
	report.ObservedThrough, report.ConnectionAttempts, report.PolicyDenials = base.Add(20*time.Second), 2, 1
	watermark := report.BucketEnd
	batch := IngressUsageBatch{Reports: []IngressUsageReport{report}, ObservedThrough: &watermark}
	if err := database.ReportIngressUsage(t.Context(), lease.IngressLeaseIdentity, batch, base.Add(59*time.Second)); err != nil {
		t.Fatal(err)
	}
	// Keep the ingress lease live after the bucket can finalize. The report is
	// not final, so a new revision must reach the aggregate finalization guard.
	lease, err := database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: lease.IngressLeaseIdentity}, base.Add(59*time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := database.FinalizeRouteUsageBuckets(t.Context(), watermark, watermark); err != nil || count != 1 {
		t.Fatalf("finalize bucket: count=%d: %v", count, err)
	}
	wrongRun, wrongRevision := lease.IngressLeaseIdentity, lease.IngressLeaseIdentity
	wrongRun.IngressRunID = "other-run"
	wrongRevision.IngressLeaseRevision++
	for _, test := range []struct {
		name     string
		identity IngressLeaseIdentity
		at       time.Time
		want     error
	}{
		{"exact replay after finalization", lease.IngressLeaseIdentity, base.Add(61 * time.Second), nil},
		{"wrong run", wrongRun, base.Add(62 * time.Second), ErrIngressLeaseStale},
		{"wrong lease revision", wrongRevision, base.Add(62 * time.Second), ErrIngressLeaseStale},
		{"expired lease", lease.IngressLeaseIdentity, lease.LeaseExpiresAt, ErrIngressLeaseStale},
	} {
		if err := database.ReportIngressUsage(t.Context(), test.identity, batch, test.at); !errors.Is(err, test.want) {
			t.Fatalf("%s: got %v, want %v", test.name, err, test.want)
		}
	}
	stale := batch
	stale.ObservedThrough = &report.ObservedThrough
	if err := database.ReportIngressUsage(t.Context(), lease.IngressLeaseIdentity, stale, base.Add(62*time.Second)); !errors.Is(err, ErrIngressUsageReportStale) {
		t.Fatalf("exact replay with stale watermark: %v", err)
	}
	next := report
	next.ReportRevision, next.ConnectionAttempts, next.PolicyDenials = 2, 4, 2
	if err := database.ReportIngressUsage(t.Context(), lease.IngressLeaseIdentity, IngressUsageBatch{Reports: []IngressUsageReport{next}}, base.Add(62*time.Second)); !errors.Is(err, ErrRouteUsageBucketFinalized) {
		t.Fatalf("new revision after finalization: %v", err)
	}
	var attempts, denials, sessionDenials, revision, reports int64
	if err := database.pool.QueryRow(t.Context(), `
		SELECT buckets.connection_attempts, buckets.policy_denials, sessions.policy_denials, buckets.bucket_revision,
		       (SELECT count(*) FROM control.ingress_usage_reports)
		FROM control.route_usage_buckets AS buckets
		JOIN control.route_sessions AS sessions USING (route_id, route_version)
		WHERE buckets.route_id = $1 AND buckets.route_version = $2 AND buckets.bucket_start = $3
	`, report.RouteID, int64(report.RouteVersion), report.BucketStart).Scan(&attempts, &denials, &sessionDenials, &revision, &reports); err != nil || attempts != 2 || denials != 1 || sessionDenials != 1 || revision != 1 || reports != 1 {
		t.Fatalf("finalized usage changed: attempts=%d denials=%d session denials=%d bucket revision=%d reports=%d: %v", attempts, denials, sessionDenials, revision, reports, err)
	}
}
