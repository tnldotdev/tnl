package state

import (
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// use unchanged, single-loss and concurrent-renewal workloads on the same
// ready runs. the first refresh after close must already exclude the exact run.
func TestProfileIncrementalIngressReads(t *testing.T) {
	f := newControlLoadFixture(t)
	sessions := readySteadyLoadSessions(t, f)
	if len(sessions) < 2 {
		t.Fatal("requires at least two public services")
	}
	ctx := t.Context()
	lease, err := f.database.RegisterIngress(ctx, IngressRegistration{
		IngressID: "profile-ingress", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix), ProtocolVersion: 1,
		HTTPS: true, IngressPoolID: PrimaryIngressPoolID, ConnectionCapacity: uint64(max(64, f.routes)),
	}, f.now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// only the measured reader collects function statistics. flush its single
	// backend before each sample so setup and concurrent writers don't count.
	cfg := f.controls[0].pool.Config()
	cfg.MaxConns = 1
	cfg.ConnConfig.RuntimeParams["track_functions"] = "pl"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	reader := &Database{pool: pool, storageKey: f.database.storageKey, activity: f.controls[0].activity, connections: f.controls[0].connections}
	type readerStats struct {
		calls, seqRows, indexFetches, allocatedBytes int64
		ms                                           float64
	}
	stats := func() (s readerStats) {
		t.Helper()
		if _, err := pool.Exec(ctx, `SELECT pg_stat_force_next_flush()`); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT COALESCE(sum(calls),0)::bigint,COALESCE(sum(total_time),0),
			(SELECT COALESCE(sum(seq_tup_read),0)::bigint FROM pg_stat_user_tables WHERE schemaname='control'),
			(SELECT COALESCE(sum(idx_tup_fetch),0)::bigint FROM pg_stat_user_tables WHERE schemaname='control'),
			(SELECT sum(total_bytes)::bigint FROM pg_backend_memory_contexts) FROM pg_stat_user_functions
			WHERE funcid='control.publisher_service_permission(text,text,text,timestamptz)'::regprocedure`).Scan(&s.calls, &s.ms, &s.seqRows, &s.indexFetches, &s.allocatedBytes); err != nil {
			t.Fatal(err)
		}
		return
	}
	read := func() (map[string]IngressServiceRun, time.Duration) {
		t.Helper()
		start := time.Now()
		runs, err := readLoadServiceRuns(ctx, reader, lease.IngressLeaseIdentity, f.now)
		if err != nil {
			t.Fatal(err)
		}
		return runs, time.Since(start)
	}
	baseStats := stats()
	runs, cold := read()
	coldStats := stats()
	for _, s := range sessions {
		if err := observeLoadService(runs, s, f.now); err != nil {
			t.Fatal(err)
		}
	}
	var warm time.Duration
	for range 12 {
		current, elapsed := read()
		if len(current) != len(runs) {
			t.Fatal("lost a ready service")
		}
		warm += elapsed
	}
	warmStats := stats()
	lost := sessions[0]
	if err := f.database.CloseServiceRun(ctx, lost.service.ID, lost.run.RunID, lost.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	runs, afterLoss := read()
	lossStats := stats()
	if _, ok := runs[lost.run.RunID]; ok || len(runs) != len(sessions)-1 {
		t.Fatal("stale or missing run after disconnect")
	}
	for _, s := range sessions[1:] {
		if err := observeLoadService(runs, s, f.now); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("services=%d cold=%s steady_mean=%s first_refresh_after_close=%s survivors=%d", len(sessions), cold, warm/12, afterLoss, len(runs))
	t.Logf("permission_evaluations cold=%d steady_12=%d after_loss=%d; postgres_function_ms cold=%.2f steady_12=%.2f after_loss=%.2f",
		coldStats.calls-baseStats.calls, warmStats.calls-coldStats.calls, lossStats.calls-warmStats.calls,
		coldStats.ms-baseStats.ms, warmStats.ms-coldStats.ms, lossStats.ms-warmStats.ms)
	// table counters exclude index-only reads. memory contexts are this
	// backend's post-refresh allocations, not peak memory or process RSS.
	t.Logf("steady_12 seq_tup_read=%d idx_tup_fetch=%d reader_context_bytes=%d", warmStats.seqRows-coldStats.seqRows,
		warmStats.indexFetches-coldStats.indexFetches, warmStats.allocatedBytes)

	// sample writer latency while another control refreshes. all writers must
	// commit; record the tail rather than hiding contention behind a mean.
	n := min(32, len(sessions)-1)
	times := make([]time.Duration, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i, s := range sessions[1 : n+1] {
		wg.Go(func() {
			<-start
			begin := time.Now()
			_, errs[i] = f.controls[1].HeartbeatServiceRun(ctx, s.service.ID, s.run.RunID, s.run.Token, f.now, ServiceRunHealth{Healthy: true, StreamCapacity: 64})
			times[i] = time.Since(begin)
		})
	}
	close(start)
	_, readErr := reader.ReadIngressServices(ctx, lease.IngressLeaseIdentity, f.now)
	wg.Wait()
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	slices.Sort(times)
	t.Logf("simultaneous_heartbeats=%d median=%s max=%s", n, times[n/2], times[n-1])

	// unlike a close, a grant change leaves its run in the live candidate set.
	// read from a different control and count how much work a bucket collision adds.
	read()
	beforeRevoke := stats()
	revoked := sessions[1]
	if _, err := f.database.pool.Exec(ctx, `UPDATE control.publisher_grants SET revoked_at=$2 WHERE id=(
		SELECT publisher_grant_id FROM control.service_runs WHERE id=$1)`, revoked.run.RunID, f.now); err != nil {
		t.Fatal(err)
	}
	survivors, elapsed := read()
	afterRevoke := stats()
	if _, found := survivors[revoked.run.RunID]; found || len(survivors) != len(sessions)-2 {
		t.Fatal("revoked publisher or missing survivors")
	}
	for _, s := range sessions[2:] {
		if err := observeLoadService(survivors, s, f.now); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("grant_revocation refresh=%s permission_evaluations=%d survivors=%d", elapsed, afterRevoke.calls-beforeRevoke.calls, len(survivors))
}
