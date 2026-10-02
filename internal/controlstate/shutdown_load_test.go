package controlstate

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/publicurlusage"
)

// a finite shutdown workload with one-hour logical leases, not a cadence test.
// half the public URLs stop while the other half heartbeat and both ingress sources
// account for every public URL. publisher transports and visitor sockets
// are absent; the separate runtime load test exercises them.
func TestLoadShutdown(t *testing.T) {
	f := newControlLoadFixture(t)
	if f.routes < 2 {
		t.Fatal("shutdown load requires at least two routes")
	}
	sessions := readySteadyLoadSessions(t, f)
	initialRevision := seedLoadRoutingHistory(t, f, 1, f.history)
	closing := len(sessions) / 2
	byID := make(map[string]int, len(sessions))
	for index, session := range sessions {
		byID[session.setup.PublicURLID] = index
	}
	var ingresses [2]IngressLease
	for index := range ingresses {
		lease, err := f.database.RegisterIngress(t.Context(), IngressRegistration{
			IngressID: fmt.Sprintf("shutdown-ingress-%d", index), IngressRunID: "run", ProtocolVersion: 1, ConnectionCapacity: uint64(f.routes),
		}, f.now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		ingresses[index] = lease
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	actors := newIntegrationWorkers(t, cancel)
	defer actors.stop()
	var first sync.Once
	var firstErr error
	fail := func(err error) {
		first.Do(func() {
			firstErr = err
			diagnostic, _ := f.controls[0].Diagnostics(t.Context())
			data, _ := json.Marshal(diagnostic)
			t.Logf("shutdown_first_failure=%v diagnostic=%s", err, data)
			cancel()
		})
	}
	var heartbeats, pages, closed, maximumClose atomic.Int64
	var usageRevisions [2][]uint64
	for index := range usageRevisions {
		usageRevisions[index] = make([]uint64, len(sessions))
	}
	stopBackground := make(chan struct{})
	allWritesDone := make(chan struct{})
	ready := make(chan struct{}, 5)
	var heartbeatReady sync.Once
	var background sync.WaitGroup
	f.startMetrics(t)
	started := time.Now()
	defer func() {
		t.Logf("shutdown routes=%d closed=%d heartbeats=%d usage_pages_including_replays=%d close_workers=16 heartbeat_workers=48 max_close=%s elapsed=%s", f.routes, closed.Load(), heartbeats.Load(), pages.Load(), time.Duration(maximumClose.Load()), time.Since(started))
		f.logStats(t)
	}()
	for worker := range 48 {
		background.Add(1)
		actors.Go(func() {
			defer background.Done()
			for sweep := 1; ctx.Err() == nil; sweep++ {
				for index := closing + worker; index < len(sessions); index += 48 {
					select {
					case <-stopBackground:
						return
					default:
					}
					session := sessions[index]
					callCtx, stop := context.WithTimeout(ctx, 10*time.Second)
					updated, err := f.controls[worker%2].HeartbeatPublishRun(callCtx, session.authentication(), f.now.Add(time.Duration(sweep)*time.Millisecond), time.Hour, time.Hour)
					stop()
					if err != nil {
						fail(fmt.Errorf("healthy heartbeat: %w", err))
						return
					}
					if updated.PublishRunNumber != session.setup.PublishRunNumber || updated.State != PublishRunReady {
						fail(fmt.Errorf("healthy session changed: %s", session.setup.PublicURLID))
						return
					}
					heartbeats.Add(1)
					heartbeatReady.Do(func() { ready <- struct{}{} })
				}
				select {
				case <-stopBackground:
					return
				case <-ctx.Done():
					return
				case <-time.After(100 * time.Millisecond):
				}
			}
		})
	}
	for index, ingress := range ingresses {
		background.Add(1)
		actors.Go(func() {
			defer background.Done()
			bucket := f.now.Truncate(time.Minute)
			for revision := uint64(1); ctx.Err() == nil; revision++ {
				for offset := 0; offset < len(sessions); offset += 16 {
					var reports []IngressUsageReport
					for _, session := range sessions[offset:min(offset+16, len(sessions))] {
						n := revision * uint64(index+1)
						reports = append(reports, IngressUsageReport{PublicURLID: session.setup.PublicURLID, PublishRunNumber: session.setup.PublishRunNumber,
							BucketStart: bucket, BucketEnd: bucket.Add(time.Minute), ObservedThrough: f.now, ReportRevision: revision,
							ConnectionAttempts: 2 * n, SuccessfulStreams: n, PolicyDenials: n, IngressBytes: 100 * n, EgressBytes: 200 * n,
							HistogramData: (publicurlusage.Checkpoint{}).MarshalBinary()})
					}
					for range 2 {
						callCtx, stop := context.WithTimeout(ctx, 10*time.Second)
						err := f.controls[index].ReportIngressUsage(callCtx, ingress.IngressLeaseIdentity, IngressUsageBatch{Reports: reports}, f.now)
						stop()
						if err != nil {
							fail(fmt.Errorf("usage ingress=%d offset=%d: %w", index, offset, err))
							return
						}
						pages.Add(1)
					}
					for route := offset; route < min(offset+16, len(sessions)); route++ {
						usageRevisions[index][route] = revision
					}
					if revision == 1 && offset == 0 {
						ready <- struct{}{}
					}
				}
				select {
				case <-stopBackground:
					return
				default:
				}
			}
		})
		actors.Go(func() {
			if err := observeShutdownLoad(t, ctx, f.controls[index], ingress, f.now, uint64(initialRevision), byID, closing, allWritesDone, ready); err != nil {
				fail(err)
			}
		})
	}
	for range 5 {
		select {
		case <-ready:
		case <-ctx.Done():
			t.Fatalf("background startup: %v", ctx.Err())
		}
	}
	closeRange := func(begin, end int) {
		var next atomic.Int64
		next.Store(int64(begin))
		var closers sync.WaitGroup
		for worker := range 16 {
			closers.Add(1)
			actors.Go(func() {
				defer closers.Done()
				for ctx.Err() == nil {
					index := int(next.Add(1) - 1)
					if index >= end {
						return
					}
					session := sessions[index]
					callCtx, stop := context.WithTimeout(ctx, 10*time.Second)
					at := time.Now()
					err := f.controls[worker%2].ClosePublishRun(callCtx, session.setup.PublishRunID, session.setup.PublishRunToken, f.now.Add(time.Second))
					elapsed := time.Since(at)
					stop()
					for old := maximumClose.Load(); int64(elapsed) > old; old = maximumClose.Load() {
						if maximumClose.CompareAndSwap(old, int64(elapsed)) {
							break
						}
					}
					if err != nil {
						fail(fmt.Errorf("close route=%s elapsed=%s: %w", session.setup.PublicURLID, elapsed, err))
						return
					}
					closed.Add(1)
				}
			})
		}
		closers.Wait()
	}
	closeStarted := time.Now()
	beforeHeartbeats, beforePages := heartbeats.Load(), pages.Load()
	closeRange(0, closing)
	duringHeartbeats, duringPages := heartbeats.Load()-beforeHeartbeats, pages.Load()-beforePages
	t.Logf("shutdown_under_load closed=%d elapsed=%s background_heartbeats=%d background_pages=%d", closed.Load(), time.Since(closeStarted), duringHeartbeats, duringPages)
	close(stopBackground)
	background.Wait()
	close(allWritesDone)
	actors.Wait()
	if firstErr != nil || ctx.Err() != nil {
		t.Fatalf("shutdown under load: %v (context %v)", firstErr, ctx.Err())
	}
	// tiny smoke fixtures can close between the 100ms heartbeat sweeps. larger
	// load cases must demonstrate completed background work during closure itself.
	if f.routes >= 128 && (duringHeartbeats == 0 || duringPages == 0) {
		t.Fatal("background work made no progress while closing routes")
	}
	assertAssignmentTotals(t, f.database.pool, int64(len(sessions)-closing)*2)
	middle, err := f.database.ReadIngressRoutingTableSnapshot(ctx, ingresses[0].IngressLeaseIdentity, f.now.Add(time.Second))
	if err != nil || len(middle.Entries) != len(sessions)-closing {
		t.Fatalf("healthy routes after partial shutdown: count=%d, %v", len(middle.Entries), err)
	}
	for _, event := range middle.Entries {
		index, exists := byID[event.PublicURLID]
		if !exists || index < closing || event.PublishRunNumber != sessions[index].setup.PublishRunNumber || len(event.Projection.PublisherConnections) != 2 {
			t.Fatalf("unexpected surviving route %s", event.PublicURLID)
		}
	}
	// usage remains accepted for closed historical publish run numbers and must not be lost
	// or counted again by replay. verify every public URL, not only global totals.
	for index, session := range sessions {
		want := int64(usageRevisions[0][index] + 2*usageRevisions[1][index])
		var matches bool
		if err := f.database.pool.QueryRow(ctx, `SELECT b.connection_attempts = $2*2 AND b.successful_streams = $2
			AND b.policy_denials = $2 AND b.ingress_bytes = $2*100 AND b.egress_bytes = $2*200
			AND s.policy_denials = $2 AND (s.closed_at IS NOT NULL) = $3
			FROM control.public_url_usage_buckets b JOIN control.publish_runs s ON s.public_url_id = b.public_url_id AND s.publish_run_number = b.publish_run_number
			WHERE s.id = $1`, session.setup.PublishRunID, want, index < closing).Scan(&matches); err != nil || !matches {
			t.Fatalf("shutdown accounting route=%s want=%d: %v", session.setup.PublicURLID, want, err)
		}
	}
	closeRange(closing, len(sessions))
	if firstErr != nil || ctx.Err() != nil {
		t.Fatalf("final close: %v (context %v)", firstErr, ctx.Err())
	}
	var openSessions, activeConnections int64
	if err := f.database.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM control.publish_runs WHERE closed_at IS NULL OR assignments_open OR state <> 'closed'),
		(SELECT count(*) FROM control.publish_run_connection_slots WHERE state <> 'closed')`).Scan(&openSessions, &activeConnections); err != nil || openSessions != 0 || activeConnections != 0 {
		t.Fatalf("remaining sessions=%d connections=%d: %v", openSessions, activeConnections, err)
	}
	assertAssignmentTotals(t, f.database.pool, 0)
	var buckets int
	if err := f.database.pool.QueryRow(ctx, `SELECT count(*) FROM control.public_url_usage_buckets`).Scan(&buckets); err != nil || buckets != len(sessions) {
		t.Fatalf("usage bucket count=%d: %v", buckets, err)
	}
	// a repeated close must not publish another tombstone or release capacity twice.
	if err := f.controls[0].ClosePublishRun(ctx, sessions[0].setup.PublishRunID, sessions[0].setup.PublishRunToken, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	final, err := f.database.ReadIngressRoutingTableSnapshot(ctx, ingresses[0].IngressLeaseIdentity, f.now.Add(time.Second))
	wantRevision := uint64(initialRevision) + uint64(heartbeats.Load()) + uint64(len(sessions))
	if err != nil || len(final.Entries) != 0 || final.RoutingTableRevision != wantRevision {
		t.Fatalf("final routing rows=%d revision=%d want=%d: %v", len(final.Entries), final.RoutingTableRevision, wantRevision, err)
	}
	t.Logf("shutdown_verified sessions=%d connections=%d usage_buckets=%d final_revision=%d", len(sessions), 2*len(sessions), len(sessions), wantRevision)
}

func observeShutdownLoad(t *testing.T, ctx context.Context, database *Database, ingress IngressLease, now time.Time, cursor uint64, routes map[string]int, closing int, finished <-chan struct{}, ready chan<- struct{}) error {
	retired := make(map[string]bool)
	first := true
	for ctx.Err() == nil {
		done := false
		select {
		case <-finished:
			done = true
		default:
		}
		callCtx, stop := context.WithTimeout(ctx, 10*time.Second)
		page, err := database.ReadIngressRoutingTableEvents(callCtx, ingress.IngressLeaseIdentity, cursor, MaximumIngressRoutingTablePageSize, now)
		stop()
		if err != nil || page.ResnapshotRequired {
			return fmt.Errorf("shutdown routing read: resnapshot=%t: %w", page.ResnapshotRequired, err)
		}
		for _, event := range page.Events {
			index, exists := routes[event.PublicURLID]
			if !exists || event.RoutingTableRevision != cursor+1 || retired[event.PublicURLID] {
				return fmt.Errorf("shutdown routing lost order or resurrected route %s", event.PublicURLID)
			}
			switch event.Kind {
			case IngressPublicURLTombstone:
				if index >= closing {
					return fmt.Errorf("healthy route %s retired", event.PublicURLID)
				}
				retired[event.PublicURLID] = true
			case IngressPublicURLUpsert:
				if index < closing || len(event.Projection.PublisherConnections) != 2 {
					return fmt.Errorf("unexpected shutdown upsert %s", event.PublicURLID)
				}
			default:
				return fmt.Errorf("unexpected shutdown event %s", event.Kind)
			}
			cursor = event.RoutingTableRevision
		}
		if page.NextRevision != cursor {
			return fmt.Errorf("shutdown cursor mismatch %d != %d", page.NextRevision, cursor)
		}
		callCtx, stop = context.WithTimeout(ctx, 10*time.Second)
		_, err = database.RenewIngress(callCtx, IngressRenewal{IngressLeaseIdentity: ingress.IngressLeaseIdentity, RoutingTableRevision: cursor}, now, time.Hour)
		stop()
		if err != nil {
			return err
		}
		if first {
			ready <- struct{}{}
			first = false
		}
		if done && !page.More {
			if len(retired) != closing {
				return fmt.Errorf("ingress saw %d tombstones, want %d", len(retired), closing)
			}
			t.Logf("shutdown_ingress=%s retired=%d cursor=%d", ingress.IngressID, len(retired), cursor)
			return nil
		}
		if !page.More {
			select {
			case <-ctx.Done():
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	return ctx.Err()
}
