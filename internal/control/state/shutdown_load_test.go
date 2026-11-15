package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
)

// half the services close while the others heartbeat. two ingress observers
// check current admission and exact terminal tuples, not retired routing history.
func TestLoadShutdown(t *testing.T) {
	f := newControlLoadFixture(t)
	if f.routes < 2 {
		t.Fatal("shutdown load requires at least two services")
	}
	sessions := readySteadyLoadSessions(t, f)
	closing := len(sessions) / 2
	var ingresses [2]IngressLease
	for index := range ingresses {
		lease, err := f.database.RegisterIngress(t.Context(), IngressRegistration{
			IngressID: fmt.Sprintf("shutdown-ingress-%d", index), IngressRunID: "run", ProtocolVersion: 1,
			HTTPS: true, IngressPoolID: PrimaryIngressPoolID, ConnectionCapacity: uint64(max(64, f.routes)),
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
	var heartbeats, closed, maximumClose atomic.Int64
	stopBackground, allWritesDone := make(chan struct{}), make(chan struct{})
	ready := make(chan struct{}, 3)
	var heartbeatReady sync.Once
	var background sync.WaitGroup
	f.startMetrics(t)
	started := time.Now()
	defer func() {
		t.Logf("shutdown services=%d closed=%d heartbeats=%d close_workers=16 heartbeat_workers=48 max_close=%s elapsed=%s",
			f.routes, closed.Load(), heartbeats.Load(), time.Duration(maximumClose.Load()), time.Since(started))
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
					run, err := f.controls[worker%2].HeartbeatServiceRun(callCtx, session.service.ID, session.run.RunID,
						session.run.Token, f.now.Add(time.Duration(sweep)*time.Millisecond), ServiceRunHealth{Healthy: true, StreamCapacity: 64})
					stop()
					if err != nil || run.RunID != session.run.RunID || run.RunNumber != session.run.RunNumber || run.State != "ready" {
						fail(fmt.Errorf("healthy service changed: service=%s err=%v", session.service.ID, err))
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
		actors.Go(func() {
			if err := observeShutdownLoad(t, ctx, f.controls[index], ingress, f.now.Add(time.Second), sessions, closing, allWritesDone, ready); err != nil {
				fail(err)
			}
		})
	}
	for range 3 {
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
					err := f.controls[worker%2].CloseServiceRun(callCtx, session.service.ID, session.run.RunID, session.run.Token, f.now.Add(time.Second))
					elapsed := time.Since(at)
					stop()
					for old := maximumClose.Load(); int64(elapsed) > old; old = maximumClose.Load() {
						if maximumClose.CompareAndSwap(old, int64(elapsed)) {
							break
						}
					}
					if err != nil {
						fail(fmt.Errorf("close service=%s elapsed=%s: %w", session.service.ID, elapsed, err))
						return
					}
					closed.Add(1)
				}
			})
		}
		closers.Wait()
	}
	closeStarted, beforeHeartbeats := time.Now(), heartbeats.Load()
	closeRange(0, closing)
	duringHeartbeats := heartbeats.Load() - beforeHeartbeats
	t.Logf("shutdown_under_load closed=%d elapsed=%s background_heartbeats=%d", closed.Load(), time.Since(closeStarted), duringHeartbeats)
	close(stopBackground)
	background.Wait()
	close(allWritesDone)
	actors.Wait()
	if firstErr != nil || ctx.Err() != nil {
		t.Fatalf("shutdown under load: %v (context %v)", firstErr, ctx.Err())
	}
	if f.routes >= 128 && duringHeartbeats == 0 {
		t.Fatal("background work made no progress while closing services")
	}
	assertAssignmentTotals(t, f.database.pool, int64(len(sessions)-closing)*2)
	for index, session := range sessions {
		var matches bool
		if err := f.database.pool.QueryRow(ctx, `SELECT service_id=$2 AND run_number=$3 AND (closed_at IS NOT NULL)=$4
			FROM control.service_runs WHERE id=$1`, session.run.RunID, session.service.ID, session.run.RunNumber, index < closing).Scan(&matches); err != nil || !matches {
			t.Fatalf("shutdown changed the durable tuple for service=%s closed=%t: %v", session.service.ID, index < closing, err)
		}
	}
	closeRange(closing, len(sessions))
	if firstErr != nil || ctx.Err() != nil {
		t.Fatalf("final close: %v (context %v)", firstErr, ctx.Err())
	}
	var openRuns, activeConnections int64
	if err := f.database.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM control.service_runs WHERE closed_at IS NULL OR state<>'closed'),
		(SELECT count(*) FROM control.service_connection_slots WHERE state<>'closed' OR session_open)`).Scan(&openRuns, &activeConnections); err != nil || openRuns != 0 || activeConnections != 0 {
		t.Fatalf("remaining runs=%d connections=%d: %v", openRuns, activeConnections, err)
	}
	assertAssignmentTotals(t, f.database.pool, 0)
	// a late close rejects the old run instead of releasing capacity twice.
	var before, after time.Time
	if err := f.database.pool.QueryRow(ctx, `SELECT closed_at FROM control.service_runs WHERE id=$1`, sessions[0].run.RunID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := f.controls[0].CloseServiceRun(ctx, sessions[0].service.ID, sessions[0].run.RunID, sessions[0].run.Token, f.now.Add(2*time.Second)); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("a repeated close did not reject the terminal run", err)
	}
	if err := f.database.pool.QueryRow(ctx, `SELECT closed_at FROM control.service_runs WHERE id=$1`, sessions[0].run.RunID).Scan(&after); err != nil || !before.Equal(after) {
		t.Fatal("repeated close changed terminal state", err)
	}
	assertAssignmentTotals(t, f.database.pool, 0)
	for _, ingress := range ingresses {
		for start := 0; start < len(sessions); start += 128 {
			var refs []ServiceRunReference
			for _, session := range sessions[start:min(start+128, len(sessions))] {
				refs = append(refs, ServiceRunReference{ServiceID: session.service.ID, RunID: session.run.RunID, RunNumber: session.run.RunNumber})
			}
			proof, err := f.database.ClosedServiceRuns(ctx, ingress.IngressLeaseIdentity, refs, f.now.Add(2*time.Second))
			if err != nil || len(proof) != len(refs) {
				t.Fatal("final shutdown lost exact terminal proofs", len(proof), len(refs), err)
			}
		}
	}
	t.Logf("shutdown_verified runs=%d connections=%d", len(sessions), 2*len(sessions))
}

func observeShutdownLoad(t *testing.T, ctx context.Context, database *Database, ingress IngressLease, now time.Time, sessions []servicePublicationFixture, closing int, finished <-chan struct{}, ready chan<- struct{}) error {
	retired := make(map[string]bool)
	first := true
	for ctx.Err() == nil {
		done := false
		select {
		case <-finished:
			done = true
		default:
		}
		for index, session := range sessions {
			callCtx, stop := context.WithTimeout(ctx, 10*time.Second)
			err := observeLoadService(callCtx, database, ingress.IngressLeaseIdentity, session, now)
			stop()
			if err == nil {
				if retired[session.service.ID] {
					return fmt.Errorf("shutdown resurrected service %s", session.service.ID)
				}
				continue
			}
			if index >= closing || !failure.Only(err, ErrServiceAccess) {
				return fmt.Errorf("shutdown admission service=%s: %w", session.service.ID, err)
			}
			ref := ServiceRunReference{ServiceID: session.service.ID, RunID: session.run.RunID, RunNumber: session.run.RunNumber}
			proof, err := database.ClosedServiceRuns(ctx, ingress.IngressLeaseIdentity, []ServiceRunReference{ref}, now)
			if err != nil || len(proof) != 1 || proof[0] != ref {
				return fmt.Errorf("unavailable service %s had no exact terminal proof: %w", session.service.ID, err)
			}
			retired[session.service.ID] = true
		}
		if _, err := database.RenewIngress(ctx, IngressRenewal{IngressLeaseIdentity: ingress.IngressLeaseIdentity}, now, time.Hour); err != nil {
			return err
		}
		if first {
			ready <- struct{}{}
			first = false
		}
		if done {
			if len(retired) != closing {
				return fmt.Errorf("ingress observed %d terminal services, want %d", len(retired), closing)
			}
			t.Logf("shutdown_ingress=%s retired=%d", ingress.IngressID, len(retired))
			return nil
		}
		select {
		case <-ctx.Done():
		case <-finished:
		case <-time.After(100 * time.Millisecond):
		}
	}
	return ctx.Err()
}
