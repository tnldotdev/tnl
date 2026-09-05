package controlstate

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/routeusage"
)

// A database-state model of one relay restart, not a process-crash or visitor
// recovery test. Drain to a short logical deadline, then register a new run.
// The other leases remain valid for one hour; no real network calls are made.
func TestLoadRelayRecovery(t *testing.T) {
	f := newControlLoadFixture(t)
	if f.routes < 2 {
		t.Fatal("relay recovery requires at least two routes for affected and healthy work")
	}
	sessions := readySteadyLoadSessions(t, f)
	historyRevision := seedLoadRoutingHistory(t, f, 1, f.history)
	failed := sessions[0].leases[sessions[0].setup.PublisherConnections[0].RelayServiceID]
	var affected, unaffected []int
	byID := make(map[string]int, f.routes)
	current := make([]RouteSessionSetup, f.routes)
	for index, session := range sessions {
		byID[session.setup.RouteID], current[index] = index, session.setup
		if session.leases[failed.RelayServiceID].RelayLeaseIdentity == failed.RelayLeaseIdentity {
			affected = append(affected, index)
		} else {
			unaffected = append(unaffected, index)
		}
	}
	if len(affected) != (f.routes+1)/2 || len(unaffected) != f.routes/2 {
		t.Fatalf("unexpected affected/unaffected split: %d/%d", len(affected), len(unaffected))
	}
	var ingresses [2]IngressLease
	for index := range ingresses {
		lease, err := f.database.RegisterIngress(t.Context(), IngressRegistration{
			IngressID: fmt.Sprintf("recovery-ingress-%d", index), IngressRunID: "load-run", ProtocolVersion: 1,
			ConnectionCapacity: uint64(f.routes),
		}, f.now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		ingresses[index] = lease
	}
	initial, err := f.database.ReadIngressRoutingTableSnapshot(t.Context(), ingresses[0].IngressLeaseIdentity, f.now)
	if err != nil || len(initial.Routes) != f.routes || initial.RoutingTableRevision != uint64(historyRevision) {
		t.Fatalf("initial snapshot: routes=%d want=%d: %v", len(initial.Routes), f.routes, err)
	}
	entries := make(map[string]uint64, f.routes)
	for _, event := range initial.Routes {
		index, ok := byID[event.RouteID]
		if !ok || entries[event.RouteID] != 0 || event.EntryRevision != uint64(f.history) {
			t.Fatalf("unexpected initial route %s", event.RouteID)
		}
		if err := checkRecoveryLoadProjection(event, sessions[index], current[index], RelayLease{}, f.now, true); err != nil {
			t.Fatal(err)
		}
		entries[event.RouteID] = event.EntryRevision
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	var recovered, healthyRoutes, heartbeats atomic.Int64
	var pages [2]atomic.Int64
	var usageRevisions [2]uint64 // One writer per ingress; read only after joining.
	recoveryTimes := make([]time.Duration, f.routes)
	f.startMetrics(t)
	started := time.Now()
	defer func() {
		var total, maximum time.Duration
		for _, elapsed := range recoveryTimes {
			total += elapsed
			maximum = max(maximum, elapsed)
		}
		t.Logf("affected=%d recovered=%d unaffected_verified=%d/%d healthy_heartbeats=%d usage_pages=%d+%d usage_revisions=%d+%d workflows=64 elapsed=%s",
			len(affected), recovered.Load(), healthyRoutes.Load(), len(unaffected), heartbeats.Load(), pages[0].Load(), pages[1].Load(), usageRevisions[0], usageRevisions[1], time.Since(started))
		t.Logf("successful_slot_recovery_mean=%s max=%s (heartbeat through readiness)", total/time.Duration(max(1, recovered.Load())), maximum)
		f.logStats(t)
	}()
	defer workers.stop()
	var first, healthyStarted sync.Once
	var firstErr error
	fail := func(err error) { first.Do(func() { firstErr = err; cancel() }) }
	now := f.now.Add(3 * time.Second)
	callCtx, stop := context.WithTimeout(ctx, 20*time.Second)
	drained, err := f.controls[0].BeginRelayDrain(callCtx, failed.RelayLeaseIdentity, f.now.Add(time.Second), f.now.Add(2*time.Second))
	stop()
	if err != nil || drained.RelayLeaseIdentity != failed.RelayLeaseIdentity || !drained.Draining || !drained.LeaseExpiresAt.Before(now) {
		t.Fatalf("expire relay=%s: %v", failed.RelayID, err)
	}

	// 32 recovery workflows and 32 healthy workflows share the same two pools.
	// Healthy heartbeats and the two serial usage writers finish their current
	// sweep only after every affected slot has actually been marked ready.
	restartReady := make(chan struct{})
	backgroundReady := make(chan struct{}, 3+len(ingresses))
	var work sync.WaitGroup
	work.Add(64 + len(ingresses))
	var restarted RelayLease // Published to recovery workflows by restartReady.
	for worker := range 32 {
		workers.Go(func() {
			defer work.Done()
			select {
			case <-ctx.Done():
				return
			case <-restartReady:
			}
			for offset := worker; offset < len(affected) && ctx.Err() == nil; offset += 32 {
				index := affected[offset]
				began := time.Now()
				setup, err := recoverLoadRelaySlot(ctx, f.controls[worker%2], sessions[index], failed, restarted, now)
				if err != nil {
					fail(fmt.Errorf("recover route=%s: %w", sessions[index].setup.RouteID, err))
					return
				}
				current[index], recoveryTimes[index] = setup, time.Since(began)
				if recovered.Add(1) == int64(len(affected)) {
					t.Logf("all_slots_ready_elapsed=%s healthy_heartbeats=%d usage_pages=%d+%d", time.Since(started), heartbeats.Load(), pages[0].Load(), pages[1].Load())
				}
			}
		})
		workers.Go(func() {
			defer work.Done()
			if worker >= len(unaffected) {
				return
			}
			for sweep := 0; ctx.Err() == nil; sweep++ {
				for offset := worker; offset < len(unaffected) && ctx.Err() == nil; offset += 32 {
					index := unaffected[offset]
					session := sessions[index]
					callCtx, stop := context.WithTimeout(ctx, 20*time.Second)
					// One owner per route advances its logical heartbeats monotonically.
					at := now.Add(time.Since(started))
					setup, err := f.controls[worker%2].HeartbeatRouteSession(callCtx, session.authentication(), at, time.Hour, time.Hour)
					stop()
					if err != nil {
						fail(fmt.Errorf("healthy heartbeat route=%s: %w", session.setup.RouteID, err))
						return
					}
					if setup.RouteID != session.setup.RouteID || setup.RouteSessionID != session.setup.RouteSessionID ||
						setup.RouteVersion != session.setup.RouteVersion || setup.RouteSessionToken != session.setup.RouteSessionToken ||
						setup.State != RouteSessionReady || setup.ReadyAt == nil || !setup.ReadyAt.Equal(f.now) || setup.ClosedAt != nil || !setup.ExpiresAt.After(at) {
						fail(fmt.Errorf("healthy heartbeat changed session route=%s", session.setup.RouteID))
						return
					}
					for slot, connection := range setup.PublisherConnections {
						expected := session.setup.PublisherConnections[slot]
						expected.State = PublisherConnectionReady
						if connection != expected {
							fail(fmt.Errorf("healthy heartbeat changed assignment route=%s slot=%d", setup.RouteID, slot))
							return
						}
					}
					if sweep == 0 {
						healthyRoutes.Add(1)
					}
					heartbeats.Add(1)
					healthyStarted.Do(func() { backgroundReady <- struct{}{} })
				}
				if recovered.Load() == int64(len(affected)) {
					return
				}
			}
		})
	}
	bucketStart := f.now.Truncate(time.Minute)
	for index, ingress := range ingresses {
		workers.Go(func() {
			defer work.Done()
			for revision := uint64(1); ctx.Err() == nil; revision++ {
				for offset := 0; offset < len(sessions) && ctx.Err() == nil; offset += 16 {
					var reports []IngressUsageReport
					for _, session := range sessions[offset:min(offset+16, len(sessions))] {
						n := revision * uint64(index+1)
						reports = append(reports, IngressUsageReport{
							RouteID: session.setup.RouteID, RouteVersion: session.setup.RouteVersion,
							BucketStart: bucketStart, BucketEnd: bucketStart.Add(time.Minute), ObservedThrough: f.now,
							ReportRevision: revision, ConnectionAttempts: n, PolicyDenials: n,
							HistogramData: (routeusage.Checkpoint{}).MarshalBinary(),
						})
					}
					callCtx, stop := context.WithTimeout(ctx, 20*time.Second)
					err := f.controls[index].ReportIngressUsage(callCtx, ingress.IngressLeaseIdentity, IngressUsageBatch{Reports: reports}, now)
					stop()
					if err != nil {
						fail(fmt.Errorf("usage ingress=%d offset=%d revision=%d: %w", index, offset, revision, err))
						return
					}
					pages[index].Add(1)
					if revision == 1 && offset == 0 {
						backgroundReady <- struct{}{}
					}
				}
				if ctx.Err() != nil {
					return
				}
				usageRevisions[index] = revision
				if recovered.Load() == int64(len(affected)) {
					return
				}
			}
		})
	}
	workDone := make(chan struct{})
	workers.Go(func() { work.Wait(); close(workDone) })
	for index, ingress := range ingresses {
		workers.Go(func() {
			if err := observeRecoveryLoad(t, ctx, f.controls[index], ingress.IngressLeaseIdentity, initial, failed.RelayID, now, workDone, backgroundReady); err != nil {
				fail(fmt.Errorf("snapshot/renewal ingress=%d: %w", index, err))
			}
		})
	}
	// Require successful background work after the failure before releasing the
	// recovery workflows, rather than counting goroutine starts as progress.
	for range 3 + len(ingresses) {
		select {
		case <-backgroundReady:
		case <-ctx.Done():
			workers.Wait()
			t.Fatalf("background startup: %v (context: %v)", firstErr, ctx.Err())
		}
	}
	registration := relayLifecycleRegistration(failed.RelayServiceID)
	registration.RelayID, registration.RelayRunID = failed.RelayID, failed.RelayRunID+"-restarted"
	registration.ConnectionCapacity = uint64(max(4096, f.routes))
	callCtx, stop = context.WithTimeout(ctx, 20*time.Second)
	restarted, err = f.controls[1].RegisterRelay(callCtx, registration, now, time.Hour)
	stop()
	if err != nil || restarted.RelayID != failed.RelayID || restarted.RelayRunID != registration.RelayRunID ||
		restarted.RelayLeaseRevision <= failed.RelayLeaseRevision || restarted.Draining || !restarted.LeaseExpiresAt.After(now) {
		t.Fatalf("register new relay run: %v", err)
	}
	callCtx, stop = context.WithTimeout(ctx, 20*time.Second)
	_, err = f.controls[0].RenewRelay(callCtx, RelayRenewal{RelayLeaseIdentity: failed.RelayLeaseIdentity}, now, time.Hour)
	stop()
	if !errors.Is(err, ErrRelayLeaseStale) {
		t.Fatalf("old relay run renewal: got %v, want stale lease", err)
	}
	callCtx, stop = context.WithTimeout(ctx, 20*time.Second)
	renewed, err := f.controls[1].RenewRelay(callCtx, RelayRenewal{RelayLeaseIdentity: restarted.RelayLeaseIdentity}, now, time.Hour)
	stop()
	if err != nil || renewed.RelayLeaseIdentity != restarted.RelayLeaseIdentity || !renewed.LeaseExpiresAt.After(now) {
		t.Fatalf("new relay run renewal: %v", err)
	}
	t.Logf("relay_restarted_elapsed=%s healthy_heartbeats=%d usage_pages=%d+%d", time.Since(started), heartbeats.Load(), pages[0].Load(), pages[1].Load())
	close(restartReady)
	workers.Wait()
	if firstErr != nil {
		t.Fatal(firstErr)
	}
	if ctx.Err() != nil || recovered.Load() != int64(len(affected)) || healthyRoutes.Load() != int64(len(unaffected)) {
		t.Fatalf("incomplete recovery workload: %v", ctx.Err())
	}
	for index, revision := range usageRevisions {
		if revision == 0 || pages[index].Load() != int64(revision)*int64((f.routes+15)/16) {
			t.Fatalf("incomplete usage stream ingress=%d", index)
		}
	}

	// Verification uses the undelayed setup pool. Walk the bounded event history
	// once against one final snapshot to check every intermediate survivor
	// projection; never take a full snapshot for each small delta page.
	verificationStarted := time.Now()
	verifyAt := now.Add(time.Since(started))
	var events, degraded, verified int
	defer func() {
		t.Logf("verified_routing_events=%d degraded_routes=%d/%d final_routes=%d/%d verification_elapsed=%s", events, degraded, len(affected), verified, f.routes, time.Since(verificationStarted))
	}()
	callCtx, stop = context.WithTimeout(ctx, 20*time.Second)
	final, err := f.database.ReadIngressRoutingTableSnapshot(callCtx, ingresses[0].IngressLeaseIdentity, verifyAt)
	stop()
	if err != nil || len(final.Routes) != f.routes {
		t.Fatalf("final snapshot: routes=%d want=%d: %v", len(final.Routes), f.routes, err)
	}
	cursor := initial.RoutingTableRevision
	sawDegraded := make(map[string]bool, len(affected))
	for cursor < final.RoutingTableRevision {
		callCtx, stop = context.WithTimeout(ctx, 20*time.Second)
		page, err := f.database.ReadIngressRoutingTableEvents(callCtx, ingresses[0].IngressLeaseIdentity, cursor, MaximumIngressRoutingTablePageSize, verifyAt)
		stop()
		if err != nil || page.ResnapshotRequired || page.ThroughRevision != final.RoutingTableRevision || len(page.Events) == 0 {
			t.Fatalf("recovery events after=%d: %v", cursor, err)
		}
		for _, event := range page.Events {
			index, ok := byID[event.RouteID]
			if !ok || event.RoutingTableRevision != cursor+1 || event.EntryRevision != entries[event.RouteID]+1 {
				t.Fatalf("missing or unordered recovery event after=%d route=%s", cursor, event.RouteID)
			}
			if err := checkRecoveryLoadProjection(event, sessions[index], current[index], restarted, verifyAt, false); err != nil {
				t.Fatal(err)
			}
			if len(event.Projection.PublisherConnections) == 1 && !sawDegraded[event.RouteID] {
				sawDegraded[event.RouteID] = true
				degraded++
			}
			cursor, entries[event.RouteID] = event.RoutingTableRevision, event.EntryRevision
			events++
		}
		if page.NextRevision != cursor || page.More != (cursor < final.RoutingTableRevision) {
			t.Fatal("inconsistent recovery event cursor")
		}
	}
	if degraded != len(affected) {
		t.Fatalf("missing intermediate survivor projections: got=%d want=%d", degraded, len(affected))
	}
	seen := make(map[string]bool, f.routes)
	for _, event := range final.Routes {
		index, ok := byID[event.RouteID]
		if !ok || seen[event.RouteID] || event.EntryRevision != entries[event.RouteID] {
			t.Fatalf("unexpected final snapshot route=%s", event.RouteID)
		}
		if err := checkRecoveryLoadProjection(event, sessions[index], current[index], restarted, verifyAt, true); err != nil {
			t.Fatal(err)
		}
		seen[event.RouteID] = true
		verified++
	}
	// Check committed usage per route/session, not merely successful calls or a
	// global total. Both serial streams finish complete cumulative revisions.
	units := usageRevisions[0] + 2*usageRevisions[1]
	callCtx, stop = context.WithTimeout(ctx, 20*time.Second)
	defer stop()
	rows, err := f.database.pool.Query(callCtx, `
		SELECT b.route_id, b.route_version, s.id,
			(b.bucket_start = $1 AND b.bucket_end = $2 AND b.observed_through = $3
			 AND b.connection_attempts = $4 AND b.policy_denials = $4 AND s.policy_denials = $4) IS TRUE
		FROM control.route_usage_buckets b
		JOIN control.route_sessions s ON s.route_id = b.route_id AND s.route_version = b.route_version`,
		bucketStart, bucketStart.Add(time.Minute), f.now, int64(units))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var routeID, sessionID string
		var version uint64
		var matches bool
		if err := rows.Scan(&routeID, &version, &sessionID, &matches); err != nil {
			t.Fatal(err)
		}
		index, ok := byID[routeID]
		if !ok || !matches || version != sessions[index].setup.RouteVersion || sessionID != sessions[index].setup.RouteSessionID {
			t.Fatalf("unexpected recovery usage bucket route=%s", routeID)
		}
		delete(byID, routeID)
	}
	if err := rows.Err(); err != nil || len(byID) != 0 || ctx.Err() != nil {
		t.Fatalf("recovery usage verification: missing=%d err=%v context=%v", len(byID), err, ctx.Err())
	}
	assertAssignmentTotals(t, f.database.pool, int64(f.routes)*2)
}

// Readers use immutable initial projections while recovery workers change their
// assignments. Check identity, monotonic revisions, and surviving connections
// live; the post-join event walk verifies every final replacement and stale run.
func observeRecoveryLoad(t *testing.T, ctx context.Context, control *Database, ingress IngressLeaseIdentity, initial IngressRoutingTableSnapshot, failedRelayID string, now time.Time, workDone <-chan struct{}, backgroundReady chan<- struct{}) error {
	expected := make(map[string]IngressRoutingTableEvent, len(initial.Routes))
	entries := make(map[string]uint64, len(initial.Routes))
	for _, event := range initial.Routes {
		expected[event.RouteID], entries[event.RouteID] = event, event.EntryRevision
	}
	cursor := initial.RoutingTableRevision
	var snapshots, renewals int
	started := time.Now()
	defer func() {
		t.Logf("ingress=%s snapshots=%d renewals=%d cursor=%d elapsed=%s", ingress.IngressID, snapshots, renewals, cursor, time.Since(started))
	}()
	for ctx.Err() == nil {
		finished := false
		select {
		case <-workDone:
			finished = true
		default:
		}
		callCtx, stop := context.WithTimeout(ctx, 20*time.Second)
		snapshot, err := control.ReadIngressRoutingTableSnapshot(callCtx, ingress, now)
		stop()
		if err != nil {
			return fmt.Errorf("snapshot: %w", err)
		}
		if snapshot.RoutingTableRevision < cursor || len(snapshot.Routes) != len(expected) {
			return fmt.Errorf("snapshot routes=%d want=%d revision=%d previous=%d", len(snapshot.Routes), len(expected), snapshot.RoutingTableRevision, cursor)
		}
		seen := make(map[string]bool, len(expected))
		for _, event := range snapshot.Routes {
			before, ok := expected[event.RouteID]
			if !ok || seen[event.RouteID] || event.Kind != IngressRouteUpsert || event.RouteVersion != before.RouteVersion ||
				event.CanonicalHostname != before.CanonicalHostname || event.Projection.RouteSessionID != before.Projection.RouteSessionID ||
				event.EntryRevision < entries[event.RouteID] || event.RoutingTableRevision > snapshot.RoutingTableRevision ||
				!event.Projection.RouteExpiresAt.After(now) {
				return fmt.Errorf("snapshot lost current session or revision route=%s", event.RouteID)
			}
			connections := event.Projection.PublisherConnections
			if len(connections) < 1 || len(connections) > 2 {
				return fmt.Errorf("snapshot connection count=%d route=%s", len(connections), event.RouteID)
			}
			var slots [2]bool
			for _, connection := range connections {
				slot := connection.ConnectionSlot
				if slot < 0 || slot >= len(slots) || slots[slot] {
					return fmt.Errorf("snapshot invalid or duplicate slot=%d route=%s", slot, event.RouteID)
				}
				slots[slot] = true
			}
			for _, connection := range before.Projection.PublisherConnections {
				if connection.RelayID != failedRelayID && !slices.Contains(connections, connection) {
					return fmt.Errorf("snapshot lost surviving connection route=%s slot=%d", event.RouteID, connection.ConnectionSlot)
				}
			}
			seen[event.RouteID], entries[event.RouteID] = true, event.EntryRevision
		}
		cursor = snapshot.RoutingTableRevision
		snapshots++
		callCtx, stop = context.WithTimeout(ctx, 20*time.Second)
		lease, err := control.RenewIngress(callCtx, IngressRenewal{IngressLeaseIdentity: ingress, RoutingTableRevision: cursor}, now, time.Hour)
		stop()
		if err != nil {
			return fmt.Errorf("renew: %w", err)
		}
		if lease.IngressLeaseIdentity != ingress || !lease.LeaseExpiresAt.After(now) {
			return errors.New("renew changed ingress identity or expired its lease")
		}
		renewals++
		if snapshots == 1 {
			backgroundReady <- struct{}{}
		}
		if finished {
			return nil
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
		case <-workDone:
		case <-timer.C:
		}
		timer.Stop()
	}
	return ctx.Err()
}

func recoverLoadRelaySlot(ctx context.Context, control *Database, session routeSessionFixture, failed, restarted RelayLease, now time.Time) (RouteSessionSetup, error) {
	callCtx, stop := context.WithTimeout(ctx, 20*time.Second)
	setup, err := control.HeartbeatRouteSession(callCtx, session.authentication(), now, time.Hour, time.Hour)
	stop()
	if err != nil {
		return setup, fmt.Errorf("replenish: %w", err)
	}
	if setup.RouteID != session.setup.RouteID || setup.RouteSessionID != session.setup.RouteSessionID ||
		setup.RouteVersion != session.setup.RouteVersion || setup.RouteSessionToken != session.setup.RouteSessionToken ||
		setup.State != RouteSessionReady || setup.ReadyAt == nil || !setup.ReadyAt.Equal(session.now) || setup.ClosedAt != nil || !setup.ExpiresAt.After(now) {
		return setup, errors.New("replenishment changed the ready session")
	}
	for slot, connection := range setup.PublisherConnections {
		previous := session.setup.PublisherConnections[slot]
		if session.leases[previous.RelayServiceID].RelayLeaseIdentity != failed.RelayLeaseIdentity {
			previous.State = PublisherConnectionReady
			if connection != previous {
				return setup, fmt.Errorf("replenishment changed surviving slot=%d", slot)
			}
			continue
		}
		if connection.ConnectionSlot != slot || connection.RouteSessionID != setup.RouteSessionID ||
			connection.RouteID != setup.RouteID || connection.RouteVersion != setup.RouteVersion || connection.RelayServiceID != previous.RelayServiceID ||
			connection.ConnectionAssignmentRevision <= previous.ConnectionAssignmentRevision || connection.PublisherConnectionID == previous.PublisherConnectionID ||
			connection.PublisherConnectionCredential == previous.PublisherConnectionCredential || connection.State != PublisherConnectionAssigned ||
			!connection.PublisherConnectionCredentialExpiresAt.After(now) {
			return setup, fmt.Errorf("missing fresh replacement slot=%d", slot)
		}
		digest, err := credentials.ParsePublisherConnectionCredential(connection.PublisherConnectionCredential)
		if err != nil {
			return setup, err
		}
		claim := PublisherConnectionClaimRequest{ConnectionAssignmentIdentity: connection.ConnectionAssignmentIdentity,
			RelayLeaseIdentity: restarted.RelayLeaseIdentity, ClaimID: "recovery", CredentialDigest: [32]byte(digest)}
		stale := claim
		stale.RelayLeaseIdentity = failed.RelayLeaseIdentity
		callCtx, stop = context.WithTimeout(ctx, 20*time.Second)
		_, err = control.ClaimPublisherConnection(callCtx, stale, now)
		stop()
		if !errors.Is(err, ErrRelayLeaseStale) {
			return setup, fmt.Errorf("old run claim: got %v, want stale lease", err)
		}
		oldDigest, err := credentials.ParsePublisherConnectionCredential(previous.PublisherConnectionCredential)
		if err != nil {
			return setup, err
		}
		stale = claim
		stale.ConnectionAssignmentIdentity, stale.CredentialDigest = previous.ConnectionAssignmentIdentity, [32]byte(oldDigest)
		callCtx, stop = context.WithTimeout(ctx, 20*time.Second)
		_, err = control.ClaimPublisherConnection(callCtx, stale, now)
		stop()
		if !errors.Is(err, ErrPublisherConnectionUnavailable) {
			return setup, fmt.Errorf("old assignment claim: got %v, want unavailable connection", err)
		}
		callCtx, stop = context.WithTimeout(ctx, 20*time.Second)
		claimed, err := control.ClaimPublisherConnection(callCtx, claim, now)
		stop()
		if err != nil || claimed.ConnectionAssignmentIdentity != claim.ConnectionAssignmentIdentity ||
			claimed.RelayLeaseIdentity != claim.RelayLeaseIdentity || claimed.State != PublisherConnectionConnected {
			return setup, fmt.Errorf("replacement claim identity/state: %v", err)
		}
		callCtx, stop = context.WithTimeout(ctx, 20*time.Second)
		ready, err := control.MarkPublisherConnectionReady(callCtx, claim, now)
		stop()
		if err != nil || ready.ConnectionAssignmentIdentity != claim.ConnectionAssignmentIdentity ||
			ready.RelayLeaseIdentity != claim.RelayLeaseIdentity || ready.State != PublisherConnectionReady || ready.ReadyAt == nil {
			return setup, fmt.Errorf("replacement readiness identity/state: %v", err)
		}
	}
	return setup, nil
}

func checkRecoveryLoadProjection(event IngressRoutingTableEvent, session routeSessionFixture, current RouteSessionSetup, restarted RelayLease, now time.Time, complete bool) error {
	if event.Kind != IngressRouteUpsert || event.RouteID != session.setup.RouteID || event.RouteVersion != session.setup.RouteVersion ||
		event.CanonicalHostname != session.request.CertificateIdentifiers[0] || event.Projection.RouteSessionID != session.setup.RouteSessionID ||
		!event.Projection.RouteExpiresAt.After(now) {
		return fmt.Errorf("projection lost ready session route=%s", event.RouteID)
	}
	connections := event.Projection.PublisherConnections
	if len(connections) < 1 || len(connections) > 2 || (complete && len(connections) != 2) {
		return fmt.Errorf("projection connection count=%d route=%s complete=%t", len(connections), event.RouteID, complete)
	}
	var seen [2]bool
	for _, connection := range connections {
		slot := connection.ConnectionSlot
		if slot < 0 || slot >= len(seen) || seen[slot] {
			return fmt.Errorf("duplicate or invalid projection slot=%d route=%s", slot, event.RouteID)
		}
		seen[slot] = true
		expected := current.PublisherConnections[slot]
		lease := session.leases[expected.RelayServiceID]
		if lease.RelayID == restarted.RelayID {
			lease = restarted
		}
		if connection.PublisherConnectionID != expected.PublisherConnectionID || connection.ConnectionAssignmentRevision != expected.ConnectionAssignmentRevision ||
			connection.RelayServiceID != expected.RelayServiceID || connection.RelayID != lease.RelayID || connection.RelayRunID != lease.RelayRunID ||
			connection.RelayLeaseRevision != lease.RelayLeaseRevision || !connection.LeaseExpiresAt.After(now) {
			return fmt.Errorf("projection lost current assignment/relay run route=%s slot=%d", event.RouteID, slot)
		}
	}
	for slot, connection := range session.setup.PublisherConnections {
		if session.leases[connection.RelayServiceID].RelayID != restarted.RelayID && !seen[slot] {
			return fmt.Errorf("projection lost surviving connection route=%s slot=%d", event.RouteID, slot)
		}
	}
	return nil
}
