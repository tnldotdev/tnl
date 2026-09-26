package controlstate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/publicurlusage"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

const (
	cadenceHeartbeatInterval = 15 * time.Second
	cadenceHeartbeatTimeout  = 10 * time.Second
	cadencePublisherLease    = 45 * time.Second
	cadenceCredentialLife    = 2 * time.Minute
	cadenceProcessLease      = 30 * time.Second
	cadenceRenewalInterval   = 10 * time.Second
	cadenceControlTimeout    = 30 * time.Second
)

// RunCadenceLoad is bridged from the external test package so it can use the
// production ingress API adapter without a controlstate import cycle. This is
// still a database workload: publisher transports and visitor sockets are absent.
func RunCadenceLoad(t *testing.T, newClient func(*Database, func() time.Time, <-chan struct{}, bool) (ingress.ControlClient, error)) {
	t.Helper()
	duration := *loadDuration
	if duration == 0 {
		t.Skip("select RUN='^TestLoadCadence$' DURATION=10m for the paced workload")
	}
	if duration < 2*time.Minute || duration > 10*time.Minute || duration%time.Minute != 0 {
		t.Fatal("cadence duration must be whole minutes between 2m and 10m")
	}
	retention := *loadRetention
	if retention != 0 && (retention < 30*time.Second || retention >= duration/2) {
		t.Fatal("test retention must be at least 30s and shorter than half the cadence duration")
	}
	f := newControlLoadFixture(t)
	if f.routes < 2 {
		t.Fatal("cadence recovery requires at least two routes")
	}
	setupStarted := time.Now()
	var leases []RelayLease
	for service, choices := range f.leases {
		for index, lease := range choices {
			registration := relayLifecycleRegistration(service)
			registration.RelayID, registration.RelayRunID = lease.RelayID, lease.RelayRunID
			registration.ConnectionCapacity = uint64(max(4096, f.routes))
			lease, err := f.database.RegisterRelay(t.Context(), registration, f.now, cadenceProcessLease)
			if err != nil {
				t.Fatal(err)
			}
			f.leases[service][index] = lease
			leases = append(leases, lease)
		}
	}
	sort.Slice(leases, func(i, j int) bool { return leases[i].RelayID < leases[j].RelayID })
	sessions := readyLoadSessions(t, f, cadencePublisherLease, cadenceCredentialLife)
	seedLoadRoutingHistory(t, f, 1, f.history)
	failed := sessions[0].leases[sessions[0].setup.PublisherConnections[0].RelayServiceID]
	var leaseMu sync.RWMutex
	current := make([]PublishRunSetup, f.routes)
	for index, session := range sessions {
		current[index] = session.setup
		for slot := range current[index].PublisherConnections {
			current[index].PublisherConnections[slot].State = PublisherConnectionReady
		}
	}
	// Setup uses one fixed logical instant. From here the clock runs at wall
	// speed; every caller, session, process lease, and routing entry shares it.
	clockStarted := time.Now()
	now := func() time.Time { return f.now.Add(time.Since(clockStarted)) }
	ctx, cancel := context.WithTimeout(t.Context(), duration+time.Minute)
	defer cancel()
	actors := newIntegrationWorkers(t, cancel)
	defer actors.stop()
	var first sync.Once
	var firstErr error
	fail := func(err error) {
		first.Do(func() {
			firstErr = err
			t.Logf("first_failure_since_clock_start=%s error=%v", time.Since(clockStarted), err)
			// Collect the production's bounded, sanitized diagnostics before
			// cancellation and cleanup change the database wait graph.
			diagnostic, _ := f.controls[0].Diagnostics(t.Context())
			if data, marshalErr := json.Marshal(diagnostic); marshalErr == nil {
				t.Logf("failure_database_diagnostic=%s", data)
			}
			cancel()
		})
	}
	resnapshot := make(chan struct{})
	var controllers [2]*ingress.Controller
	var ingressMetrics [2]*observability.Metrics
	for index := range controllers {
		client, err := newClient(f.controls[index], now, resnapshot, retention != 0)
		if err != nil {
			t.Fatal(err)
		}
		metrics := observability.New("ingress")
		controller, err := ingress.NewController(ingress.ControllerConfig{
			Client: client, RoutingTable: new(ingress.RoutingTable),
			Registration:    ingressv1.IngressRegistration{IngressId: fmt.Sprintf("cadence-ingress-%d", index), IngressRunId: "cadence-run", ProtocolVersion: 1, ConnectionCapacity: int64(f.routes)},
			RenewalInterval: cadenceRenewalInterval, RetryInterval: time.Second, RoutingWait: 25 * time.Second,
			Now: now, Observer: metrics, Report: func(err error) { fail(fmt.Errorf("ingress control: %w", err)) },
		})
		if err != nil {
			t.Fatal(err)
		}
		controllers[index], ingressMetrics[index] = controller, metrics
		metrics.RegisterIngressRouting(controller.RoutingStatus)
		actors.Go(func() {
			if err := controller.Run(ctx); err != nil && ctx.Err() == nil {
				fail(err)
			}
		})
	}
	for !controllers[0].Ready(now()) || !controllers[1].Ready(now()) {
		if err := waitCadence(ctx, time.Now().Add(10*time.Millisecond)); err != nil {
			actors.Wait()
			t.Fatalf("initial ingress readiness: %v", firstErr)
		}
	}
	f.startMetrics(t)
	var ingressBefore [2][]*dto.MetricFamily
	for index, metrics := range ingressMetrics {
		gathered, err := metrics.Gather()
		if err != nil {
			t.Fatal(err)
		}
		ingressBefore[index] = gathered
	}
	var databaseBytesBefore int64
	var walStart string
	if err := f.database.pool.QueryRow(ctx, `SELECT pg_database_size(current_database()), pg_current_wal_lsn()::text`).Scan(&databaseBytesBefore, &walStart); err != nil {
		t.Fatal(err)
	}
	t.Logf("cadence_setup_elapsed=%s routes=%d heartbeat_interval=%s publisher_lease=%s process_lease=%s renewal_interval=%s duration=%s usage=one_connection_per_route_per_minute", time.Since(setupStarted), f.routes, cadenceHeartbeatInterval, cadencePublisherLease, cadenceProcessLease, cadenceRenewalInterval, duration)
	started := time.Now()
	var scheduled, completed, renewed, pages, replays, late, repaired atomic.Int64
	var maximumQueueDelay atomic.Int64
	var pruned, scanned atomic.Int64
	var retentionFloor atomic.Uint64
	var expiredAt atomic.Int64
	pending := make([]atomic.Bool, f.routes)
	wasRepaired := make([]bool, f.routes) // One pending heartbeat per route.
	affected := int64(0)
	for _, session := range sessions {
		if session.leases[failed.RelayServiceID].RelayID == failed.RelayID {
			affected++
		}
	}
	defer func() {
		if retention > 0 {
			t.Logf("retention=%s floor=%d scanned=%d deleted=%d", retention, retentionFloor.Load(), scanned.Load(), pruned.Load())
		}
		t.Logf("cadence_elapsed=%s scheduled=%d completed=%d expected=%d pending=%d late=%d max_scheduler_queue_delay=%s lease_renewals=%d usage_pages=%d replays=%d recovered=%d/%d", time.Since(started), scheduled.Load(), completed.Load(), int64(f.routes)*int64(duration/cadenceHeartbeatInterval), scheduled.Load()-completed.Load(), late.Load(), time.Duration(maximumQueueDelay.Load()), renewed.Load(), pages.Load(), replays.Load(), repaired.Load(), affected)
		f.logStats(t)
		for index, metrics := range ingressMetrics {
			families, err := metrics.Gather()
			if err != nil {
				t.Error(err)
				continue
			}
			summaries, err := observability.DurationSummaries(ingressBefore[index], families)
			if err != nil {
				t.Error(err)
				continue
			}
			for _, summary := range summaries {
				if summary.Count != 0 {
					t.Logf("ingress=%d %s labels=%v calls=%d mean_seconds=%g p95_seconds=%s", index, summary.Name, summary.Labels, summary.Count, summary.MeanSeconds, loadPercentile(summary.P95Seconds))
				}
			}
		}
		after, err := f.metrics[0].Gather()
		if err != nil {
			t.Error(err)
			return
		}
		for _, name := range []string{"process_cpu_seconds_total", "process_resident_memory_bytes", "go_memstats_heap_inuse_bytes", "go_goroutines"} {
			beforeValue, beforeOK := cadenceMetricValue(f.before[0], name)
			afterValue, afterOK := cadenceMetricValue(after, name)
			t.Logf("test_process %s before=%g after=%g available=%t", name, beforeValue, afterValue, beforeOK && afterOK)
		}
	}()
	// Join before the deferred metric snapshot, even when a deadline fails.
	defer actors.stop()
	type job struct {
		index int
		due   time.Time
	}
	jobs := make(chan job, f.routes)
	var work sync.WaitGroup
	work.Add(64 + 1 + len(leases) + len(controllers))
	if retention > 0 {
		work.Add(len(f.controls))
		for _, control := range f.controls {
			actors.Go(func() {
				defer work.Done()
				var cursor uint64
				var nextFloorCheck time.Time
				for time.Since(started) < duration && ctx.Err() == nil {
					at := now()
					if !at.Before(nextFloorCheck) {
						callCtx, stop := context.WithTimeout(ctx, 2*time.Second)
						floor, err := control.AdvanceIngressRoutingRetention(callCtx, at.Add(-retention))
						stop()
						if err != nil {
							if ctx.Err() == nil {
								fail(err)
							}
							return
						}
						for previous := retentionFloor.Load(); floor > previous; previous = retentionFloor.Load() {
							if retentionFloor.CompareAndSwap(previous, floor) {
								break
							}
						}
						nextFloorCheck = at.Add(30 * time.Second)
					}
					callCtx, stop := context.WithTimeout(ctx, 2*time.Second)
					batch, err := control.PruneIngressRoutingHistory(callCtx, cursor)
					stop()
					if err != nil {
						if ctx.Err() == nil {
							fail(err)
						}
						return
					}
					scanned.Add(batch.Scanned)
					pruned.Add(batch.Deleted)
					delay := 30 * time.Second
					if !batch.Busy {
						cursor = batch.NextRevision
						if batch.More {
							delay = 100 * time.Millisecond
						} else {
							cursor = 0
						}
					}
					if waitCadence(ctx, minTime(started.Add(duration), time.Now().Add(delay))) != nil {
						return
					}
				}
			})
		}
	}
	for worker := range 64 {
		actors.Go(func() {
			defer work.Done()
			for item := range jobs {
				if ctx.Err() != nil {
					return
				}
				queueDelay := time.Since(item.due)
				for previous := maximumQueueDelay.Load(); int64(queueDelay) > previous; previous = maximumQueueDelay.Load() {
					if maximumQueueDelay.CompareAndSwap(previous, int64(queueDelay)) {
						break
					}
				}
				deadline := item.due.Add(cadenceHeartbeatTimeout)
				if !time.Now().Before(deadline) {
					late.Add(1)
					fail(fmt.Errorf("heartbeat scheduler deadline: route=%d queue_delay=%s", item.index, queueDelay))
					return
				}
				callCtx, stop := context.WithDeadline(ctx, deadline)
				session := sessions[item.index]
				setup, err := f.controls[worker%2].HeartbeatPublishRun(callCtx, session.authentication(), now(), cadencePublisherLease, cadenceCredentialLife)
				stop()
				if err == nil && (setup.PublishRunID != session.setup.PublishRunID || setup.PublishRunNumber != session.setup.PublishRunNumber || setup.State != PublishRunReady || !setup.ExpiresAt.After(now())) {
					err = errors.New("heartbeat lost a live session")
				}
				changed := false
				for slot, connection := range setup.PublisherConnections {
					if err != nil {
						break
					}
					previous := current[item.index].PublisherConnections[slot]
					if connection.State == PublisherConnectionReady {
						if connection.ConnectionAssignmentIdentity != previous.ConnectionAssignmentIdentity {
							err = errors.New("ready assignment changed without publisher claim")
						}
						continue
					}
					if connection.State != PublisherConnectionAssigned || session.leases[connection.RelayServiceID].RelayID != failed.RelayID || connection.ConnectionAssignmentRevision <= previous.ConnectionAssignmentRevision || connection.PublisherConnectionID == previous.PublisherConnectionID {
						err = errors.New("unexpected replacement assignment")
						break
					}
					leaseMu.RLock()
					var selected RelayLease
					for _, lease := range leases {
						if lease.RelayServiceID == connection.RelayServiceID && lease.LeaseExpiresAt.After(now()) && !lease.Draining {
							selected = lease
							break
						}
					}
					leaseMu.RUnlock()
					if selected.RelayID == "" {
						err = errors.New("no live relay for replacement")
						break
					}
					digest, parseErr := credentials.ParsePublisherConnectionCredential(connection.PublisherConnectionCredential)
					if parseErr != nil {
						err = parseErr
						break
					}
					claim := PublisherConnectionClaimRequest{ConnectionAssignmentIdentity: connection.ConnectionAssignmentIdentity, RelayLeaseIdentity: selected.RelayLeaseIdentity, ClaimID: "cadence", CredentialDigest: [32]byte(digest)}
					callCtx, stop = context.WithTimeout(ctx, cadenceControlTimeout)
					_, err = f.controls[worker%2].ClaimPublisherConnection(callCtx, claim, now())
					stop()
					if err != nil {
						break
					}
					callCtx, stop = context.WithTimeout(ctx, cadenceControlTimeout)
					_, err = f.controls[worker%2].MarkPublisherConnectionReady(callCtx, claim, now())
					stop()
					if err != nil {
						break
					}
					setup.PublisherConnections[slot].State = PublisherConnectionReady
					changed = true
				}
				if err != nil {
					if errors.Is(err, context.DeadlineExceeded) {
						late.Add(1)
					}
					fail(fmt.Errorf("heartbeat/replacement route=%d scheduled_elapsed=%s: %w", item.index, item.due.Sub(started), err))
					return
				}
				current[item.index] = setup
				if changed && !wasRepaired[item.index] {
					wasRepaired[item.index] = true
					if repaired.Add(1) == affected {
						t.Logf("all_slots_ready_elapsed=%s recovery_since_lease_expiry=%s", time.Since(started), time.Since(started)-time.Duration(expiredAt.Load()))
					}
				}
				completed.Add(1)
				pending[item.index].Store(false)
			}
		})
	}
	actors.Go(func() {
		defer work.Done()
		defer close(jobs)
		for round := time.Duration(0); round < duration; round += cadenceHeartbeatInterval {
			for index := range f.routes {
				due := started.Add(round + time.Duration(int64(cadenceHeartbeatInterval)*int64(index)/int64(f.routes)))
				if waitCadence(ctx, due) != nil {
					return
				}
				scheduled.Add(1)
				if !pending[index].CompareAndSwap(false, true) {
					late.Add(1)
					fail(fmt.Errorf("heartbeat still pending at next schedule: route=%d", index))
					return
				}
				select {
				case jobs <- job{index, due}:
				case <-ctx.Done():
					return
				default:
					late.Add(1)
					fail(errors.New("bounded heartbeat queue filled"))
					return
				}
			}
		}
	})
	for index := range leases {
		actors.Go(func() {
			defer work.Done()
			restarted := false
			for tick := cadenceRenewalInterval; tick <= duration; tick += cadenceRenewalInterval {
				if waitCadence(ctx, started.Add(tick)) != nil {
					return
				}
				leaseMu.RLock()
				lease := leases[index]
				leaseMu.RUnlock()
				if lease.RelayID == failed.RelayID && !restarted && tick >= duration/2 {
					expiration := clockStarted.Add(lease.LeaseExpiresAt.Sub(f.now))
					expiredAt.Store(int64(expiration.Sub(started)))
					t.Logf("stop_relay_renewals_elapsed=%s lease_expiry_elapsed=%s", time.Since(started), expiration.Sub(started))
					if waitCadence(ctx, expiration.Add(time.Millisecond)) != nil {
						return
					}
					registration := relayLifecycleRegistration(lease.RelayServiceID)
					registration.RelayID, registration.RelayRunID = lease.RelayID, lease.RelayRunID+"-cadence-restart"
					registration.ConnectionCapacity = uint64(max(4096, f.routes))
					callCtx, stop := context.WithTimeout(ctx, cadenceControlTimeout)
					replacement, err := f.controls[index%2].RegisterRelay(callCtx, registration, now(), cadenceProcessLease)
					stop()
					if err == nil && (replacement.RelayID != lease.RelayID || replacement.RelayRunID != registration.RelayRunID || replacement.RelayLeaseRevision <= lease.RelayLeaseRevision || !replacement.LeaseExpiresAt.After(now())) {
						err = errors.New("invalid restarted relay lease")
					}
					if err != nil {
						fail(fmt.Errorf("restart relay %s: %w", lease.RelayID, err))
						return
					}
					leaseMu.Lock()
					leases[index] = replacement
					leaseMu.Unlock()
					restarted = true
					close(resnapshot)
					t.Logf("relay_restarted_elapsed=%s", time.Since(started))
					for started.Add(tick + cadenceRenewalInterval).Before(time.Now()) {
						tick += cadenceRenewalInterval
					}
					continue
				}
				deadline := clockStarted.Add(lease.LeaseExpiresAt.Sub(f.now))
				callCtx, stop := context.WithDeadline(ctx, deadline)
				updated, err := f.controls[index%2].RenewRelay(callCtx, RelayRenewal{RelayLeaseIdentity: lease.RelayLeaseIdentity}, now(), cadenceProcessLease)
				stop()
				if err == nil && (updated.RelayLeaseIdentity != lease.RelayLeaseIdentity || !updated.LeaseExpiresAt.After(now())) {
					err = errors.New("renewal changed relay identity or expired its lease")
				}
				if err != nil {
					fail(fmt.Errorf("renew relay %s: %w", lease.RelayID, err))
					return
				}
				leaseMu.Lock()
				leases[index] = updated
				leaseMu.Unlock()
				renewed.Add(1)
			}
		})
	}
	for ingressIndex, controller := range controllers {
		actors.Go(func() {
			defer work.Done()
			for tick := 1; time.Duration(tick)*10*time.Second <= duration; tick++ {
				due := started.Add(time.Duration(tick) * 10 * time.Second)
				if waitCadence(ctx, due) != nil {
					return
				}
				// One accounted connection per route per minute, divided between
				// two ingresses and six ten-second reporting checkpoints.
				at := f.now.Add(due.Sub(clockStarted)).Add(-time.Microsecond)
				bucket := at.Truncate(time.Minute)
				var reports []IngressUsageReport
				for index := ingressIndex; index < f.routes; index += 2 {
					if (index/2)%6 != (tick-1)%6 {
						continue
					}
					session := sessions[index]
					reports = append(reports, IngressUsageReport{PublicURLID: session.setup.PublicURLID, PublishRunNumber: session.setup.PublishRunNumber,
						BucketStart: bucket, BucketEnd: bucket.Add(time.Minute), ObservedThrough: at, ReportRevision: 1,
						ConnectionAttempts: 1, SuccessfulStreams: 1, IngressBytes: 100, EgressBytes: 200,
						HistogramData: (publicurlusage.Checkpoint{}).MarshalBinary()})
				}
				identity := controller.Lease()
				lease := IngressLeaseIdentity{IngressID: identity.IngressId, IngressRunID: identity.IngressRunId, IngressLeaseRevision: uint64(identity.IngressLeaseRevision)}
				for offset := 0; offset < max(1, len(reports)); offset += 16 {
					batch := IngressUsageBatch{Reports: reports[offset:min(offset+16, len(reports))]}
					if offset+16 >= len(reports) {
						batch.ObservedThrough = &at
					}
					attempts := 1
					if offset == 0 && len(reports) > 0 {
						attempts = 2
					}
					for attempt := range attempts {
						callCtx, stop := context.WithDeadline(ctx, due.Add(10*time.Second))
						err := f.controls[ingressIndex].ReportIngressUsage(callCtx, lease, batch, now())
						stop()
						if err != nil {
							fail(fmt.Errorf("usage checkpoint=%d ingress=%d offset=%d: %w", tick, ingressIndex, offset, err))
							return
						}
						pages.Add(1)
						if attempt != 0 {
							replays.Add(1)
						}
					}
				}
			}
		})
	}
	workDone := make(chan struct{})
	actors.Go(func() { work.Wait(); close(workDone) })
	progress := time.NewTicker(30 * time.Second)
	defer progress.Stop()
waiting:
	for {
		select {
		case <-workDone:
			break waiting
		case <-ctx.Done():
			break waiting
		case <-progress.C:
			t.Logf("cadence_progress elapsed=%s scheduled=%d completed=%d pending=%d recovered=%d/%d", time.Since(started), scheduled.Load(), completed.Load(), scheduled.Load()-completed.Load(), repaired.Load(), affected)
			for index, controller := range controllers {
				status := controller.RoutingStatus()
				t.Logf("ingress=%d applied=%d known_backlog=%d last_check_age=%s", index, status.AppliedRevision, status.LatestRevision-status.AppliedRevision, now().Sub(status.LastSuccessfulCheck))
			}
			if retention > 0 {
				var relationBytes, deadTuples, vacuums int64
				if err := f.database.pool.QueryRow(ctx, `SELECT pg_total_relation_size('control.ingress_routing_table_events'), n_dead_tup, autovacuum_count FROM pg_stat_user_tables WHERE schemaname = 'control' AND relname = 'ingress_routing_table_events'`).Scan(&relationBytes, &deadTuples, &vacuums); err != nil {
					fail(err)
				} else {
					t.Logf("retention_progress floor=%d deleted=%d approximate_rows=%d relation_bytes=%d estimated_dead_tuples=%d autovacuums=%d", retentionFloor.Load(), pruned.Load(), int64(f.routes)*int64(f.history)+completed.Load()+repaired.Load()-pruned.Load(), relationBytes, deadTuples, vacuums)
				}
			}
		}
	}
	if ctx.Err() != nil {
		actors.stop()
		t.Fatalf("cadence failed: %v (context: %v)", firstErr, ctx.Err())
	}
	if completed.Load() != int64(f.routes)*int64(duration/cadenceHeartbeatInterval) || repaired.Load() != affected || late.Load() != 0 {
		t.Fatal("incomplete cadence workload")
	}
	verifyCtx, stopVerification := context.WithTimeout(ctx, 10*time.Second)
	defer stopVerification()
	// All publishing and reporting has stopped. Drain routing consumers to a
	// final production snapshot while their normal lease renewals continue.
	identity := controllers[0].Lease()
	final, err := f.database.ReadIngressRoutingTableSnapshot(verifyCtx, IngressLeaseIdentity{IngressID: identity.IngressId, IngressRunID: identity.IngressRunId, IngressLeaseRevision: uint64(identity.IngressLeaseRevision)}, now())
	if err != nil || len(final.Entries) != f.routes {
		t.Fatalf("final snapshot routes=%d want=%d: %v", len(final.Entries), f.routes, err)
	}
	wantRevision := uint64(f.routes)*uint64(f.history) + uint64(completed.Load()) + uint64(repaired.Load())
	if final.RoutingTableRevision != wantRevision {
		t.Fatalf("final revision=%d want=%d", final.RoutingTableRevision, wantRevision)
	}
	if retention > 0 {
		var rows int64
		if err := f.database.pool.QueryRow(verifyCtx, `SELECT count(*) FROM control.ingress_routing_table_events`).Scan(&rows); err != nil || rows != int64(wantRevision)-pruned.Load() || pruned.Load() == 0 || final.RetainedAfterRevision == 0 {
			t.Fatalf("retention rows=%d deleted=%d floor=%d: %v", rows, pruned.Load(), final.RetainedAfterRevision, err)
		}
		t.Logf("retention_verified_rows=%d deleted=%d floor=%d", rows, pruned.Load(), final.RetainedAfterRevision)
	}
	for ingressIndex, controller := range controllers {
		for controller.RoutingStatus().AppliedRevision != int64(final.RoutingTableRevision) {
			if err := waitCadence(verifyCtx, time.Now().Add(10*time.Millisecond)); err != nil {
				t.Fatal(err)
			}
		}
		for index, session := range sessions {
			entry, ok := controller.Lookup(session.request.CertificateIdentifiers[0], now())
			if !ok || entry.PublishRunId != session.setup.PublishRunID || entry.PublishRunNumber != int64(session.setup.PublishRunNumber) || len(entry.PublisherConnections) != 2 {
				t.Fatalf("final routing lost live route=%d", index)
			}
			for _, connection := range entry.PublisherConnections {
				if connection.PublisherConnectionId != current[index].PublisherConnections[connection.ConnectionSlot].PublisherConnectionID {
					t.Fatalf("final routing has stale assignment route=%d", index)
				}
				if connection.RelayId == failed.RelayID && connection.RelayRunId == failed.RelayRunID {
					t.Fatalf("final routing has old relay run route=%d", index)
				}
			}
		}
		status := controller.RoutingStatus()
		if !status.CaughtUp || status.UpdateFailures != 0 || status.Resnapshots != 1 {
			t.Fatalf("ingress=%d did not recover cleanly: %+v", ingressIndex, status)
		}
		t.Logf("ingress=%d final_applied=%d known_backlog=%d last_check_age=%s resnapshots=%d failures=%d", ingressIndex, status.AppliedRevision, status.LatestRevision-status.AppliedRevision, now().Sub(status.LastSuccessfulCheck), status.Resnapshots, status.UpdateFailures)
	}
	expectedUsage := make(map[string]PublishRunSetup, f.routes)
	for _, session := range sessions {
		expectedUsage[session.setup.PublicURLID] = session.setup
	}
	rows, err := f.database.pool.Query(verifyCtx, `
		SELECT b.public_url_id, b.publish_run_number, s.id,
		 (count(*) = $1 AND sum(b.connection_attempts) = $1 AND sum(b.successful_streams) = $1
		  AND sum(b.policy_denials) = 0 AND sum(b.capacity_denials) = 0
		  AND sum(b.visitor_stream_open_failures) = 0 AND sum(b.connection_nanoseconds) = 0
		  AND sum(b.ingress_bytes) = $1 * 100 AND sum(b.egress_bytes) = $1 * 200
		  AND bool_and(s.policy_denials = 0 AND s.closed_at IS NULL AND s.publisher_expires_at > $2)) IS TRUE
		FROM control.public_url_usage_buckets AS b
		LEFT JOIN control.publish_runs AS s USING (public_url_id, publish_run_number)
		GROUP BY b.public_url_id, b.publish_run_number, s.id`, int64(duration/time.Minute), now())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var publicURLID, sessionID string
		var version uint64
		var matches bool
		if err := rows.Scan(&publicURLID, &version, &sessionID, &matches); err != nil {
			t.Fatal(err)
		}
		expected, ok := expectedUsage[publicURLID]
		if !ok || !matches || version != expected.PublishRunNumber || sessionID != expected.PublishRunID {
			t.Fatalf("unexpected usage route=%s version=%d values_match=%t", publicURLID, version, matches)
		}
		delete(expectedUsage, publicURLID)
	}
	if err := rows.Err(); err != nil || len(expectedUsage) != 0 {
		t.Fatalf("missing usage routes=%d: %v", len(expectedUsage), err)
	}
	assertAssignmentTotals(t, f.database.pool, int64(f.routes)*2)
	var databaseBytesAfter, historyBytesAfter, walBytes int64
	if err := f.database.pool.QueryRow(verifyCtx, `SELECT pg_database_size(current_database()), pg_total_relation_size('control.ingress_routing_table_events'), pg_wal_lsn_diff(pg_current_wal_lsn(), $1::pg_lsn)::bigint`, walStart).Scan(&databaseBytesAfter, &historyBytesAfter, &walBytes); err != nil {
		t.Fatal(err)
	}
	t.Logf("database_bytes_before=%d database_bytes_after=%d routing_history_bytes_after=%d", databaseBytesBefore, databaseBytesAfter, historyBytesAfter)
	t.Logf("postgres_cluster_wal_bytes=%d (includes all concurrent database activity and vacuum)", walBytes)
	t.Logf("cadence_verified_routes=%d usage_buckets=%d final_revision=%d", f.routes, f.routes*int(duration/time.Minute), final.RoutingTableRevision)
	cancel()
	actors.Wait()
	if firstErr != nil {
		t.Fatal(firstErr)
	}
}

func cadenceMetricValue(families []*dto.MetricFamily, name string) (float64, bool) {
	for _, family := range families {
		if family.GetName() != name || len(family.Metric) != 1 {
			continue
		}
		metric := family.Metric[0]
		if metric.Counter != nil {
			return metric.Counter.GetValue(), true
		}
		if metric.Gauge != nil {
			return metric.Gauge.GetValue(), true
		}
	}
	return 0, false
}

func waitCadence(ctx context.Context, at time.Time) error {
	timer := time.NewTimer(max(0, time.Until(at)))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
