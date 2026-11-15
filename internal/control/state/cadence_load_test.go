package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
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
// production ingress API adapter without a controlstate import cycle. this is
// still a database workload: publisher transports and visitor sockets are absent.
func RunCadenceLoad(t *testing.T, newClient func(*Database, func() time.Time) (ingress.ControlClient, error)) {
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
	if err := f.database.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, f.now); err != nil {
		t.Fatal(err)
	}
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
	failed := sessions[0].leases[sessions[0].run.Connections[0].RelayServiceID]
	var leaseMu sync.RWMutex
	current := make([]ServiceRunState, f.routes)
	bindings := make([]map[string]RelayLease, f.routes)
	for index, session := range sessions {
		current[index] = session.run
		bindings[index] = cloneLoadLeases(session.leases)
	}
	// setup uses one fixed logical instant. from here the clock runs at wall
	// speed; every caller, service run, and process lease shares it.
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
			// collect the production's bounded, sanitized diagnostics before
			// cancellation and cleanup change the database wait graph.
			diagnostic, _ := f.controls[0].Diagnostics(t.Context())
			if data, marshalErr := json.Marshal(diagnostic); marshalErr == nil {
				t.Logf("failure_database_diagnostic=%s", data)
			}
			cancel()
		})
	}
	var controllers [2]*ingress.Controller
	var ingressMetrics [2]*observability.Metrics
	for index := range controllers {
		client, err := newClient(f.controls[index], now)
		if err != nil {
			t.Fatal(err)
		}
		metrics := observability.New("ingress")
		controller, err := ingress.NewController(ingress.ControllerConfig{
			Client:          client,
			Registration:    ingressv1.IngressRegistration{Region: "local", IngressId: fmt.Sprintf("cadence-ingress-%d", index), IngressRunId: "cadence-run", ProtocolVersion: 1, ConnectionCapacity: int64(max(64, f.routes)), IngressPoolId: PrimaryIngressPoolID, Https: true, ServicePorts: []int{}},
			RenewalInterval: cadenceRenewalInterval, RetryInterval: time.Second,
			Now: now, Observer: metrics, Report: func(err error) { fail(fmt.Errorf("ingress control: %w", err)) },
		})
		if err != nil {
			t.Fatal(err)
		}
		controllers[index], ingressMetrics[index] = controller, metrics
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
	t.Logf("cadence_setup_elapsed=%s routes=%d heartbeat_interval=%s publisher_lease=%s process_lease=%s renewal_interval=%s duration=%s", time.Since(setupStarted), f.routes, cadenceHeartbeatInterval, cadencePublisherLease, cadenceProcessLease, cadenceRenewalInterval, duration)
	started := time.Now()
	var scheduled, completed, renewed, late, repaired atomic.Int64
	var maximumQueueDelay atomic.Int64
	var pruned, scanned atomic.Int64
	var expiredAt atomic.Int64
	pending := make([]atomic.Bool, f.routes)
	wasRepaired := make([]bool, f.routes) // one pending heartbeat per service.
	affected := int64(0)
	for _, session := range sessions {
		if session.leases[failed.RelayServiceID].RelayID == failed.RelayID {
			affected++
		}
	}
	defer func() {
		if retention > 0 {
			t.Logf("service_audit_cleanup_window=%s eligible_observations=%d deleted=%d", retention, scanned.Load(), pruned.Load())
		}
		t.Logf("cadence_elapsed=%s scheduled=%d completed=%d expected=%d pending=%d late=%d max_scheduler_queue_delay=%s lease_renewals=%d recovered=%d/%d", time.Since(started), scheduled.Load(), completed.Load(), int64(f.routes)*int64(duration/cadenceHeartbeatInterval), scheduled.Load()-completed.Load(), late.Load(), time.Duration(maximumQueueDelay.Load()), renewed.Load(), repaired.Load(), affected)
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
	// join before the deferred metric snapshot, even when a deadline fails.
	defer actors.stop()
	type job struct {
		index int
		due   time.Time
	}
	jobs := make(chan job, f.routes)
	var work sync.WaitGroup
	work.Add(64 + 1 + len(leases) + len(controllers))
	for index, controller := range controllers {
		actors.Go(func() {
			defer work.Done()
			if err := observeCadenceAdmissions(t, ctx, f.controls[index], controller, sessions, failed, now, started.Add(duration)); err != nil {
				fail(err)
			}
		})
	}
	var auditRowsBefore int64
	if err := f.database.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_audit_events`).Scan(&auditRowsBefore); err != nil {
		t.Fatal(err)
	}
	if retention > 0 {
		work.Add(len(f.controls))
		for _, control := range f.controls {
			actors.Go(func() {
				defer work.Done()
				for time.Since(started) < duration && ctx.Err() == nil {
					at := time.Now()
					callCtx, stop := context.WithTimeout(ctx, 2*time.Second)
					var eligible int64
					err := control.pool.QueryRow(callCtx, `SELECT count(*) FROM
						(SELECT cursor FROM control.service_audit_events WHERE received_at<$1 ORDER BY received_at,cursor LIMIT 1000) candidates`, at.Add(-retention)).Scan(&eligible)
					var deleted int64
					if err == nil {
						// audit received_at uses PostgreSQL's wall clock, not the
						// serving clock. shorten only its cleanup retention window.
						deleted, err = control.CleanupServiceAudit(callCtx, at.Add(serviceaudit.Retention-retention), 1000)
					}
					stop()
					if err != nil {
						if ctx.Err() == nil {
							fail(err)
						}
						return
					}
					scanned.Add(eligible)
					pruned.Add(deleted)
					delay := 30 * time.Second
					if deleted == 1000 {
						delay = 100 * time.Millisecond
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
				setup, err := f.controls[worker%2].HeartbeatServiceRun(callCtx, session.service.ID, session.run.RunID, session.run.Token, now(), ServiceRunHealth{Healthy: true, StreamCapacity: 64})
				stop()
				if err == nil && (setup.ServiceID != session.service.ID || setup.RunID != session.run.RunID || setup.RunNumber != session.run.RunNumber || setup.State != "ready" || !setup.Healthy || !setup.ExpiresAt.After(now()) || len(setup.Connections) != 2) {
					err = errors.New("heartbeat lost a live session")
				}
				changed := false
				for slot, connection := range setup.Connections {
					if err != nil {
						break
					}
					previous := current[item.index].Connections[slot]
					if connection.State == "ready" {
						if connection != previous {
							err = errors.New("ready assignment changed without publisher claim")
						}
						continue
					}
					if connection.State != "assigned" || session.leases[connection.RelayServiceID].RelayID != failed.RelayID || connection.ConnectionSlot != previous.ConnectionSlot || connection.RelayServiceID != previous.RelayServiceID || connection.Revision <= previous.Revision || connection.PublisherConnectionID == previous.PublisherConnectionID || connection.Credential == previous.Credential || !connection.CredentialExpiresAt.After(now()) {
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
					callCtx, stop = context.WithTimeout(ctx, cadenceControlTimeout)
					_, err = f.controls[worker%2].ClaimServicePublisherConnection(callCtx, connection.PublisherConnectionID, session.service.ID, setup.RunID, setup.RunNumber,
						connection.Revision, connection.Credential, netip.MustParseAddr("127.0.0.1"), selected.RelayLeaseIdentity, now())
					stop()
					if err != nil {
						break
					}
					callCtx, stop = context.WithTimeout(ctx, cadenceControlTimeout)
					_, err = f.controls[worker%2].ReadyServicePublisherConnection(callCtx, connection.PublisherConnectionID, setup.RunID, setup.RunNumber, connection.Revision, selected.RelayLeaseIdentity, now())
					stop()
					if err != nil {
						break
					}
					setup.Connections[slot].State = "ready"
					bindings[item.index][connection.RelayServiceID] = selected
					changed = true
				}
				if err != nil {
					if errors.Is(err, context.DeadlineExceeded) {
						late.Add(1)
					}
					fail(fmt.Errorf("heartbeat/replacement route=%d scheduled_elapsed=%s: %w", item.index, item.due.Sub(started), err))
					return
				}
				setup.Token = session.run.Token
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
				lease := controller.Lease()
				t.Logf("ingress=%d ready=%t lease_revision=%d last_renewal_age=%s", index, controller.Ready(now()), lease.IngressLeaseRevision, now().Sub(lease.RenewedAt))
			}
			if retention > 0 {
				var relationBytes, deadTuples, vacuums, rows int64
				if err := f.database.pool.QueryRow(ctx, `SELECT pg_total_relation_size('control.service_audit_events'), n_dead_tup, autovacuum_count,
					(SELECT count(*) FROM control.service_audit_events) FROM pg_stat_user_tables WHERE schemaname='control' AND relname='service_audit_events'`).Scan(&relationBytes, &deadTuples, &vacuums, &rows); err != nil {
					fail(err)
				} else {
					t.Logf("service_audit_cleanup_progress deleted=%d rows=%d relation_bytes=%d estimated_dead_tuples=%d autovacuums=%d", pruned.Load(), rows, relationBytes, deadTuples, vacuums)
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
	verifyCtx, stopVerification := context.WithTimeout(ctx, cadenceControlTimeout)
	defer stopVerification()
	// publisher workers have joined. lease controllers remain live while each
	// ingress verifies the exact current service and connected relay tuples.
	if retention > 0 {
		var rows int64
		if err := f.database.pool.QueryRow(verifyCtx, `SELECT count(*) FROM control.service_audit_events`).Scan(&rows); err != nil || rows != auditRowsBefore-pruned.Load() || pruned.Load() == 0 {
			t.Fatalf("service audit cleanup rows=%d before=%d deleted=%d: %v", rows, auditRowsBefore, pruned.Load(), err)
		}
		t.Logf("service_audit_cleanup_verified_rows=%d deleted=%d", rows, pruned.Load())
	}
	for ingressIndex, controller := range controllers {
		lease := controller.Lease()
		if !controller.Ready(now()) || lease.IngressLeaseRevision < 1 || !lease.RenewedAt.After(lease.RegisteredAt) {
			t.Fatalf("ingress=%d lost current renewed lease", ingressIndex)
		}
		identity := IngressLeaseIdentity{IngressID: lease.IngressId, IngressRunID: lease.IngressRunId, IngressLeaseRevision: uint64(lease.IngressLeaseRevision)}
		runs, err := readLoadServiceRuns(verifyCtx, f.database, identity, now())
		if err != nil {
			t.Fatal("final routing snapshot", err)
		}
		for index, session := range sessions {
			session.run, session.leases = current[index], bindings[index]
			if err := observeLoadService(runs, session, now()); err != nil {
				t.Fatalf("final admission ingress=%d service=%s: %v", ingressIndex, session.service.ID, err)
			}
		}
		t.Logf("ingress=%d verified_admissions=%d lease_revision=%d last_renewal_age=%s", ingressIndex, f.routes, lease.IngressLeaseRevision, now().Sub(lease.RenewedAt))
	}
	expectedRuns := make(map[string]ServiceRunState, f.routes)
	for _, session := range sessions {
		expectedRuns[session.service.ID] = session.run
	}
	rows, err := f.database.pool.Query(verifyCtx, `
		SELECT service_id, run_number, id,
		    (state='ready' AND healthy AND closed_at IS NULL AND publisher_expires_at > $1) IS TRUE
		FROM control.service_runs`, now())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var serviceID, sessionID string
		var version int64
		var matches bool
		if err := rows.Scan(&serviceID, &version, &sessionID, &matches); err != nil {
			t.Fatal(err)
		}
		expected, ok := expectedRuns[serviceID]
		if !ok || !matches || version != expected.RunNumber || sessionID != expected.RunID {
			t.Fatalf("unexpected run service_id=%s number=%d values_match=%t", serviceID, version, matches)
		}
		delete(expectedRuns, serviceID)
	}
	if err := rows.Err(); err != nil || len(expectedRuns) != 0 {
		t.Fatalf("missing runs=%d: %v", len(expectedRuns), err)
	}
	assertAssignmentTotals(t, f.database.pool, int64(f.routes)*2)
	var databaseBytesAfter, serviceBytesAfter, walBytes int64
	if err := f.database.pool.QueryRow(verifyCtx, `SELECT pg_database_size(current_database()),
		pg_total_relation_size('control.service_runs')+pg_total_relation_size('control.service_connection_slots')+pg_total_relation_size('control.public_service_visitors'),
		pg_wal_lsn_diff(pg_current_wal_lsn(), $1::pg_lsn)::bigint`, walStart).Scan(&databaseBytesAfter, &serviceBytesAfter, &walBytes); err != nil {
		t.Fatal(err)
	}
	t.Logf("database_bytes_before=%d database_bytes_after=%d service_admission_bytes_after=%d", databaseBytesBefore, databaseBytesAfter, serviceBytesAfter)
	t.Logf("postgres_cluster_wal_bytes=%d (includes all concurrent database activity and vacuum)", walBytes)
	t.Logf("cadence_verified_services=%d", f.routes)
	cancel()
	actors.Wait()
	if firstErr != nil {
		t.Fatal(firstErr)
	}
}

func observeCadenceAdmissions(t *testing.T, ctx context.Context, control *Database, controller *ingress.Controller, sessions []servicePublicationFixture, failed RelayLease, now func() time.Time, until time.Time) error {
	previous := make([][2]int64, len(sessions))
	var admissions, degraded int
	defer func() {
		t.Logf("cadence_ingress=%s admissions=%d degraded_observations=%d", controller.Lease().IngressId, admissions, degraded)
	}()
	for time.Now().Before(until) && ctx.Err() == nil {
		lease := controller.Lease()
		if !controller.Ready(now()) {
			return errors.New("cadence ingress lost its current lease")
		}
		identity := IngressLeaseIdentity{IngressID: lease.IngressId, IngressRunID: lease.IngressRunId, IngressLeaseRevision: uint64(lease.IngressLeaseRevision)}
		callCtx, stop := context.WithTimeout(ctx, cadenceControlTimeout)
		runs, err := readLoadServiceRuns(callCtx, control, identity, now())
		stop()
		if err != nil {
			return fmt.Errorf("cadence routing snapshot: %w", err)
		}
		for index, session := range sessions {
			admission, err := loadServiceRun(runs, session, now())
			if err != nil {
				return fmt.Errorf("cadence admission service=%s: %w", session.service.ID, err)
			}
			var seen [2]bool
			for _, relay := range admission.Relays {
				slot := relay.ConnectionSlot
				if slot < 0 || slot > 1 || seen[slot] || relay.ConnectionAssignmentRevision < previous[index][slot] {
					return fmt.Errorf("cadence admission duplicated or regressed a slot for %s", session.service.ID)
				}
				seen[slot] = true
				before := session.run.Connections[slot]
				initial := session.leases[before.RelayServiceID]
				if initial.RelayID != failed.RelayID && (relay.PublisherConnectionID != before.PublisherConnectionID ||
					relay.ConnectionAssignmentRevision != before.Revision || relay.RelayID != initial.RelayID ||
					relay.RelayRunID != initial.RelayRunID || relay.RelayLeaseRevision != int64(initial.RelayLeaseRevision)) {
					return fmt.Errorf("cadence admission changed a surviving relay for %s", session.service.ID)
				}
				if relay.RelayServiceID != before.RelayServiceID || relay.ConnectionAssignmentRevision < before.Revision ||
					relay.ConnectionAssignmentRevision == before.Revision && relay.PublisherConnectionID != before.PublisherConnectionID {
					return fmt.Errorf("cadence admission changed an assignment without advancing its revision for %s", session.service.ID)
				}
				previous[index][slot] = relay.ConnectionAssignmentRevision
			}
			for _, slot := range session.run.Connections {
				if session.leases[slot.RelayServiceID].RelayID != failed.RelayID && !seen[slot.ConnectionSlot] {
					return fmt.Errorf("cadence admission lost a surviving relay for %s", session.service.ID)
				}
			}
			if len(admission.Relays) == 1 {
				degraded++
			}
			admissions++
		}
		if waitCadence(ctx, minTime(until, time.Now().Add(time.Second))) != nil {
			return ctx.Err()
		}
	}
	return ctx.Err()
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
