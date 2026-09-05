package controlstate

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/routeusage"
)

// This is a bounded database workload, not a lease-cadence or soak test. The
// certificate fixture signs local test material; no visitors, DNS, or ACME
// network calls are involved. All logical leases last one hour.
func TestLoadSteadyState(t *testing.T) {
	setupStarted := time.Now()
	f := newControlLoadFixture(t)
	sessions := readySteadyLoadSessions(t, f)
	historyRevision := seedLoadRoutingHistory(t, f, 1, f.history)
	var ingresses [2]IngressLease
	for index := range ingresses {
		lease, err := f.database.RegisterIngress(t.Context(), IngressRegistration{
			IngressID: fmt.Sprintf("load-ingress-%d", index), IngressRunID: "load-run", ProtocolVersion: 1,
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
	byID := make(map[string]RouteSessionSetup, f.routes)
	for _, session := range sessions {
		byID[session.setup.RouteID] = session.setup
	}
	for _, event := range initial.Routes {
		setup, ok := byID[event.RouteID]
		if !ok || event.Kind != IngressRouteUpsert || event.RouteVersion != setup.RouteVersion || event.EntryRevision != uint64(f.history) ||
			event.Projection.RouteSessionID != setup.RouteSessionID || len(event.Projection.PublisherConnections) != 2 {
			t.Fatalf("initial snapshot: unexpected route %s", event.RouteID)
		}
		delete(byID, event.RouteID)
	}
	t.Logf("setup_ready=%d relays=4 ingresses=2 setup_elapsed=%s (no injected SQL delay)", len(sessions), time.Since(setupStarted))

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	var heartbeats, pages atomic.Int64
	f.startMetrics(t)
	started := time.Now()
	defer func() {
		t.Logf("heartbeats=%d/%d usage_pages_including_replays=%d/%d workers=64 elapsed=%s", heartbeats.Load(), 3*f.routes, pages.Load(), 8*((f.routes+15)/16), time.Since(started))
		f.logStats(t)
	}()
	defer workers.stop()
	var first sync.Once
	var firstErr error
	fail := func(err error) {
		first.Do(func() { firstErr = err; cancel() })
	}
	// Each route belongs to one workflow, so its three heartbeats advance its
	// logical time monotonically even when workflows progress at different rates.
	start := make(chan struct{})
	var work sync.WaitGroup
	work.Add(64 + len(ingresses))
	for worker := range 64 {
		workers.Go(func() {
			defer work.Done()
			<-start
			control := f.controls[worker%2]
			for sweep := range 3 {
				for index := worker; index < len(sessions) && ctx.Err() == nil; index += 64 {
					session := sessions[index]
					callCtx, stop := context.WithTimeout(ctx, 20*time.Second)
					setup, err := control.HeartbeatRouteSession(callCtx, session.authentication(), f.now.Add(time.Duration(sweep+1)*time.Second), time.Hour, time.Hour)
					stop()
					if err != nil {
						fail(fmt.Errorf("heartbeat route=%s sweep=%d: %w", session.setup.RouteID, sweep+1, err))
						return
					}
					if setup.RouteID != session.setup.RouteID || setup.RouteVersion != session.setup.RouteVersion ||
						setup.RouteSessionID != session.setup.RouteSessionID || setup.State != RouteSessionReady || setup.ReadyAt == nil {
						fail(fmt.Errorf("heartbeat changed ready session %s", session.setup.RouteID))
						return
					}
					for slot, connection := range setup.PublisherConnections {
						if connection.ConnectionAssignmentIdentity != session.setup.PublisherConnections[slot].ConnectionAssignmentIdentity || connection.State != PublisherConnectionReady {
							fail(fmt.Errorf("heartbeat changed ready assignment route=%s slot=%d", setup.RouteID, slot))
							return
						}
					}
					heartbeats.Add(1)
				}
			}
		})
	}
	bucketStart := f.now.Truncate(time.Minute)
	now := f.now.Add(3 * time.Second)
	for index, ingress := range ingresses {
		// Exactly one serial page stream per ingress. Each cumulative revision
		// is replayed once before the next page; only new deltas may be counted.
		workers.Go(func() {
			defer work.Done()
			<-start
			for revision := uint64(1); revision <= 2; revision++ {
				for offset := 0; offset < len(sessions) && ctx.Err() == nil; offset += 16 {
					var reports []IngressUsageReport
					for _, session := range sessions[offset:min(offset+16, len(sessions))] {
						n := revision * uint64(index+1)
						reports = append(reports, IngressUsageReport{
							RouteID: session.setup.RouteID, RouteVersion: session.setup.RouteVersion,
							BucketStart: bucketStart, BucketEnd: bucketStart.Add(time.Minute), ObservedThrough: f.now,
							ReportRevision: revision, ConnectionAttempts: 4 * n, SuccessfulStreams: n,
							PolicyDenials: n, CapacityDenials: n, VisitorStreamOpenFailures: n,
							ConnectionNanoseconds: 100 * n, IngressBytes: 100 * n, EgressBytes: 200 * n,
							HistogramData: (routeusage.Checkpoint{}).MarshalBinary(),
						})
					}
					for replay := range 2 {
						callCtx, stop := context.WithTimeout(ctx, 20*time.Second)
						err := f.controls[index].ReportIngressUsage(callCtx, ingress.IngressLeaseIdentity, IngressUsageBatch{Reports: reports}, now)
						stop()
						if err != nil {
							fail(fmt.Errorf("usage ingress=%d offset=%d revision=%d replay=%d: %w", index, offset, revision, replay, err))
							return
						}
						pages.Add(1)
					}
				}
			}
		})
	}
	workDone := make(chan struct{})
	workers.Go(func() { work.Wait(); close(workDone) })
	for index, ingress := range ingresses {
		workers.Go(func() {
			<-start
			if err := observeSteadyLoad(t, ctx, f.controls[index], ingress.IngressLeaseIdentity, initial, now, workDone); err != nil {
				fail(fmt.Errorf("routing/renewal ingress=%d: %w", index, err))
			}
		})
	}
	close(start)
	workers.Wait()
	if firstErr != nil {
		t.Fatal(firstErr)
	}
	if ctx.Err() != nil {
		t.Fatal(ctx.Err())
	}
	if heartbeats.Load() != int64(3*f.routes) || pages.Load() != int64(8*((f.routes+15)/16)) {
		t.Fatal("incomplete heartbeat or usage workload")
	}
	t.Logf("mixed_workload_elapsed=%s", time.Since(started))
	// Both ingress streams end at revision 2: their cumulative units are 2+4.
	// One undelayed row stream checks every stored bucket and its session. Match
	// each row to the fixture to reject missing, extra, duplicate, or misrouted
	// rows even when their global sums happen to be correct.
	verificationStarted := time.Now()
	verified := 0
	defer func() {
		t.Logf("verified_usage_buckets=%d/%d verification_elapsed=%s", verified, len(sessions), time.Since(verificationStarted))
	}()
	for _, session := range sessions {
		byID[session.setup.RouteID] = session.setup
	}
	callCtx, stop := context.WithTimeout(ctx, 20*time.Second)
	defer stop()
	rows, err := f.database.pool.Query(callCtx, `
		SELECT b.route_id, b.route_version, COALESCE(s.id, ''),
			(b.bucket_start = $1 AND b.bucket_end = $2 AND b.observed_through = $3
			 AND b.connection_attempts = 24 AND b.successful_streams = 6
			 AND b.policy_denials = 6 AND b.capacity_denials = 6 AND b.visitor_stream_open_failures = 6
			 AND b.connection_nanoseconds = 600 AND b.ingress_bytes = 600 AND b.egress_bytes = 1200
			 AND s.policy_denials = 6) IS TRUE
		FROM control.route_usage_buckets b
		LEFT JOIN control.route_sessions s ON s.route_id = b.route_id AND s.route_version = b.route_version`,
		bucketStart, bucketStart.Add(time.Minute), f.now)
	if err != nil {
		t.Fatalf("verify usage: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var routeID, sessionID string
		var version uint64
		var valuesMatch bool
		if err := rows.Scan(&routeID, &version, &sessionID, &valuesMatch); err != nil {
			t.Fatalf("verify usage row: %v", err)
		}
		expected, ok := byID[routeID]
		if !ok || version != expected.RouteVersion || sessionID != expected.RouteSessionID || !valuesMatch {
			t.Fatalf("unexpected usage bucket/session route=%s version=%d session=%s expected_route=%t values_match=%t", routeID, version, sessionID, ok, valuesMatch)
		}
		delete(byID, routeID)
		verified++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("verify usage rows: %v", err)
	}
	if len(byID) != 0 {
		t.Fatalf("missing usage buckets: verified=%d want=%d", verified, len(sessions))
	}
	assertAssignmentTotals(t, f.database.pool, int64(f.routes)*2)
}

func readySteadyLoadSessions(t *testing.T, f *controlLoadFixture) []routeSessionFixture {
	t.Helper()
	return readyLoadSessions(t, f, time.Hour, time.Hour)
}

func readyLoadSessions(t *testing.T, f *controlLoadFixture, publisherLease, credentialLifetime time.Duration) []routeSessionFixture {
	t.Helper()
	var sessions []routeSessionFixture
	started := time.Now()
	defer func() { t.Logf("ready_setup_completed=%d/%d elapsed=%s", len(sessions), f.routes, time.Since(started)) }()
	// Use the untraced setup pool and stay serial: the certificate helper claims
	// the oldest pending ACME order and expects it to be the one just created.
	for index := range f.routes {
		request := f.request(index)
		setup, err := f.database.CreateRouteSession(t.Context(), request, f.now, publisherLease, credentialLifetime)
		if err != nil {
			t.Fatal(err)
		}
		leases := make(map[string]RelayLease)
		for service, choices := range f.leases {
			leases[service] = choices[index%2]
		}
		session := routeSessionFixture{database: f.database, now: f.now, request: request, setup: setup, leases: leases}
		work := createPlanIssuanceWork(t, f.database, f.now, session.authentication(), session.certificatePlan(), true, func(work *ACMEOrderWork) {
			for index := range work.Authorizations {
				work.Authorizations[index].AuthorizationURL += "/" + setup.RouteSessionID
				work.Authorizations[index].ChallengeURL += "/" + setup.RouteSessionID
			}
		})
		if _, err := f.database.MarkRouteCertificateInstalled(t.Context(), session.authentication(), work.ID, *work.NotAfter, f.now); err != nil {
			t.Fatal(err)
		}
		for slot := range setup.PublisherConnections {
			claimTestConnection(t, session, slot, f.now)
		}
		ready, err := f.database.MarkRouteSessionReady(t.Context(), session.authentication(), f.now)
		if err != nil || !ready.Routable {
			t.Fatalf("ready route=%s routable=%t: %v", setup.RouteID, ready.Routable, err)
		}
		sessions = append(sessions, session)
	}
	return sessions
}

// One actor per ingress drains delta pages promptly, renewing and sampling a
// live snapshot initially and once a second. A final observation after writes
// finish verifies the fully drained history against the final snapshot.
func observeSteadyLoad(t *testing.T, ctx context.Context, control *Database, ingress IngressLeaseIdentity, initial IngressRoutingTableSnapshot, now time.Time, workDone <-chan struct{}) error {
	expected := make(map[string]IngressRoutingTableEvent, len(initial.Routes))
	entries := make(map[string]uint64, len(initial.Routes))
	for _, event := range initial.Routes {
		expected[event.RouteID], entries[event.RouteID] = event, event.EntryRevision
	}
	cursor := initial.RoutingTableRevision
	highWater := initial.RoutingTableRevision
	var nextObservation time.Time
	var renewals, events, snapshots int
	started := time.Now()
	defer func() {
		t.Logf("ingress=%s renewals=%d routing_events=%d snapshots=%d cursor=%d elapsed=%s", ingress.IngressID, renewals, events, snapshots, cursor, time.Since(started))
	}()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for ctx.Err() == nil {
		finished := false
		select {
		case <-workDone:
			finished = true
		default:
		}
		callCtx, stop := context.WithTimeout(ctx, 20*time.Second)
		page, err := control.ReadIngressRoutingTableEvents(callCtx, ingress, cursor, MaximumIngressRoutingTablePageSize, now)
		stop()
		if err != nil {
			return fmt.Errorf("events after=%d: %w", cursor, err)
		}
		if page.ResnapshotRequired || page.ThroughRevision < highWater {
			return fmt.Errorf("unexpected routing history reset after=%d through=%d high_water=%d", cursor, page.ThroughRevision, highWater)
		}
		highWater = page.ThroughRevision
		for _, event := range page.Events {
			if event.RoutingTableRevision != cursor+1 || event.EntryRevision != entries[event.RouteID]+1 {
				return fmt.Errorf("missing or unordered event after=%d got=%d route=%s entry=%d", cursor, event.RoutingTableRevision, event.RouteID, event.EntryRevision)
			}
			if err := checkSteadyLoadProjection(event, expected[event.RouteID], now); err != nil {
				return err
			}
			cursor, entries[event.RouteID] = event.RoutingTableRevision, event.EntryRevision
			events++
		}
		if page.NextRevision != cursor || cursor > page.ThroughRevision || page.More != (cursor < page.ThroughRevision) || (page.More && len(page.Events) == 0) {
			return fmt.Errorf("inconsistent routing cursor=%d next=%d through=%d", cursor, page.NextRevision, page.ThroughRevision)
		}
		if !time.Now().Before(nextObservation) || (finished && !page.More) {
			callCtx, stop = context.WithTimeout(ctx, 20*time.Second)
			lease, err := control.RenewIngress(callCtx, IngressRenewal{IngressLeaseIdentity: ingress, RoutingTableRevision: cursor}, now, time.Hour)
			stop()
			if err != nil {
				return fmt.Errorf("renew: %w", err)
			}
			if lease.IngressLeaseIdentity != ingress || !lease.LeaseExpiresAt.After(now) {
				return fmt.Errorf("renew changed ingress identity or expired its lease")
			}
			renewals++
			callCtx, stop = context.WithTimeout(ctx, 20*time.Second)
			snapshot, err := control.ReadIngressRoutingTableSnapshot(callCtx, ingress, now)
			stop()
			if err != nil {
				return fmt.Errorf("snapshot: %w", err)
			}
			snapshots++
			if len(snapshot.Routes) != len(expected) || snapshot.RoutingTableRevision < highWater {
				return fmt.Errorf("snapshot routes=%d want=%d revision=%d high_water=%d", len(snapshot.Routes), len(expected), snapshot.RoutingTableRevision, highWater)
			}
			highWater = snapshot.RoutingTableRevision
			nextObservation = time.Now().Add(time.Second)
			seen := make(map[string]bool, len(expected))
			for _, event := range snapshot.Routes {
				if seen[event.RouteID] || event.EntryRevision < entries[event.RouteID] {
					return fmt.Errorf("duplicate or stale snapshot route=%s entry=%d", event.RouteID, event.EntryRevision)
				}
				seen[event.RouteID] = true
				if err := checkSteadyLoadProjection(event, expected[event.RouteID], now); err != nil {
					return err
				}
			}
			if finished && !page.More {
				if cursor != snapshot.RoutingTableRevision || cursor != initial.RoutingTableRevision+uint64(3*len(expected)) {
					return fmt.Errorf("final routing cursor=%d snapshot=%d want=%d", cursor, snapshot.RoutingTableRevision, initial.RoutingTableRevision+uint64(3*len(expected)))
				}
				for _, event := range snapshot.Routes {
					if event.EntryRevision != expected[event.RouteID].EntryRevision+3 || event.EntryRevision != entries[event.RouteID] {
						return fmt.Errorf("final snapshot/event history mismatch route=%s entry=%d", event.RouteID, event.EntryRevision)
					}
				}
				return nil
			}
		}
		if !page.More {
			select {
			case <-ctx.Done():
			case <-tick.C:
			}
		}
	}
	return ctx.Err()
}

func checkSteadyLoadProjection(event, expected IngressRoutingTableEvent, now time.Time) error {
	if event.Kind != IngressRouteUpsert || event.RouteID != expected.RouteID || event.RouteVersion != expected.RouteVersion ||
		event.CanonicalHostname != expected.CanonicalHostname || event.Projection.RouteSessionID != expected.Projection.RouteSessionID ||
		!event.Projection.RouteExpiresAt.After(now) || !slices.Equal(event.Projection.PublisherConnections, expected.Projection.PublisherConnections) {
		return fmt.Errorf("routing projection lost ready session or assignment identity route=%s revision=%d", event.RouteID, event.RoutingTableRevision)
	}
	return nil
}
