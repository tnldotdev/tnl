package controlstate

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/publicurlusage"
)

// the gate is controlled latency on the last public URL, not a sleep: PostgreSQL's
// wait graph proves which earlier locks are retained and exhaust both pools.
func TestIntegrationUsagePagesContainHeartbeatLockFootprint(t *testing.T) {
	for _, pageSize := range []int{256, 16} {
		t.Run(fmt.Sprint(pageSize), func(t *testing.T) {
			observer, databaseURL, now := newControlStateIntegrationDatabaseWithURL(t, "usage_contention")
			leases := make(map[string]RelayLease)
			for index := range 2 {
				registration := relayLifecycleRegistration(fmt.Sprintf("usage-%d", index))
				registration.ConnectionCapacity = 100
				lease, err := observer.RegisterRelay(t.Context(), registration, now, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				leases[lease.RelayServiceID] = lease
			}
			var fixtures []publishRunFixture
			var reports []IngressUsageReport
			for index := range 17 {
				suffix := fmt.Sprintf("usage%02d", index)
				seedControlPublicURL(t, observer, now, suffix)
				request := PublishRunRequest{
					PublicURLID: "public_url_" + suffix, TeamID: "team_" + suffix, ActingIdentityID: "identity_" + suffix, MembershipID: "membership_" + suffix,
					RequireLocalAuthority: true, RetrySecret: make([]byte, 32), IdempotencyKey: suffix, PolicyRevision: 1, ExpectedMutationRevision: 1,
					CertificateCacheKey: suffix, CertificateScope: "route", CertificateIdentifiers: []string{"route-" + suffix + ".example.test"}, CertificateChallenge: "tls-alpn-01",
				}
				setup, err := observer.CreatePublishRun(t.Context(), request, now, time.Hour, time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				fixture := publishRunFixture{database: observer, now: now, request: request, setup: setup, leases: leases}
				work := createPlanIssuanceWork(t, observer, now, fixture.authentication(), fixture.certificatePlan(), true, func(work *ACMEOrderWork) {
					for index := range work.Authorizations {
						work.Authorizations[index].AuthorizationURL += "/" + suffix
						work.Authorizations[index].ChallengeURL += "/" + suffix
					}
				})
				if _, err := observer.MarkPublicURLCertificateInstalled(t.Context(), fixture.authentication(), work.ID, *work.NotAfter, now); err != nil {
					t.Fatal(err)
				}
				for slot := range setup.PublisherConnections {
					claimTestConnection(t, fixture, slot, now)
				}
				if _, err := observer.MarkPublishRunReady(t.Context(), fixture.authentication(), now); err != nil {
					t.Fatal(err)
				}
				fixtures = append(fixtures, fixture)
				start := now.Truncate(time.Minute)
				reports = append(reports, IngressUsageReport{PublicURLID: setup.PublicURLID, PublishRunNumber: setup.PublishRunNumber, BucketStart: start, BucketEnd: start.Add(time.Minute), ObservedThrough: now, ReportRevision: 1, ConnectionAttempts: 1, HistogramData: (publicurlusage.Checkpoint{}).MarshalBinary()})
			}
			ingress := registerTestIngress(t, observer, now)
			parsed, err := url.Parse(databaseURL)
			if err != nil {
				t.Fatal(err)
			}
			query := parsed.Query()
			query.Set("pool_max_conns", "4")
			parsed.RawQuery = query.Encode()
			var pools []*Database
			for range 2 {
				db, err := Open(t.Context(), parsed.String(), testStorageKey, "")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(db.Close)
				pools = append(pools, db)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			workers := newIntegrationWorkers(t, cancel)
			gate, err := observer.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			defer workers.stop()
			if _, err := controlstatedb.New(gate).LockPublishRunForUsage(ctx, controlstatedb.LockPublishRunForUsageParams{PublicURLID: reports[16].PublicURLID, PublishRunNumber: int64(reports[16].PublishRunNumber)}); err != nil {
				t.Fatal(err)
			}
			// Baseline: healthy ready heartbeats complete before usage starts.
			heartbeat := func(db *Database, index int) error {
				setup, err := db.HeartbeatPublishRun(ctx, fixtures[index].authentication(), now.Add(time.Second), time.Hour, time.Minute)
				if err == nil && (setup.PublisherConnections[0].State != PublisherConnectionReady || setup.PublisherConnections[1].State != PublisherConnectionReady) {
					return errors.New("heartbeat lost ready connections")
				}
				return err
			}
			for _, db := range pools {
				if err := heartbeat(db, 0); err != nil {
					t.Fatal(err)
				}
			}
			// a separate gate demonstrates the other serialization boundary:
			// ready heartbeats still publish lease-extension events at commit.
			clock, err := observer.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, clock)
			if _, err := controlstatedb.New(clock).LockIngressRoutingTableClock(ctx); err != nil {
				t.Fatal(err)
			}
			clockDone := make(chan error, 1)
			workers.Go(func() { clockDone <- heartbeat(pools[0], 6) })
			waitForPostgresBlock(t, ctx, observer, int32(clock.Conn().PgConn().PID()), clockDone)
			operations, _ := pools[0].activity.snapshot(time.Now())
			if len(operations) != 1 || operations[0].Operation != "InsertFinalIngressRoutingTableEvent" {
				t.Fatalf("heartbeat clock wait = %+v", operations)
			}
			if err := clock.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, clockDone); err != nil {
				t.Fatal(err)
			}
			usageDone := make(chan error, 1)
			workers.Go(func() {
				for offset := 0; offset < len(reports); offset += pageSize {
					if err := pools[0].ReportIngressUsage(ctx, ingress.IngressLeaseIdentity, IngressUsageBatch{Reports: reports[offset:min(offset+pageSize, len(reports))]}, now.Add(time.Second)); err != nil {
						usageDone <- err
						return
					}
				}
				usageDone <- nil
			})
			usagePID := waitForPostgresBlock(t, ctx, observer, int32(gate.Conn().PgConn().PID()), usageDone)
			renewDone := make(chan error, 1)
			workers.Go(func() {
				_, err := pools[1].RenewIngress(ctx, IngressRenewal{IngressLeaseIdentity: ingress.IngressLeaseIdentity}, now.Add(time.Second), time.Hour)
				renewDone <- err
			})
			waitForPostgresBlock(t, ctx, observer, usagePID, renewDone)
			heartbeats := make(chan error, 6)
			for index := range 6 {
				workers.Go(func() { heartbeats <- heartbeat(pools[index%2], index) })
			}
			if pageSize == 16 {
				for range 6 {
					if err := awaitIntegrationResult(t, ctx, heartbeats); err != nil {
						t.Fatal(err)
					}
				}
				t.Log("16-report page committed: all six earlier-route heartbeats completed while the next page and lease renewal remained blocked")
			} else {
				// six different public URLs make every waiter block on usage, not
				// another heartbeat's public URL lock.
				tick := time.NewTicker(time.Millisecond)
				defer tick.Stop()
				for {
					var blocked int
					if err := observer.pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND $1::int = ANY(pg_blocking_pids(pid))`, usagePID).Scan(&blocked); err != nil {
						t.Fatal(err)
					}
					if blocked == 7 && pools[0].PoolStats().AcquiredConns() == 4 && pools[1].PoolStats().AcquiredConns() == 4 {
						break
					}
					select {
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					case <-tick.C:
					}
				}
				for _, db := range pools {
					snapshot, err := db.Diagnostics(ctx)
					if err != nil || len(snapshot.ActiveOperations) != 4 {
						t.Fatalf("pool-exhausted diagnostic = %+v, %v", snapshot, err)
					}
					for _, operation := range snapshot.ActiveOperations {
						if operation.Operation == "unknown" || operation.ElapsedSeconds < 0 {
							t.Fatalf("waiting query not identified: %+v", operation)
						}
					}
					unavailable, stopDiagnostics := context.WithCancel(ctx)
					stopDiagnostics()
					local, err := db.Diagnostics(unavailable)
					if err == nil || local.Error == "" || len(local.ActiveOperations) != 4 {
						t.Fatalf("upstream failure lost local queries: %+v, %v", local, err)
					}
					waitCtx, stop := context.WithTimeout(ctx, 25*time.Millisecond)
					err = db.Health(waitCtx)
					stop()
					if !errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("request pool was not exhausted: %v", err)
					}
				}
				t.Log("single batch: usage holds six publish-run locks plus ingress lease; seven direct waiters exhaust both four-connection pools without a SQL deadlock")
			}
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, usageDone); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, renewDone); err != nil {
				t.Fatal(err)
			}
			if pageSize != 16 {
				for range 6 {
					if err := awaitIntegrationResult(t, ctx, heartbeats); err != nil {
						t.Fatal(err)
					}
				}
			}
			for _, db := range pools {
				if operations, truncated := db.activity.snapshot(time.Now()); len(operations) != 0 || truncated {
					t.Fatalf("finished SQL retained: %+v", operations)
				}
			}
		})
	}
}

func TestIntegrationExpiredIngressRunRequiresNewRun(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "expired_ingress")
	registration := IngressRegistration{IngressID: "ingress-expired", IngressRunID: "old-run", ProtocolVersion: 1, ConnectionCapacity: 10}
	lease, err := database.RegisterIngress(t.Context(), registration, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	expired := now.Add(time.Minute)
	for range 2 {
		if _, err := database.RegisterIngress(t.Context(), registration, expired, time.Minute); !errors.Is(err, ErrIngressLeaseStale) {
			t.Fatalf("same-run registration = %v", err)
		}
	}
	if _, err := database.MarkExpiredIngressUsageRunsIncomplete(t.Context(), expired); err != nil {
		t.Fatal(err)
	}
	before := readUsageRun(t, database, lease)
	registration.IngressRunID = "new-run"
	restarted, err := database.RegisterIngress(t.Context(), registration, expired, time.Minute)
	if err != nil || restarted.IngressLeaseRevision != lease.IngressLeaseRevision+1 {
		t.Fatalf("new-run registration = %+v, %v", restarted, err)
	}
	if _, err := database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: restarted.IngressLeaseIdentity}, expired.Add(time.Second), time.Minute); err != nil {
		t.Fatal(err)
	}
	if after := readUsageRun(t, database, lease); after != before {
		t.Fatalf("restart changed finalized old coverage: before=%+v after=%+v", before, after)
	}
	var oldRevision int64
	if err := database.pool.QueryRow(t.Context(), `SELECT ingress_lease_revision FROM control.ingress_usage_runs WHERE ingress_run_id = 'old-run'`).Scan(&oldRevision); err != nil || oldRevision != int64(lease.IngressLeaseRevision) {
		t.Fatalf("old accounting revision = %d, %v", oldRevision, err)
	}
}
