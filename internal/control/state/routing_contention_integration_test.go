package state

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationReadyHeartbeatPublishesRoutingAtCommit(t *testing.T) {
	f := newPublishRunFixture(t)
	readyTestSession(t, f)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	gate, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	if _, err := controlstatedb.New(gate).LockIngressRoutingTableClock(ctx); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	workers.Go(func() {
		_, err := f.database.HeartbeatPublishRun(ctx, f.authentication(), f.now.Add(time.Second), time.Hour, time.Minute)
		done <- err
	})
	waitForPostgresBlock(t, ctx, f.database, int32(gate.Conn().PgConn().PID()), done)
	operations, _ := f.database.activity.snapshot(time.Now())
	if len(operations) != 1 || operations[0].Operation != "InsertFinalIngressRoutingTableEvent" {
		t.Fatal("heartbeat lost commit-time routing serialization", operations)
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, done); err != nil {
		t.Fatal(err)
	}
}

// retain the independent diagnostics/pool assertions from the retired usage
// contention suite, using actual remaining heartbeat and routing-clock owners.
func TestIntegrationHeartbeatPoolExhaustionRetainsLocalDiagnostics(t *testing.T) {
	observer, databaseURL, now := newControlStateIntegrationDatabaseWithURL(t, "heartbeat_contention")
	leases := make(map[string]RelayLease)
	for index := range 2 {
		registration := relayLifecycleRegistration(fmt.Sprintf("routing-%d", index))
		registration.ConnectionCapacity = 100
		lease, err := observer.RegisterRelay(t.Context(), registration, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		leases[lease.RelayServiceID] = lease
	}
	var fixtures []publishRunFixture
	for index := range 8 {
		suffix := fmt.Sprintf("routing%02d", index)
		publicURLID := fmt.Sprintf("url_%022d", index+1)
		seedControlPublicURL(t, observer, now, suffix, publicURLID)
		request := PublishRunRequest{PublicURLID: publicURLID, TeamID: "team_" + suffix, ActingIdentityID: "identity_" + suffix, MembershipID: "membership_" + suffix,
			RetrySecret: make([]byte, 32), IdempotencyKey: suffix, PolicyRevision: 1, ExpectedMutationRevision: 1, CertificateCacheKey: suffix, CertificateScope: "route", CertificateIdentifiers: []string{"route-" + suffix + ".example.test"}, CertificateChallenge: "dns-01"}
		setup, err := observer.CreatePublishRun(t.Context(), request, now, time.Hour, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		fixture := publishRunFixture{observer, now, request, setup, leases}
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
		readyTestServingRun(t, fixture, now)
		fixtures = append(fixtures, fixture)
	}
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
	gate, err := observer.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	if _, err := controlstatedb.New(gate).LockIngressRoutingTableClock(ctx); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 8)
	for index, f := range fixtures {
		workers.Go(func() {
			setup, err := pools[index%2].HeartbeatPublishRun(ctx, f.authentication(), now.Add(time.Second), time.Hour, time.Minute)
			if err == nil && (setup.PublisherConnections[0].State != PublisherConnectionReady || setup.PublisherConnections[1].State != PublisherConnectionReady) {
				err = errors.New("heartbeat lost ready publisher connections")
			}
			done <- err
		})
	}
	for {
		first, _ := pools[0].activity.snapshot(time.Now())
		second, _ := pools[1].activity.snapshot(time.Now())
		if len(first) == 4 && len(second) == 4 && pools[0].PoolStats().AcquiredConns() == 4 && pools[1].PoolStats().AcquiredConns() == 4 {
			break
		}
		select {
		case err := <-done:
			t.Fatal("heartbeat escaped routing gate", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	for _, db := range pools {
		snapshot, err := db.Diagnostics(ctx)
		if err != nil || len(snapshot.ActiveOperations) != 4 {
			t.Fatal("exhausted pool diagnostics lost operations", snapshot, err)
		}
		for _, operation := range snapshot.ActiveOperations {
			if operation.Operation == "unknown" || operation.ElapsedSeconds < 0 {
				t.Fatal("blocked query lost identity/time", operation)
			}
		}
		unavailable, stop := context.WithCancel(ctx)
		stop()
		local, err := db.Diagnostics(unavailable)
		if err == nil || local.Error == "" || len(local.ActiveOperations) != 4 {
			t.Fatal("upstream failure lost local operations", local, err)
		}
		waiting, stop := context.WithTimeout(ctx, 25*time.Millisecond)
		err = db.Health(waiting)
		stop()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("request pool was not exhausted", err)
		}
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for range fixtures {
		if err := awaitIntegrationResult(t, ctx, done); err != nil {
			t.Fatal(err)
		}
	}
	for _, db := range pools {
		if operations, truncated := db.activity.snapshot(time.Now()); len(operations) != 0 || truncated {
			t.Fatal("completed SQL retained local operations", operations)
		}
	}
}
