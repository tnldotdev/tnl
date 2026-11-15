package state

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// this is a bounded database workload, not a cadence or soak test. certificate
// material is signed locally; ingress observers exercise real service admission.
func TestLoadSteadyState(t *testing.T) {
	setupStarted := time.Now()
	f := newControlLoadFixture(t)
	sessions := readySteadyLoadSessions(t, f)
	var ingresses [2]IngressLease
	for index := range ingresses {
		lease, err := f.database.RegisterIngress(t.Context(), IngressRegistration{
			IngressID: fmt.Sprintf("load-ingress-%d", index), IngressRunID: "load-run", ProtocolVersion: 1,
			HTTPS: true, IngressPoolID: PrimaryIngressPoolID, ConnectionCapacity: uint64(max(64, f.routes)),
		}, f.now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		ingresses[index] = lease
	}
	t.Logf("setup_ready=%d relays=4 ingresses=2 setup_elapsed=%s (no injected SQL delay)", len(sessions), time.Since(setupStarted))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	var heartbeats atomic.Int64
	f.startMetrics(t)
	started := time.Now()
	defer func() {
		t.Logf("heartbeats=%d/%d workers=64 elapsed=%s", heartbeats.Load(), 3*f.routes, time.Since(started))
		f.logStats(t)
	}()
	var first sync.Once
	var firstErr error
	fail := func(err error) { first.Do(func() { firstErr = err; cancel() }) }
	start := make(chan struct{})
	var work sync.WaitGroup
	work.Add(64)
	for worker := range 64 {
		workers.Go(func() {
			defer work.Done()
			<-start
			for sweep := range 3 {
				for index := worker; index < len(sessions) && ctx.Err() == nil; index += 64 {
					session := sessions[index]
					callCtx, stop := context.WithTimeout(ctx, 20*time.Second)
					run, err := f.controls[worker%2].HeartbeatServiceRun(callCtx, session.service.ID,
						session.run.RunID, session.run.Token, f.now.Add(time.Duration(sweep+1)*time.Second),
						ServiceRunHealth{Healthy: true, StreamCapacity: 64})
					stop()
					if err != nil {
						fail(fmt.Errorf("heartbeat service=%s sweep=%d: %w", session.service.ID, sweep+1, err))
						return
					}
					if run.ServiceID != session.service.ID || run.RunID != session.run.RunID ||
						run.RunNumber != session.run.RunNumber || run.State != "ready" || len(run.Connections) != 2 {
						fail(fmt.Errorf("heartbeat changed ready service %s", session.service.ID))
						return
					}
					for slot, connection := range run.Connections {
						expected := session.run.Connections[slot]
						if connection.PublisherConnectionID != expected.PublisherConnectionID || connection.Revision != expected.Revision || connection.State != "ready" {
							fail(fmt.Errorf("heartbeat changed service=%s slot=%d", session.service.ID, slot))
							return
						}
					}
					heartbeats.Add(1)
				}
			}
		})
	}
	workDone := make(chan struct{})
	workers.Go(func() { work.Wait(); close(workDone) })
	now := f.now.Add(3 * time.Second)
	for index, ingress := range ingresses {
		workers.Go(func() {
			<-start
			if err := observeSteadyLoad(t, ctx, f.controls[index], ingress.IngressLeaseIdentity, sessions, now, workDone); err != nil {
				fail(fmt.Errorf("admission/renewal ingress=%d: %w", index, err))
			}
		})
	}
	close(start)
	workers.Wait()
	if firstErr != nil || ctx.Err() != nil {
		t.Fatalf("steady workload: %v (context %v)", firstErr, ctx.Err())
	}
	if heartbeats.Load() != int64(3*f.routes) {
		t.Fatal("incomplete heartbeat workload")
	}
	// verify every durable tuple, not just successful calls or a global count.
	expected := make(map[string]ServiceRunState, len(sessions))
	for _, session := range sessions {
		expected[session.service.ID] = session.run
	}
	rows, err := f.database.pool.Query(ctx, `SELECT service_id,run_number,id,
		(state='ready' AND healthy AND closed_at IS NULL AND publisher_expires_at>$1) IS TRUE
		FROM control.service_runs`, now)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var service, id string
		var number int64
		var live bool
		if err := rows.Scan(&service, &number, &id, &live); err != nil {
			t.Fatal(err)
		}
		run, found := expected[service]
		if !found || run.RunID != id || run.RunNumber != number || !live {
			t.Fatalf("unexpected durable service tuple: service=%s run=%s number=%d live=%t", service, id, number, live)
		}
		delete(expected, service)
	}
	if err := rows.Err(); err != nil || len(expected) != 0 {
		t.Fatalf("incomplete durable verification: missing=%d err=%v", len(expected), err)
	}
	assertAssignmentTotals(t, f.database.pool, int64(f.routes)*2)
}

func readySteadyLoadSessions(t *testing.T, f *controlLoadFixture) []servicePublicationFixture {
	t.Helper()
	return readyLoadSessions(t, f, time.Hour, time.Hour)
}

func readyLoadSessions(t *testing.T, f *controlLoadFixture, publisherLease, credentialLifetime time.Duration) []servicePublicationFixture {
	t.Helper()
	sessions := make([]servicePublicationFixture, 0, f.routes)
	started := time.Now()
	defer func() { t.Logf("ready_setup_completed=%d/%d elapsed=%s", len(sessions), f.routes, time.Since(started)) }()
	for index := range f.routes {
		session := servicePublicationFixture{database: f.database, now: f.now, service: f.services[index],
			publisher: f.publishers[index], leases: make(map[string]RelayLease)}
		for service, choices := range f.leases {
			session.leases[service] = choices[index%len(choices)]
		}
		session.start(t, "load", f.now)
		installPrivateTestCertificate(t, f.database, session.prepared, session.run, f.now)
		session.readyConnections(t, f.now)
		for range f.history {
			ready, err := f.database.HeartbeatServiceRun(t.Context(), session.service.ID, session.run.RunID,
				session.run.Token, f.now, ServiceRunHealth{Healthy: true, StreamCapacity: 64})
			if err != nil || ready.State != "ready" || len(ready.Connections) != 2 {
				t.Fatal("service fixture did not become ready", ready, err)
			}
			ready.Token = session.run.Token
			session.run = ready
		}
		// synthetic initial deadlines keep these finite workloads separate from
		// real-clock cadence tests. later heartbeats use the production lifetime.
		until := f.now.Add(publisherLease)
		if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.service_runs SET publisher_expires_at=$2 WHERE id=$1`, session.run.RunID, until); err != nil {
			t.Fatal(err)
		}
		if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.service_connection_slots SET credential_expires_at=$2 WHERE service_run_id=$1`,
			session.run.RunID, f.now.Add(credentialLifetime)); err != nil {
			t.Fatal(err)
		}
		session.run.ExpiresAt = until
		for index := range session.run.Connections {
			session.run.Connections[index].CredentialExpiresAt = f.now.Add(credentialLifetime)
		}
		sessions = append(sessions, session)
	}
	return sessions
}

func observeSteadyLoad(t *testing.T, ctx context.Context, control *Database, ingress IngressLeaseIdentity, sessions []servicePublicationFixture, now time.Time, workDone <-chan struct{}) error {
	var admissions, renewals int
	defer func() { t.Logf("ingress=%s admissions=%d renewals=%d", ingress.IngressID, admissions, renewals) }()
	for ctx.Err() == nil {
		finished := false
		select {
		case <-workDone:
			finished = true
		default:
		}
		for _, session := range sessions {
			callCtx, stop := context.WithTimeout(ctx, 20*time.Second)
			err := observeLoadService(callCtx, control, ingress, session, now)
			stop()
			if err != nil {
				return err
			}
			admissions++
		}
		callCtx, stop := context.WithTimeout(ctx, 20*time.Second)
		lease, err := control.RenewIngress(callCtx, IngressRenewal{IngressLeaseIdentity: ingress}, now, time.Hour)
		stop()
		if err != nil || lease.IngressLeaseIdentity != ingress || !lease.LeaseExpiresAt.After(now) {
			return fmt.Errorf("ingress renewal changed identity or expired: %v", err)
		}
		renewals++
		if finished {
			return nil
		}
		select {
		case <-ctx.Done():
		case <-workDone:
		case <-time.After(100 * time.Millisecond):
		}
	}
	return ctx.Err()
}

func observeLoadService(ctx context.Context, control *Database, ingress IngressLeaseIdentity, session servicePublicationFixture, now time.Time) (result error) {
	visitor, err := opaqueid.New(opaqueid.VisitorConnectionPrefix)
	if err != nil {
		return err
	}
	admission, err := control.AdmitPublicServiceVisitor(ctx, ingress, PrimaryIngressPoolID, visitor,
		session.service.Endpoint.Hostname, 443, netip.MustParseAddr("192.0.2.10"), now)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		result = errors.Join(result, control.ClosePublicServiceVisitor(cleanup, ingress, visitor, now))
	}()
	if admission.ServiceID != session.service.ID || admission.RunID != session.run.RunID ||
		admission.RunNumber != session.run.RunNumber || !admission.ExpiresAt.After(now) || len(admission.Relays) != 2 {
		return fmt.Errorf("admission changed ready service %s", session.service.ID)
	}
	for _, relay := range admission.Relays {
		matched := false
		for _, slot := range session.run.Connections {
			lease := session.leases[slot.RelayServiceID]
			matched = matched || relay.PublisherConnectionID == slot.PublisherConnectionID &&
				relay.ConnectionAssignmentRevision == slot.Revision && relay.ConnectionSlot == slot.ConnectionSlot &&
				relay.RelayServiceID == slot.RelayServiceID && relay.RelayID == lease.RelayID &&
				relay.RelayRunID == lease.RelayRunID && relay.RelayLeaseRevision == int64(lease.RelayLeaseRevision)
		}
		if !matched {
			return fmt.Errorf("admission changed a connected relay for service %s", session.service.ID)
		}
	}
	status, err := control.PublicServiceVisitorStatus(ctx, ingress, visitor, now)
	if err != nil || status.State != PublicServiceVisitorPending || !status.ValidUntil.Equal(admission.ExpiresAt) {
		return fmt.Errorf("admission changed its pending deadline for service %s: %w", session.service.ID, err)
	}
	return nil
}
