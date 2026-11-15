package state

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// a database-state model of one relay restart, not a process-crash or visitor
// recovery test. two ingress observers admit visitors through the surviving
// relay before replacement, then verify current ready assignments after joining.
func TestLoadRelayRecovery(t *testing.T) {
	f := newControlLoadFixture(t)
	if f.routes < 2 {
		t.Fatal("relay recovery requires at least two services for affected and healthy work")
	}
	sessions := readySteadyLoadSessions(t, f)
	failed := sessions[0].leases[sessions[0].run.Connections[0].RelayServiceID]
	var affected, unaffected []int
	current := make([]ServiceRunState, f.routes)
	for index, session := range sessions {
		current[index] = session.run
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
			HTTPS: true, IngressPoolID: PrimaryIngressPoolID, ConnectionCapacity: uint64(max(64, f.routes)),
		}, f.now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		ingresses[index] = lease
		for _, session := range sessions {
			if err := observeLoadService(t.Context(), f.database, lease.IngressLeaseIdentity, session, f.now); err != nil {
				t.Fatal("initial admission", err)
			}
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	var recovered, healthyServices, heartbeats atomic.Int64
	recoveryTimes := make([]time.Duration, f.routes)
	f.startMetrics(t)
	started := time.Now()
	defer func() {
		var total, maximum time.Duration
		for _, elapsed := range recoveryTimes {
			total += elapsed
			maximum = max(maximum, elapsed)
		}
		t.Logf("affected=%d recovered=%d unaffected_verified=%d/%d healthy_heartbeats=%d workflows=64 elapsed=%s",
			len(affected), recovered.Load(), healthyServices.Load(), len(unaffected), heartbeats.Load(), time.Since(started))
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
	restartReady := make(chan struct{})
	backgroundReady := make(chan struct{}, 1+len(ingresses))
	var work sync.WaitGroup
	work.Add(64)
	var restarted RelayLease // restartReady publishes this value.
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
				run, err := recoverLoadRelaySlot(ctx, f.controls[worker%2], sessions[index], failed, restarted, now)
				if err != nil {
					fail(fmt.Errorf("recover service=%s: %w", sessions[index].service.ID, err))
					return
				}
				current[index], recoveryTimes[index] = run, time.Since(began)
				if recovered.Add(1) == int64(len(affected)) {
					t.Logf("all_slots_ready_elapsed=%s healthy_heartbeats=%d", time.Since(started), heartbeats.Load())
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
					at := now.Add(time.Since(started))
					run, err := f.controls[worker%2].HeartbeatServiceRun(callCtx, session.service.ID, session.run.RunID,
						session.run.Token, at, ServiceRunHealth{Healthy: true, StreamCapacity: 64})
					stop()
					if err != nil || run.ServiceID != session.service.ID || run.RunID != session.run.RunID ||
						run.RunNumber != session.run.RunNumber || run.State != "ready" || !run.Healthy || !run.ExpiresAt.After(at) ||
						!reflect.DeepEqual(run.Connections, session.run.Connections) {
						fail(fmt.Errorf("healthy heartbeat changed service=%s: %v", session.service.ID, err))
						return
					}
					if sweep == 0 {
						healthyServices.Add(1)
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
	workDone := make(chan struct{})
	workers.Go(func() { work.Wait(); close(workDone) })
	for index, ingress := range ingresses {
		workers.Go(func() {
			if err := observeRecoveryLoad(t, ctx, f.controls[index], ingress.IngressLeaseIdentity, sessions, failed, now, workDone, backgroundReady); err != nil {
				fail(fmt.Errorf("admission/renewal ingress=%d: %w", index, err))
			}
		})
	}
	// each observer must see every affected service on its surviving relay
	// before recovery can begin; goroutine startup alone is not progress.
	for range 1 + len(ingresses) {
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
	t.Logf("relay_restarted_elapsed=%s healthy_heartbeats=%d", time.Since(started), heartbeats.Load())
	close(restartReady)
	workers.Wait()
	if firstErr != nil || ctx.Err() != nil || recovered.Load() != int64(len(affected)) || healthyServices.Load() != int64(len(unaffected)) {
		t.Fatalf("incomplete recovery workload: %v context=%v", firstErr, ctx.Err())
	}
	verificationStarted := time.Now()
	verifyAt := now.Add(time.Since(started))
	for index, session := range sessions {
		session.run = current[index]
		if session.leases[failed.RelayServiceID].RelayID == failed.RelayID {
			session.leases = cloneLoadLeases(session.leases)
			session.leases[failed.RelayServiceID] = restarted
		}
		for _, ingress := range ingresses {
			if err := observeLoadService(ctx, f.database, ingress.IngressLeaseIdentity, session, verifyAt); err != nil {
				t.Fatal("final current assignment admission", err)
			}
		}
		var matches bool
		err := f.database.pool.QueryRow(ctx, `SELECT service_id=$2 AND run_number=$3 AND state='ready' AND healthy
			AND closed_at IS NULL AND publisher_expires_at>$4 AND ready_at=$5
			FROM control.service_runs WHERE id=$1`, session.run.RunID, session.service.ID, session.run.RunNumber, verifyAt, f.now).Scan(&matches)
		if err != nil || !matches {
			t.Fatalf("recovery changed durable run identity/readiness service=%s: %v", session.service.ID, err)
		}
	}
	assertAssignmentTotals(t, f.database.pool, int64(f.routes)*2)
	t.Logf("verified_service_runs=%d final_admissions=%d verification_elapsed=%s", f.routes, 2*f.routes, time.Since(verificationStarted))
}

func cloneLoadLeases(before map[string]RelayLease) map[string]RelayLease {
	after := make(map[string]RelayLease, len(before))
	for id, lease := range before {
		after[id] = lease
	}
	return after
}

func observeRecoveryLoad(t *testing.T, ctx context.Context, control *Database, ingress IngressLeaseIdentity, sessions []servicePublicationFixture, failed RelayLease, now time.Time, workDone <-chan struct{}, backgroundReady chan<- struct{}) error {
	previous := make([][2]int64, len(sessions))
	var sweeps, admissions, degraded, renewals int
	defer func() {
		t.Logf("ingress=%s sweeps=%d admissions=%d degraded_observations=%d renewals=%d", ingress.IngressID, sweeps, admissions, degraded, renewals)
	}()
	for ctx.Err() == nil {
		finished := false
		select {
		case <-workDone:
			finished = true
		default:
		}
		for index, session := range sessions {
			callCtx, stop := context.WithTimeout(ctx, 20*time.Second)
			admission, err := readLoadAdmission(callCtx, control, ingress, session, now)
			stop()
			if err != nil {
				return err
			}
			affected := session.leases[failed.RelayServiceID].RelayID == failed.RelayID
			if sweeps == 0 && affected && len(admission.Relays) != 1 {
				return fmt.Errorf("first failure observation did not retain exactly one survivor: %s", session.service.ID)
			}
			var slots [2]bool
			for _, relay := range admission.Relays {
				slot := relay.ConnectionSlot
				if slot < 0 || slot >= 2 || slots[slot] || relay.ConnectionAssignmentRevision < previous[index][slot] ||
					!relay.LeaseExpiresAt.After(now) || relay.RelayID == failed.RelayID && relay.RelayRunID == failed.RelayRunID {
					return fmt.Errorf("admission used duplicate, stale, or expired relay for %s", session.service.ID)
				}
				slots[slot] = true
				before := session.run.Connections[slot]
				lease := session.leases[before.RelayServiceID]
				if lease.RelayID != failed.RelayID {
					if relay.PublisherConnectionID != before.PublisherConnectionID || relay.ConnectionAssignmentRevision != before.Revision ||
						relay.RelayServiceID != before.RelayServiceID || relay.RelayID != lease.RelayID || relay.RelayRunID != lease.RelayRunID || relay.RelayLeaseRevision != int64(lease.RelayLeaseRevision) {
						return fmt.Errorf("admission changed surviving slot service=%s slot=%d", session.service.ID, slot)
					}
				} else if relay.ConnectionAssignmentRevision <= before.Revision || relay.PublisherConnectionID == before.PublisherConnectionID ||
					relay.RelayServiceID != before.RelayServiceID || relay.RelayID != failed.RelayID || relay.RelayLeaseRevision <= int64(failed.RelayLeaseRevision) {
					return fmt.Errorf("admission used stale replacement service=%s", session.service.ID)
				}
				previous[index][slot] = relay.ConnectionAssignmentRevision
			}
			for _, slot := range session.run.Connections {
				if session.leases[slot.RelayServiceID].RelayID != failed.RelayID && !slots[slot.ConnectionSlot] {
					return fmt.Errorf("admission lost surviving slot service=%s", session.service.ID)
				}
			}
			if len(admission.Relays) == 1 {
				degraded++
			}
			admissions++
		}
		lease, err := control.RenewIngress(ctx, IngressRenewal{IngressLeaseIdentity: ingress}, now, time.Hour)
		if err != nil || lease.IngressLeaseIdentity != ingress || !lease.LeaseExpiresAt.After(now) {
			return fmt.Errorf("ingress renewal changed identity/deadline: %v", err)
		}
		renewals++
		sweeps++
		if sweeps == 1 {
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

func recoverLoadRelaySlot(ctx context.Context, control *Database, session servicePublicationFixture, failed, restarted RelayLease, now time.Time) (ServiceRunState, error) {
	callCtx, stop := context.WithTimeout(ctx, 20*time.Second)
	run, err := control.HeartbeatServiceRun(callCtx, session.service.ID, session.run.RunID, session.run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64})
	stop()
	if err != nil {
		return run, fmt.Errorf("replenish: %w", err)
	}
	run.Token = session.run.Token
	if run.ServiceID != session.service.ID || run.RunID != session.run.RunID || run.RunNumber != session.run.RunNumber ||
		run.State != "ready" || !run.Healthy || !run.ExpiresAt.After(now) || len(run.Connections) != 2 {
		return run, errors.New("replenishment changed the ready service run")
	}
	for slot, connection := range run.Connections {
		before := session.run.Connections[slot]
		if session.leases[before.RelayServiceID].RelayLeaseIdentity != failed.RelayLeaseIdentity {
			if connection != before {
				return run, fmt.Errorf("replenishment changed surviving slot=%d", slot)
			}
			continue
		}
		if connection.ConnectionSlot != int16(slot) || connection.RelayServiceID != before.RelayServiceID ||
			connection.Revision <= before.Revision || connection.PublisherConnectionID == before.PublisherConnectionID ||
			connection.Credential == before.Credential || connection.State != "assigned" || !connection.CredentialExpiresAt.After(now) {
			return run, fmt.Errorf("missing fresh replacement slot=%d", slot)
		}
		for _, stale := range []struct {
			slot  ServiceRunAssignment
			lease RelayLeaseIdentity
		}{{connection, failed.RelayLeaseIdentity}, {before, restarted.RelayLeaseIdentity}} {
			callCtx, stop = context.WithTimeout(ctx, 20*time.Second)
			_, err = control.ClaimServicePublisherConnection(callCtx, stale.slot.PublisherConnectionID, session.service.ID, run.RunID, run.RunNumber,
				stale.slot.Revision, stale.slot.Credential, netip.MustParseAddr("127.0.0.1"), stale.lease, now)
			stop()
			if !errors.Is(err, ErrServiceAccess) {
				return run, fmt.Errorf("stale relay/assignment claim was not rejected: %v", err)
			}
		}
		callCtx, stop = context.WithTimeout(ctx, 20*time.Second)
		claimed, err := control.ClaimServicePublisherConnection(callCtx, connection.PublisherConnectionID, session.service.ID, run.RunID, run.RunNumber,
			connection.Revision, connection.Credential, netip.MustParseAddr("127.0.0.1"), restarted.RelayLeaseIdentity, now)
		stop()
		expected := ServicePublisherConnection{ServiceID: session.service.ID, RunID: run.RunID, RunNumber: run.RunNumber,
			ConnectionID: connection.PublisherConnectionID, Revision: connection.Revision, RelayServiceID: connection.RelayServiceID}
		if err != nil || claimed != expected {
			return run, fmt.Errorf("replacement claim changed identity: %v", err)
		}
		callCtx, stop = context.WithTimeout(ctx, 20*time.Second)
		ready, err := control.ReadyServicePublisherConnection(callCtx, connection.PublisherConnectionID, run.RunID, run.RunNumber,
			connection.Revision, restarted.RelayLeaseIdentity, now)
		stop()
		if err != nil || ready != expected {
			return run, fmt.Errorf("replacement readiness changed identity: %v", err)
		}
		run.Connections[slot].State = "ready"
	}
	return run, nil
}
