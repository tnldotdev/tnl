package state

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

func TestIntegrationPublishRunCreation(t *testing.T) {
	f := newServicePublicationFixture(t)
	if f.run.ServiceID != f.service.ID || f.run.RunNumber != 1 || f.run.State != "starting" || f.run.Token == "" {
		t.Fatal("start lost the service identity, run number, or credential")
	}
	services := map[string]bool{}
	for index, connection := range f.run.Connections {
		if int(connection.ConnectionSlot) != index || connection.Revision != 1 {
			t.Fatal("start lost the exact connection slot")
		}
		if _, err := credentials.ParsePublisherConnectionCredential(credentials.PublisherConnectionCredential(connection.Credential)); err != nil {
			t.Fatal(err)
		}
		services[connection.RelayServiceID] = true
	}
	if len(services) != 2 {
		t.Fatal("start did not assign distinct relay services")
	}
	repeated, err := f.database.StartServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.RunNumber, f.publisher, f.now)
	if err != nil || repeated.Token != f.run.Token || repeated.VisitorSourceKey == [32]byte{} ||
		repeated.VisitorSourceKey != f.run.VisitorSourceKey || !reflect.DeepEqual(repeated.Connections, f.run.Connections) {
		t.Fatal("start replay changed its run or assignment credentials", err)
	}
	changed := f.service.ServiceMetadata
	changed.Protocol = "tcp"
	if _, err := f.database.PrepareServiceRun(t.Context(), f.service.ID, f.publisher, "changed", f.now, ServiceRunRequest{Metadata: changed}); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("run preparation changed saved protocol approval", err)
	}
	if _, err := f.database.PrepareServiceRun(t.Context(), f.service.ID, f.publisher, "second", f.now, ServiceRunRequest{Metadata: f.service.ServiceMetadata}); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("one publisher joined the same service twice", err)
	}
	if err := f.database.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	request := ServiceRunRequest{Metadata: f.service.ServiceMetadata}
	prepared, err := f.database.PrepareServiceRun(t.Context(), f.service.ID, f.publisher, "prepared-retry", f.now, request)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := f.database.PrepareServiceRun(t.Context(), f.service.ID, f.publisher, "prepared-retry", f.now.Add(time.Second), request)
	if err != nil || !reflect.DeepEqual(prepared, retry) {
		t.Fatal("preparation replay changed the captured plan or deadline", err)
	}
	request.PreferredRegions = []string{"aws:us-east-1"}
	if _, err := f.database.PrepareServiceRun(t.Context(), f.service.ID, f.publisher, "prepared-retry", f.now, request); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("preparation replay changed placement intent", err)
	}
}

func TestIntegrationPublishRunExpiryAndGatedReplay(t *testing.T) {
	f := newServicePublicationFixture(t)
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.maintenance_controls SET allowed=false,revision=revision+1,updated_at=$1,updated_by='test' WHERE operation='service_run_creation'`, f.now); err != nil {
		t.Fatal(err)
	}
	// existing bounded work remains usable while new run creation is gated.
	if _, err := f.database.StartServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.RunNumber, f.publisher, f.now); err != nil {
		t.Fatal(err)
	}
	expiredAt := f.now.Add(time.Minute)
	// maintenance gates new work, not the run's issued serving authority.
	// persist the original one-minute expiry independently of publisher liveness.
	setExpirationProgressServingDeadline(t, &f, expiredAt)
	before := expirationProgressSnapshot(t, t.Context(), f.database, f.run.RunID)
	if count, err := f.database.ExpireServiceRuns(t.Context(), f.now.Add(45*time.Second)); err != nil || count != 0 {
		t.Fatal("gated cleanup confused publisher liveness with serving expiry", count, err)
	}
	if after := expirationProgressSnapshot(t, t.Context(), f.database, f.run.RunID); after != before {
		t.Fatal("gated liveness-only cleanup changed existing run authority")
	}
	assertAssignmentTotals(t, f.database.pool, 2)
	if count, err := f.database.ExpireServiceRuns(t.Context(), expiredAt); err != nil || count != 1 {
		t.Fatal("gated cleanup did not expire the run", count, err)
	}
	assertExpirationProgressClosed(t, t.Context(), f.database, f.run.RunID)
	assertAssignmentTotals(t, f.database.pool, 0)
	if _, err := f.database.StartServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.RunNumber, f.publisher, expiredAt); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("gated replay revived expired publication authority", err)
	}
	request := ServiceRunRequest{Metadata: f.service.ServiceMetadata}
	if _, err := f.database.PrepareServiceRun(t.Context(), f.service.ID, f.publisher, "replacement", expiredAt, request); !errors.Is(err, ErrServiceRunCreationGated) {
		t.Fatal("new run bypassed maintenance control", err)
	}
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.maintenance_controls SET allowed=true,revision=revision+1,updated_at=$1,updated_by='test' WHERE operation='service_run_creation'`, expiredAt); err != nil {
		t.Fatal(err)
	}
	f.start(t, "replacement", expiredAt)
	if f.run.RunNumber != 2 {
		t.Fatal("failed creation consumed a run number")
	}
}

func TestIntegrationPublishRunPlacementRequiresAvailableServices(t *testing.T) {
	f := newServicePublicationFixture(t)
	if err := f.database.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	prepared, err := f.database.PrepareServiceRun(t.Context(), f.service.ID, f.publisher, "placement", f.now, ServiceRunRequest{Metadata: f.service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.relay_leases SET draining=true,drain_deadline=$1`, f.now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.StartServiceRun(t.Context(), f.service.ID, prepared.RunID, prepared.RunNumber, f.publisher, f.now); !errors.Is(err, ErrInsufficientRelayServices) {
		t.Fatal("draining placement accepted", err)
	}
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.relay_leases SET draining=false,drain_deadline=NULL`); err != nil {
		t.Fatal(err)
	}
	run, err := f.database.StartServiceRun(t.Context(), f.service.ID, prepared.RunID, prepared.RunNumber, f.publisher, f.now)
	if err != nil || run.RunNumber != prepared.RunNumber {
		t.Fatal("placement retry changed the prepared run", err)
	}
}

func TestIntegrationPublishRunReplacesExpiredSession(t *testing.T) {
	f := newServicePublicationFixture(t)
	old := f.run
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.service_runs SET publisher_expires_at=$2 WHERE id=$1`, old.RunID, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	f.start(t, "replacement", f.now.Add(2*time.Second))
	if f.run.RunNumber != 2 || f.run.RunID == old.RunID || f.run.Token == old.Token {
		t.Fatal("replacement reused an expired run identity")
	}
	var closed bool
	if err := f.database.pool.QueryRow(t.Context(), `SELECT state='closed' AND closed_at IS NOT NULL AND NOT assignments_open FROM control.service_runs WHERE id=$1`, old.RunID).Scan(&closed); err != nil || !closed {
		t.Fatal("replacement retained the expired run's relay authority", err)
	}
}

func TestIntegrationPublishRunCreationRollsBackBothAssignmentsAndVersion(t *testing.T) {
	f := newServicePublicationFixture(t)
	if err := f.database.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	prepared, err := f.database.PrepareServiceRun(t.Context(), f.service.ID, f.publisher, "rollback", f.now, ServiceRunRequest{Metadata: f.service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.pool.Exec(t.Context(), `ALTER TABLE control.service_connection_slots ADD CONSTRAINT reject_second_slot CHECK(connection_slot<>1 OR NOT session_open)`); err != nil {
		t.Fatal(err)
	}
	_, err = f.database.StartServiceRun(t.Context(), f.service.ID, prepared.RunID, prepared.RunNumber, f.publisher, f.now)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.ConstraintName != "reject_second_slot" {
		t.Fatal("second assignment did not fail at the selected boundary", err)
	}
	var unchanged bool
	err = f.database.pool.QueryRow(t.Context(), `SELECT run.state='prepared' AND run.started_at IS NULL AND service.next_run_number=$2+1
		AND NOT EXISTS(SELECT 1 FROM control.service_connection_slots WHERE service_run_id=run.id)
		AND NOT EXISTS(SELECT 1 FROM control.service_audit_events WHERE run_id=run.id AND event_type='run.start')
		FROM control.service_runs run JOIN control.services service ON service.id=run.service_id WHERE run.id=$1`, prepared.RunID, prepared.RunNumber).Scan(&unchanged)
	if err != nil || !unchanged {
		t.Fatal("failed start left assignments, a start audit, or changed its run number", err)
	}
	if _, err := f.database.pool.Exec(t.Context(), `ALTER TABLE control.service_connection_slots DROP CONSTRAINT reject_second_slot`); err != nil {
		t.Fatal(err)
	}
	f.prepared = prepared
	f.run, err = f.database.StartServiceRun(t.Context(), f.service.ID, prepared.RunID, prepared.RunNumber, f.publisher, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.readyConnections(t, f.now)
}

func TestIntegrationPublishRunCreationRejectsExhaustedCounters(t *testing.T) {
	f := newServicePublicationFixture(t)
	if err := f.database.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.services SET next_run_number=$2 WHERE id=$1`, f.service.ID, int64(math.MaxInt64)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.PrepareServiceRun(t.Context(), f.service.ID, f.publisher, "exhausted", f.now, ServiceRunRequest{Metadata: f.service.ServiceMetadata}); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("exhausted run counter accepted", err)
	}
	var unchanged bool
	if err := f.database.pool.QueryRow(t.Context(), `SELECT next_run_number=$2 AND NOT EXISTS(SELECT 1 FROM control.service_runs WHERE service_id=$1 AND closed_at IS NULL) FROM control.services WHERE id=$1`, f.service.ID, int64(math.MaxInt64)).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("exhausted preparation changed saved authority", err)
	}
}

func TestIntegrationPublishRunReadiness(t *testing.T) {
	f := newServicePublicationFixture(t)
	health := ServiceRunHealth{Healthy: true, StreamCapacity: 64}
	check := func(state string) {
		t.Helper()
		result, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now, health)
		if err != nil || result.State != state {
			t.Fatal("readiness skipped a certificate or connection prerequisite", result.State, err)
		}
	}
	check("starting")
	f.readyConnection(t, 0, f.now)
	work := createPlanIssuanceWork(t, f.database, f.now, f.run, f.prepared.CertificatePlan, true, nil)
	if err := f.database.MarkServiceCertificateInstalled(t.Context(), f.service.ID, f.run.RunID, f.run.Token, work.ID, f.run.RunNumber, *work.NotAfter, f.now); err != nil {
		t.Fatal(err)
	}
	check("starting")
	if issued, err := f.database.GetServiceCertificateIssuance(t.Context(), f.service.ID, f.run.RunID, f.run.Token, work.ID, f.now); err != nil || issued.State != "installed" {
		t.Fatal("certificate acknowledgement was not durable", err)
	}
	if err := f.database.MarkServiceCertificateInstalled(t.Context(), f.service.ID, f.run.RunID, f.run.Token, "issuance_other", f.run.RunNumber, *work.NotAfter, f.now); !errors.Is(err, ErrCertificateIssuanceNotFound) {
		t.Fatal("another issuance was acknowledged", err)
	}
	f.readyConnection(t, 1, f.now)
	check("ready")
	var firstReadyAt time.Time
	if err := f.database.pool.QueryRow(t.Context(), `SELECT ready_at FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&firstReadyAt); err != nil {
		t.Fatal(err)
	}
	if err := f.database.MarkServiceCertificateInstalled(t.Context(), f.service.ID, f.run.RunID, f.run.Token, work.ID, f.run.RunNumber, *work.NotAfter, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var stable bool
	if err := f.database.pool.QueryRow(t.Context(), `SELECT state='ready' AND ready_at=$2 FROM control.service_runs WHERE id=$1`, f.run.RunID, firstReadyAt).Scan(&stable); err != nil || !stable {
		t.Fatal("install replay changed first readiness", err)
	}
}

func TestIntegrationPublishRunHeartbeatPreservesConnectionsAndExpiry(t *testing.T) {
	f := newServicePublicationFixture(t)
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.services SET ephemeral=true WHERE id=$1`, f.service.ID); err != nil {
		t.Fatal(err)
	}
	if count, err := f.database.ExpireServiceRuns(t.Context(), f.now.Add(2*time.Second)); err != nil || count != 0 {
		t.Fatal("active ephemeral service was removed", count, err)
	}
	f.readyConnections(t, f.now)
	at := f.now.Add(3 * time.Second)
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.service_connection_slots SET credential_expires_at=$2 WHERE service_run_id=$1`, f.run.RunID, at.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	heartbeat, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, at, ServiceRunHealth{StreamCapacity: 64})
	if err != nil || !heartbeat.ExpiresAt.Equal(at.Add(45*time.Second)) {
		t.Fatal("heartbeat did not renew the bounded publisher lease", err)
	}
	earlier, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, at.Add(-time.Second), ServiceRunHealth{StreamCapacity: 64})
	if err != nil || !earlier.ExpiresAt.Equal(heartbeat.ExpiresAt) {
		t.Fatal("an older heartbeat shortened an existing lease", err)
	}
	for index, connection := range heartbeat.Connections {
		if connection.PublisherConnectionID != f.run.Connections[index].PublisherConnectionID || connection.Revision != f.run.Connections[index].Revision || connection.State != "ready" {
			t.Fatal("expired bootstrap credential replaced a connected slot")
		}
	}
}

func TestIntegrationHealthyPublishRunHeartbeatSkipsUnrelatedPlacementLock(t *testing.T) {
	f := newServicePublicationFixture(t)
	f.readyConnections(t, f.now)
	installPrivateTestCertificate(t, f.database, f.prepared, f.run, f.now)
	health := ServiceRunHealth{Healthy: true, StreamCapacity: 64}
	if _, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now, health); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.RegisterRelay(t.Context(), relayLifecycleRegistration("placement-unrelated"), f.now, time.Hour); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	gate, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := gate.Exec(ctx, `SELECT relay_service_id FROM control.relay_services WHERE relay_service_id='placement-unrelated' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	workers := newIntegrationWorkers(t, cancel)
	workers.Go(func() {
		result, err := f.database.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.now.Add(time.Second), health)
		if err == nil && !reflect.DeepEqual(result.Connections, f.run.Connections) {
			for i, slot := range result.Connections {
				if slot.PublisherConnectionID != f.run.Connections[i].PublisherConnectionID || slot.Revision != f.run.Connections[i].Revision {
					err = errors.New("healthy heartbeat replaced publisher connections")
					break
				}
			}
		}
		done <- err
	})
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("healthy heartbeat waited for an unrelated relay-service lock")
	}
}

func newPublishRunPrerequisites(t *testing.T) (*Database, time.Time, serviceTestAuthority, map[string]RelayLease) {
	return publishRunPrerequisitesWithRelayKeys(t, nil)
}

func publishRunPrerequisitesWithRelayKeys(t *testing.T, keyForRun func(string) []byte) (*Database, time.Time, serviceTestAuthority, map[string]RelayLease) {
	t.Helper()
	database, now := newControlStateIntegrationDatabase(t, "service_prerequisites")
	return publishRunPrerequisitesInDatabase(t, database, now, keyForRun)
}

func publishRunPrerequisitesInDatabase(t *testing.T, database *Database, now time.Time, keyForRun func(string) []byte) (*Database, time.Time, serviceTestAuthority, map[string]RelayLease) {
	t.Helper()
	authority := seedControlServiceAuthority(t, database, now, "session")
	leases := map[string]RelayLease{}
	for slot := range 2 {
		registration := relayLifecycleRegistration(fmt.Sprintf("placement-%d", slot))
		registration.ConnectionCapacity = 10
		if keyForRun != nil {
			run, err := opaqueid.New(opaqueid.RelayRunPrefix)
			if err != nil {
				t.Fatal(err)
			}
			registration.RelayRunID, registration.PeerSigningPublicKey = run, keyForRun(run)
		}
		lease, err := database.RegisterRelay(t.Context(), registration, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		leases[lease.RelayServiceID] = lease
	}
	return database, now, authority, leases
}

func registerTestIngress(t *testing.T, database *Database, now time.Time) IngressLease {
	t.Helper()
	lease, err := database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "ingress_test", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix), ProtocolVersion: 1, ConnectionCapacity: 100,
		IngressPoolID: PrimaryIngressPoolID, HTTPS: true,
	}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return lease
}
