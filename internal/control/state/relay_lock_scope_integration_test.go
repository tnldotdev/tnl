package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationPublisherConnectionsShareRelayServiceGuard(t *testing.T) {
	for _, operation := range []string{"claim", "ready"} {
		t.Run(operation, func(t *testing.T) {
			fixtures, registration := relayScopeSessions(t)
			database, now := fixtures[0].database, fixtures[0].now
			connections := []relayScopeConnection{
				relayScopeSlot(t, fixtures[0], registration.RelayServiceID),
				relayScopeSlot(t, fixtures[1], registration.RelayServiceID),
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			if operation == "ready" {
				for _, connection := range connections {
					if err := connection.claim(ctx); err != nil {
						t.Fatal(err)
					}
				}
			}
			perform := func(ctx context.Context, connection relayScopeConnection) error {
				if operation == "ready" {
					return connection.ready(ctx)
				}
				return connection.claim(ctx)
			}
			gate, err := database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err := gate.Exec(ctx, `SELECT relay_id FROM control.relay_leases WHERE relay_id=$1 FOR UPDATE`, connections[0].lease.RelayID); err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			first := make(chan error, 1)
			workers.Go(func() { first <- perform(ctx, connections[0]) })
			firstPID := waitForPostgresBlock(t, ctx, database, int32(gate.Conn().PgConn().PID()), first)
			// a blocked process reader retains a shared service guard, not an
			// exclusive guard that prevents another process from claiming.
			independent, stop := context.WithTimeout(ctx, 2*time.Second)
			defer stop()
			if err := perform(independent, connections[1]); err != nil {
				t.Fatalf("another relay process in the same service could not %s: %v", operation, err)
			}
			registered := make(chan error, 1)
			workers.Go(func() {
				_, err := database.RegisterRelay(ctx, registration, now, time.Hour)
				registered <- err
			})
			// registration targets the other process, so this wait proves the
			// service guard rather than contention on the gated process lease.
			waitForPostgresBlock(t, ctx, database, firstPID, registered)
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			for _, done := range []<-chan error{first, registered} {
				if err := awaitIntegrationResult(t, ctx, done); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestIntegrationRelayServiceWritersProgressDuringPublisherRetries(t *testing.T) {
	for _, writer := range []string{"registration", "replenishment", "certificate-store", "certificate-save", "key-rotation"} {
		t.Run(writer, func(t *testing.T) {
			fixtures, registration := relayScopeProgressSessions(t)
			database := fixtures[0].database
			write := relayScopeProgressWriter(t, writer, fixtures, registration)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			gate, err := database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err := gate.Exec(ctx, `SELECT relay_id FROM control.relay_leases WHERE relay_id=$1 FOR UPDATE`, registration.RelayID); err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			failed := make(chan error, len(fixtures)-1)
			stopReaders := make(chan struct{})
			var retries atomic.Int64
			var readerPIDs []int32
			blocker := int32(gate.Conn().PgConn().PID())
			for _, fixture := range fixtures[:len(fixtures)-1] {
				connection := relayScopeSlot(t, fixture, registration.RelayServiceID)
				workers.Go(func() {
					if err := connection.claim(ctx); err != nil {
						if ctx.Err() == nil || !failure.Only(err, ctx.Err()) {
							failed <- err
						}
						return
					}
					ready := false
					for ctx.Err() == nil {
						if ready {
							select {
							case <-stopReaders:
								return
							default:
							}
						}
						err := connection.ready(ctx)
						if ctx.Err() != nil && failure.Only(err, ctx.Err()) {
							return
						}
						if err != nil {
							failed <- fmt.Errorf("readiness retry ready=%t: %v", ready, err)
							return
						}
						ready = true
						// exact readiness retries retain the same service/run/slot
						// tuple while taking the relay service guard.
						retries.Add(1)
					}
				})
				blocker = waitForPostgresBlock(t, ctx, database, blocker, failed)
				readerPIDs = append(readerPIDs, blocker)
			}
			writerCtx, stop := context.WithTimeout(ctx, 2*time.Second)
			defer stop()
			written := make(chan error, 1)
			workers.Go(func() { written <- write(writerCtx) })
			waitForPostgresBlock(t, ctx, database, readerPIDs[0], written, readerPIDs[1:]...)
			started := time.Now()
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			err = awaitIntegrationResult(t, ctx, written)
			elapsed := time.Since(started)
			close(stopReaders)
			workers.Wait()
			select {
			case failure := <-failed:
				t.Fatal(failure)
			default:
			}
			if err != nil {
				t.Fatalf("%s failed to progress in %s after %d claim/readiness retries: %v", writer, elapsed, retries.Load(), err)
			}
			for _, fixture := range fixtures[:len(fixtures)-1] {
				connection := relayScopeSlot(t, fixture, registration.RelayServiceID)
				var current bool
				err := database.pool.QueryRow(t.Context(), `SELECT state='ready' AND session_open AND service_run_id=$2
					AND service_id=$3 AND run_number=$4 AND connection_assignment_revision=$5
					AND relay_service_id=$6 AND relay_id=$7 AND relay_run_id=$8 AND relay_lease_revision=$9
					FROM control.service_connection_slots WHERE publisher_connection_id=$1`, connection.slot.PublisherConnectionID,
					fixture.run.RunID, fixture.service.ID, fixture.run.RunNumber, connection.slot.Revision,
					connection.slot.RelayServiceID, connection.lease.RelayID, connection.lease.RelayRunID, int64(connection.lease.RelayLeaseRevision)).Scan(&current)
				if err != nil || !current {
					t.Fatalf("readiness retries changed the current slot: %v", err)
				}
			}
			t.Logf("%s progressed in %s with %d claim/readiness retries", writer, elapsed, retries.Load())
		})
	}
}

func TestIntegrationRelayServiceMaintenanceSkipsQueuedWriter(t *testing.T) {
	for _, operation := range []string{"certificate-preparation", "bulk-key-rotation"} {
		t.Run(operation, func(t *testing.T) {
			database, databaseURL, now := newControlStateIntegrationDatabaseWithURL(t, "relay_skip_locked")
			registration := relayLifecycleRegistration("relay-a")
			for _, service := range []string{"relay-a", "relay-b"} {
				if _, err := database.RegisterRelay(t.Context(), relayLifecycleRegistration(service), now, time.Hour); err != nil {
					t.Fatal(err)
				}
			}
			var maintain func(context.Context) error
			if operation == "certificate-preparation" {
				account, err := database.EnsureACMEAccount(t.Context(), "https://acme.example.test/directory", "operator@example.test", now)
				if err != nil {
					t.Fatal(err)
				}
				maintain = func(ctx context.Context) error {
					created, err := database.PrepareRelayCertificateOrder(ctx, account.ID, now, time.Hour)
					if err == nil && !created {
						return errors.New("preparation did not reach the unlocked service")
					}
					return err
				}
			} else {
				for _, service := range []string{"relay-a", "relay-b"} {
					candidate := relayLifecycleRegistration(service)
					certificate, key := testRelayCertificate(t, candidate.TLSServerName, now)
					if _, err := database.StoreRelayTransportCertificate(t.Context(), service, candidate.TLSServerName, certificate, key, now); err != nil {
						t.Fatal(err)
					}
				}
				newKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
				rotating, err := Open(t.Context(), databaseURL, newKey, testStorageKey, naming.ManagedURLModeGenerated)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(rotating.Close)
				maintain = func(ctx context.Context) error {
					count, err := rotating.ReencryptStorageSecrets(ctx, 10)
					if err == nil && count != 1 {
						return fmt.Errorf("rotated %d keys, want one unlocked service", count)
					}
					return err
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			reader, err := database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, reader)
			if _, err := controlstatedb.New(reader).GetRelayLeaseForClaim(ctx, registration.RelayID); err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			registered := make(chan error, 1)
			workers.Go(func() {
				_, err := database.RegisterRelay(ctx, registration, now, time.Hour)
				registered <- err
			})
			waitForPostgresBlock(t, ctx, database, int32(reader.Conn().PgConn().PID()), registered)
			// maintenance must actually skip relay-a and finish relay-b while
			// relay-a has both an active reader and a queued service writer.
			maintenanceCtx, stop := context.WithTimeout(ctx, 2*time.Second)
			defer stop()
			if err := maintain(maintenanceCtx); err != nil {
				t.Fatal(err)
			}
			if err := reader.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, registered); err != nil {
				t.Fatal(err)
			}
			if err := maintain(maintenanceCtx); err != nil {
				t.Fatal("skipped service did not become eligible after the writer joined", err)
			}
		})
	}
}

func relayScopeProgressWriter(t *testing.T, writer string, fixtures [5]servicePublicationFixture, registration RelayRegistration) func(context.Context) error {
	t.Helper()
	database, now := fixtures[0].database, fixtures[0].now
	switch writer {
	case "registration":
		return func(ctx context.Context) error {
			lease, err := database.RegisterRelay(ctx, registration, now.Add(time.Second), time.Hour)
			if err == nil && !lease.LeaseExpiresAt.Equal(now.Add(time.Hour+time.Second)) {
				return errors.New("registration did not extend the relay lease")
			}
			return err
		}
	case "replenishment":
		fixture := fixtures[len(fixtures)-1]
		return func(ctx context.Context) error {
			replenished, err := database.HeartbeatServiceRun(ctx, fixture.service.ID, fixture.run.RunID, fixture.run.Token,
				now.Add(2*time.Minute), ServiceRunHealth{Healthy: true, StreamCapacity: 64})
			if err != nil {
				return err
			}
			if replenished.ServiceID != fixture.service.ID || replenished.RunID != fixture.run.RunID ||
				replenished.RunNumber != fixture.run.RunNumber || len(replenished.Connections) != 2 {
				return errors.New("replenishment replaced the service run")
			}
			for slot, connection := range replenished.Connections {
				previous := fixture.run.Connections[slot]
				if connection.PublisherConnectionID == previous.PublisherConnectionID || connection.Revision != previous.Revision+1 ||
					connection.RelayServiceID != previous.RelayServiceID || connection.ConnectionSlot != previous.ConnectionSlot || connection.State != "assigned" {
					return fmt.Errorf("slot %d was not replenished", slot)
				}
			}
			return nil
		}
	case "certificate-save":
		account, err := database.EnsureACMEAccount(t.Context(), "https://acme.example.test/directory", "operator@example.test", now)
		if err != nil {
			t.Fatal(err)
		}
		if created, err := database.PrepareRelayCertificateOrder(t.Context(), account.ID, now, time.Hour); err != nil || !created {
			t.Fatalf("prepare certificate: created %t, error %v", created, err)
		}
		work, found, err := database.ClaimRelayCertificateOrderWork(t.Context(), "progress", now, time.Hour)
		if err != nil || !found || work.RelayServiceID != registration.RelayServiceID {
			t.Fatalf("claim certificate: found %t, service %s, error %v", found, work.RelayServiceID, err)
		}
		certificate, notBefore, notAfter := issueRelayOrderCertificate(t, work, now)
		renewAt := notBefore.Add(notAfter.Sub(notBefore) * 2 / 3)
		work.State, work.CertificatePEM = "complete", certificate
		work.NotBefore, work.NotAfter, work.RenewAt = &notBefore, &notAfter, &renewAt
		return func(ctx context.Context) error {
			saved, err := database.SaveRelayCertificateOrderWork(ctx, work, now)
			if err != nil {
				return err
			}
			if saved.State != "complete" || saved.OrderRevision != work.OrderRevision+1 {
				return errors.New("certificate save did not complete its order")
			}
			installed, err := database.GetRelayTransportCertificate(ctx, fixtures[0].leases[registration.RelayServiceID].RelayLeaseIdentity, now)
			if err == nil && installed.CertificatePEM != string(certificate) {
				return errors.New("certificate save did not install its certificate")
			}
			return err
		}
	case "certificate-store", "key-rotation":
		certificate, key := testRelayCertificate(t, registration.TLSServerName, now)
		if writer == "certificate-store" {
			return func(ctx context.Context) error {
				stored, err := database.StoreRelayTransportCertificate(ctx, registration.RelayServiceID, registration.TLSServerName, certificate, key, now)
				if err == nil && stored.CertificatePEM != string(certificate) {
					return errors.New("certificate store did not install its certificate")
				}
				return err
			}
		}
		if _, err := database.StoreRelayTransportCertificate(t.Context(), registration.RelayServiceID, registration.TLSServerName, certificate, key, now); err != nil {
			t.Fatal(err)
		}
		newKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
		rotating, err := Open(t.Context(), database.pool.Config().ConnConfig.ConnString(), newKey, testStorageKey, naming.ManagedURLModeGenerated)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(rotating.Close)
		return func(ctx context.Context) error {
			rotated, err := rotating.GetRelayTransportCertificate(ctx, fixtures[0].leases[registration.RelayServiceID].RelayLeaseIdentity, now)
			if err != nil {
				return err
			}
			var keyID string
			if err := database.pool.QueryRow(ctx, `SELECT transport_private_key_storage_key_id FROM control.relay_services WHERE relay_service_id=$1`, registration.RelayServiceID).Scan(&keyID); err != nil {
				return err
			}
			if rotated.PrivateKeyPEM != string(key) || keyID != rotating.storageKey.CurrentID() {
				return errors.New("key rotation did not preserve and re-encrypt the private key")
			}
			return nil
		}
	default:
		t.Fatalf("unknown service writer %q", writer)
		return nil
	}
}

// four independent services retry on one process while a fifth needs placement.
// each relay service has exactly five reservations, including the fifth run.
func relayScopeProgressSessions(t *testing.T) ([5]servicePublicationFixture, RelayRegistration) {
	t.Helper()
	database, now := newControlStateIntegrationDatabase(t, "relay_progress")
	leases := make(map[string]RelayLease)
	var registration RelayRegistration
	for _, service := range []string{"relay-a", "relay-b"} {
		candidate := relayLifecycleRegistration(service)
		candidate.ConnectionCapacity = 5
		lease, err := database.RegisterRelay(t.Context(), candidate, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		leases[service] = lease
		if service == "relay-a" {
			registration = candidate
		}
	}
	var fixtures [5]servicePublicationFixture
	for index := range fixtures {
		fixtures[index] = relayScopeService(t, database, now, fmt.Sprintf("progress-%d", index), leases)
	}
	// keep publisher authority live while the fifth run's never-claimed
	// two-minute credentials reach their exact replacement boundary.
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.service_runs SET publisher_expires_at=$1`, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	assertAssignmentTotals(t, database.pool, 10)
	return fixtures, registration
}

func TestIntegrationConcurrentClaimsRespectRelayProcessCapacity(t *testing.T) {
	fixtures, registration := relayScopeSessions(t)
	database, now := fixtures[0].database, fixtures[0].now
	connections := []relayScopeConnection{
		relayScopeSlot(t, fixtures[0], registration.RelayServiceID),
		relayScopeSlot(t, fixtures[1], registration.RelayServiceID),
	}
	connections[1].lease = connections[0].lease
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	gate, err := database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := gate.Exec(ctx, `SELECT relay_id FROM control.relay_leases WHERE relay_id=$1 FOR UPDATE`, connections[0].lease.RelayID); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	done := []chan error{make(chan error, 1), make(chan error, 1)}
	workers.Go(func() { done[0] <- connections[0].claim(ctx) })
	firstPID := waitForPostgresBlock(t, ctx, database, int32(gate.Conn().PgConn().PID()), done[0])
	workers.Go(func() { done[1] <- connections[1].claim(ctx) })
	waitForPostgresBlock(t, ctx, database, firstPID, done[1])
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	winner, successes, full := -1, 0, 0
	for index, result := range done {
		err := awaitIntegrationResult(t, ctx, result)
		switch {
		case err == nil:
			winner, successes = index, successes+1
		case errors.Is(err, ErrRelayConnectionCapacity):
			full++
		default:
			t.Fatalf("claim %d: %v", index, err)
		}
	}
	if successes != 1 || full != 1 {
		t.Fatalf("claims succeeded=%d capacity_rejected=%d; want 1/1", successes, full)
	}
	if err := connections[winner].claim(ctx); err != nil {
		t.Fatalf("idempotent claim at capacity: %v", err)
	}
	var active int
	if err := database.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_connection_slots
		WHERE relay_id=$1 AND relay_run_id=$2 AND relay_lease_revision=$3 AND session_open AND state='connected'`,
		connections[winner].lease.RelayID, connections[winner].lease.RelayRunID, int64(connections[winner].lease.RelayLeaseRevision)).Scan(&active); err != nil || active != 1 {
		t.Fatalf("idempotent claim changed occupied capacity: %d %v", active, err)
	}
	if err := database.CloseServiceRun(ctx, fixtures[winner].service.ID, fixtures[winner].run.RunID, fixtures[winner].run.Token, now); err != nil {
		t.Fatal(err)
	}
	if err := connections[1-winner].claim(ctx); err != nil {
		t.Fatalf("claim after capacity was released: %v", err)
	}
	assertAssignmentTotals(t, database.pool, 2)
}

// two services, two relay services, and two capacity-one processes per relay
// service. explicit service lookup makes placement deterministic for each proof.
func relayScopeSessions(t *testing.T) ([2]servicePublicationFixture, RelayRegistration) {
	t.Helper()
	database, now := newControlStateIntegrationDatabase(t, "relay_scope")
	leases := [2]map[string]RelayLease{{}, {}}
	var registration RelayRegistration
	for _, service := range []string{"relay-a", "relay-b"} {
		for process := range 2 {
			candidate := relayLifecycleRegistration(service)
			candidate.ConnectionCapacity = 1
			if process == 1 {
				candidate.RelayID = service + "-2"
			}
			lease, err := database.RegisterRelay(t.Context(), candidate, now, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			leases[process][service] = lease
			if service == "relay-a" && process == 1 {
				registration = candidate
			}
		}
	}
	var fixtures [2]servicePublicationFixture
	for index := range fixtures {
		fixtures[index] = relayScopeService(t, database, now, fmt.Sprintf("scope-%d", index), leases[index])
	}
	return fixtures, registration
}

func relayScopeService(t *testing.T, database *Database, now time.Time, name string, leases map[string]RelayLease) servicePublicationFixture {
	t.Helper()
	session := newOIDCSession(t, database, now)
	member, actor := session.Identity.Memberships[0], session.Identity.Identity.ID
	service, err := database.CreateServiceAt(t.Context(), member.TeamID, actor, name, name, ServicePlacement{}, now,
		ServiceMetadata{}, &ProjectServiceConfiguration{Target: "http://127.0.0.1:3000"})
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := database.IssuePublisherEnrollment(t.Context(), CreatePublisherEnrollmentRequest{
		Scope: PublisherScope{TeamID: service.TeamID, Kind: "service", ServiceID: service.ID},
		Name:  name, Kind: "installed", EditorID: actor, EditorMembershipID: member.ID,
		PolicyRevision: uint64(member.PolicyRevision), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := database.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	fixture := servicePublicationFixture{database: database, now: now, service: service, publisher: publisher, leases: leases}
	fixture.start(t, name, now)
	return fixture
}

type relayScopeConnection struct {
	fixture servicePublicationFixture
	slot    ServiceRunAssignment
	lease   RelayLeaseIdentity
}

func relayScopeSlot(t *testing.T, fixture servicePublicationFixture, service string) relayScopeConnection {
	t.Helper()
	for _, slot := range fixture.run.Connections {
		if slot.RelayServiceID == service {
			return relayScopeConnection{fixture, slot, fixture.leases[service].RelayLeaseIdentity}
		}
	}
	t.Fatalf("service run %s has no assignment for relay service %s", fixture.run.RunID, service)
	return relayScopeConnection{}
}

func (c relayScopeConnection) check(result ServicePublisherConnection, err error) error {
	if err != nil {
		return err
	}
	expected := ServicePublisherConnection{ServiceID: c.fixture.service.ID, RunID: c.fixture.run.RunID, RunNumber: c.fixture.run.RunNumber,
		ConnectionID: c.slot.PublisherConnectionID, Revision: c.slot.Revision, RelayServiceID: c.slot.RelayServiceID}
	if result != expected {
		return errors.New("publisher connection operation changed the exact service/run/slot tuple")
	}
	return nil
}

func (c relayScopeConnection) claim(ctx context.Context) error {
	return c.check(c.fixture.database.ClaimServicePublisherConnection(ctx, c.slot.PublisherConnectionID,
		c.fixture.service.ID, c.fixture.run.RunID, c.fixture.run.RunNumber, c.slot.Revision, c.slot.Credential,
		netip.MustParseAddr("127.0.0.1"), c.lease, c.fixture.now))
}

func (c relayScopeConnection) ready(ctx context.Context) error {
	return c.check(c.fixture.database.ReadyServicePublisherConnection(ctx, c.slot.PublisherConnectionID,
		c.fixture.run.RunID, c.fixture.run.RunNumber, c.slot.Revision, c.lease, c.fixture.now))
}
