package controlstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
)

func TestIntegrationPublisherConnectionsShareRelayServiceGuard(t *testing.T) {
	for _, operation := range []string{"claim", "ready"} {
		t.Run(operation, func(t *testing.T) {
			fixtures, registration := relayServiceSessions(t)
			database, now := fixtures[0].database, fixtures[0].now
			claims := []PublisherConnectionClaimRequest{sessionClaim(t, fixtures[0]), sessionClaim(t, fixtures[1])}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			if operation == "ready" {
				for _, claim := range claims {
					if _, err := database.ClaimPublisherConnection(ctx, claim, now); err != nil {
						t.Fatal(err)
					}
				}
			}
			perform := func(ctx context.Context, claim PublisherConnectionClaimRequest) error {
				if operation == "ready" {
					_, err := database.MarkPublisherConnectionReady(ctx, claim, now)
					return err
				}
				_, err := database.ClaimPublisherConnection(ctx, claim, now)
				return err
			}
			gate, err := database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err := gate.Exec(ctx, `SELECT relay_id FROM control.relay_leases WHERE relay_id = $1 FOR UPDATE`, claims[0].RelayID); err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			first := make(chan error, 1)
			workers.Go(func() { first <- perform(ctx, claims[0]) })
			firstPID := waitForPostgresBlock(t, ctx, database, int32(gate.Conn().PgConn().PID()), first)
			// the first operation holds the service guard while waiting on its lease.
			independent, stop := context.WithTimeout(ctx, 2*time.Second)
			defer stop()
			if err := perform(independent, claims[1]); err != nil {
				t.Fatalf("another relay process in the same service could not %s: %v", operation, err)
			}
			registered := make(chan error, 1)
			workers.Go(func() {
				_, err := database.RegisterRelay(ctx, registration, now, time.Hour)
				registered <- err
			})
			// registration targets the other lease but must still wait on the service.
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
			fixtures, registration := relayServiceProgressSessions(t)
			database, now := fixtures[0].database, fixtures[0].now
			write := relayServiceProgressWriter(t, writer, fixtures, registration)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			gate, err := database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err := gate.Exec(ctx, `SELECT relay_id FROM control.relay_leases WHERE relay_id = $1 FOR UPDATE`, registration.RelayID); err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			failed := make(chan error, len(fixtures)-1)
			var retries atomic.Int64
			var readerPIDs []int32
			blocker := int32(gate.Conn().PgConn().PID())
			// queue four real readers on the lease before starting the writer.
			// once the gate opens every transaction can finish; later retries must
			// not keep the service writer waiting indefinitely. this tests bounded
			// progress, not FIFO ordering between individual row-lock requests.
			for _, fixture := range fixtures[:len(fixtures)-1] {
				claim := sessionClaim(t, fixture)
				workers.Go(func() {
					for ctx.Err() == nil {
						_, err := database.ClaimPublisherConnection(ctx, claim, now)
						if err == nil {
							_, err = database.MarkPublisherConnectionReady(ctx, claim, now)
						}
						if ctx.Err() != nil {
							return
						}
						if err != nil {
							failed <- err
							return
						}
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
			workers.stop()
			select {
			case err := <-failed:
				t.Fatal(err)
			default:
			}
			if err != nil {
				t.Fatalf("%s failed to progress in %s after %d claim/readiness retries: %v", writer, elapsed, retries.Load(), err)
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
				rotating, err := Open(t.Context(), databaseURL, newKey, testStorageKey)
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
			// opportunistic maintenance must skip relay-a and finish relay-b even
			// while relay-a has both an active reader and a queued service writer.
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
			// the skipped service remains eligible once its reader and writer drain.
			if err := maintain(maintenanceCtx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func relayServiceProgressWriter(t *testing.T, writer string, fixtures [5]publishRunFixture, registration RelayRegistration) func(context.Context) error {
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
		setup := fixtures[len(fixtures)-1].setup
		return func(ctx context.Context) error {
			replenished, err := database.HeartbeatPublishRun(ctx, PublishRunAuthentication{
				PublishRunID: setup.PublishRunID, PublicURLID: setup.PublicURLID,
				PublishRunNumber: setup.PublishRunNumber, PublishRunToken: setup.PublishRunToken,
			}, now.Add(2*time.Minute), time.Hour, time.Minute)
			if err != nil {
				return err
			}
			for slot, connection := range replenished.PublisherConnections {
				previous := setup.PublisherConnections[slot]
				if connection.PublisherConnectionID == previous.PublisherConnectionID ||
					connection.ConnectionAssignmentRevision != previous.ConnectionAssignmentRevision+1 ||
					connection.RelayServiceID != previous.RelayServiceID || connection.State != PublisherConnectionAssigned {
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
		rotating, err := Open(t.Context(), database.pool.Config().ConnConfig.ConnString(), newKey, testStorageKey)
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
			if err := database.pool.QueryRow(ctx, `SELECT transport_private_key_storage_key_id FROM control.relay_services WHERE relay_service_id = $1`, registration.RelayServiceID).Scan(&keyID); err != nil {
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

// four independent public URLs retry on one relay process while a fifth
// needs placement. every service has exactly enough capacity for all five.
func relayServiceProgressSessions(t *testing.T) ([5]publishRunFixture, RelayRegistration) {
	return relayServiceProgressSessionsWithSharedTeam(t, false)
}

func relayServiceProgressSessionsWithSharedTeam(t *testing.T, sharedTeam bool) ([5]publishRunFixture, RelayRegistration) {
	t.Helper()
	database, now := newRelayLifecycleDatabase(t)
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
	var fixtures [5]publishRunFixture
	for index := range fixtures {
		suffix := fmt.Sprintf("relayprogress%d", index)
		seedControlPublicURL(t, database, now, suffix)
		if sharedTeam && index == 1 {
			// build a second, valid public URL in the first team before its run exists.
			if _, err := database.pool.Exec(t.Context(), `UPDATE control.public_urls
				SET team_id = $2, domain_id = $3, created_by_identity_id = $4, idempotency_key = $5
				WHERE id = $1`, "public_url_"+suffix, "team_relayprogress0", "domain_relayprogress0",
				"identity_relayprogress0", "seed-"+suffix); err != nil {
				t.Fatal(err)
			}
		}
		request := PublishRunRequest{
			PublicURLID: "public_url_" + suffix, TeamID: "team_" + suffix, ActingIdentityID: "identity_" + suffix,
			MembershipID: "membership_" + suffix,
			RetrySecret:  bytes.Repeat([]byte{7}, 32), IdempotencyKey: "session", RequestDigest: sha256.Sum256([]byte("session")),
			PolicyRevision: 1, ExpectedMutationRevision: 1, CertificateCacheKey: suffix, CertificateScope: "route",
			CertificateIdentifiers: []string{"route-" + suffix + ".example.test"}, CertificateChallenge: "tls-alpn-01",
		}
		if sharedTeam && index == 1 {
			request.TeamID = "team_relayprogress0"
			request.ActingIdentityID = "identity_relayprogress0"
			request.MembershipID = "membership_relayprogress0"
		}
		setup, err := database.CreatePublishRun(t.Context(), request, now, time.Hour, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		fixtures[index] = publishRunFixture{database: database, now: now, request: request, setup: setup, leases: leases}
	}
	return fixtures, registration
}

func TestIntegrationConcurrentClaimsRespectRelayProcessCapacity(t *testing.T) {
	fixtures, _ := relayServiceSessions(t)
	database, now := fixtures[0].database, fixtures[0].now
	claims := []PublisherConnectionClaimRequest{sessionClaim(t, fixtures[0]), sessionClaim(t, fixtures[1])}
	claims[1].RelayLeaseIdentity = claims[0].RelayLeaseIdentity
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	gate, err := database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := gate.Exec(ctx, `SELECT relay_id FROM control.relay_leases WHERE relay_id = $1 FOR UPDATE`, claims[0].RelayID); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	done := []chan error{make(chan error, 1), make(chan error, 1)}
	for index, claim := range claims {
		workers.Go(func() {
			_, err := database.ClaimPublisherConnection(ctx, claim, now)
			done[index] <- err
		})
	}
	firstPID := waitForPostgresBlock(t, ctx, database, int32(gate.Conn().PgConn().PID()), done[0])
	// the other claim must queue behind the first lease-lock waiter.
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
	if _, err := database.ClaimPublisherConnection(ctx, claims[winner], now); err != nil {
		t.Fatalf("idempotent claim at capacity: %v", err)
	}
	if err := database.ClosePublishRun(ctx, fixtures[winner].setup.PublishRunID, fixtures[winner].setup.PublishRunToken, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ClaimPublisherConnection(ctx, claims[1-winner], now); err != nil {
		t.Fatalf("claim after capacity was released: %v", err)
	}
}

// two public URLs, two relay services, two capacity-one processes per service. each public URL
// claims a different process, unless a test explicitly selects the same process.
func relayServiceSessions(t *testing.T) ([2]publishRunFixture, RelayRegistration) {
	t.Helper()
	f := newTransactionAuthorityFixture(t)
	leases := [2]map[string]RelayLease{{}, {}}
	var registration RelayRegistration
	for _, service := range []string{"relay-a", "relay-b"} {
		for process := range 2 {
			candidate := relayLifecycleRegistration(service)
			if process == 1 {
				candidate.RelayID = service + "-2"
			}
			lease, err := f.database.RegisterRelay(t.Context(), candidate, f.now, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			leases[process][service] = lease
			if service == "relay-a" && process == 1 {
				registration = candidate
			}
		}
	}
	var result [2]publishRunFixture
	for index, request := range []PublishRunRequest{f.sessionRequest, siblingSessionRequest(t, f)} {
		setup, err := f.database.CreatePublishRun(t.Context(), request, f.now, time.Hour, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		result[index] = publishRunFixture{database: f.database, now: f.now, request: request, setup: setup, leases: leases[index]}
	}
	return result, registration
}

func sessionClaim(t *testing.T, f publishRunFixture) PublisherConnectionClaimRequest {
	t.Helper()
	assignment := f.setup.PublisherConnections[0]
	digest, err := credentials.ParsePublisherConnectionCredential(assignment.PublisherConnectionCredential)
	if err != nil {
		t.Fatal(err)
	}
	return PublisherConnectionClaimRequest{
		ConnectionAssignmentIdentity: assignment.ConnectionAssignmentIdentity,
		RelayLeaseIdentity:           f.leases[assignment.RelayServiceID].RelayLeaseIdentity,
		ClaimID:                      "scope-test", CredentialDigest: [32]byte(digest),
	}
}
