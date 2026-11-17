package state

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationRelayLifecycleCapacityOneReplenishment(t *testing.T) {
	for _, onlySecondReturns := range []bool{false, true} {
		name := "expired_credentials"
		if onlySecondReturns {
			name = "only_second_service_returns"
		}
		t.Run(name, func(t *testing.T) {
			database, now := newRelayLifecycleDatabase(t)
			f, registrations := newRelayLifecycleServiceFixture(t, database, now)
			initial := f.run.Connections
			heartbeat := func(at time.Time) ServiceRunState {
				t.Helper()
				result, err := database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, at, ServiceRunHealth{StreamCapacity: 64})
				if err != nil {
					t.Fatal(err)
				}
				return result
			}
			good := heartbeat(now.Add(30 * time.Second))
			if !reflect.DeepEqual(good.Connections, initial) {
				t.Fatal("full services invalidated good assignments")
			}
			heartbeat(now.Add(time.Minute))
			heartbeat(now.Add(90 * time.Second))
			at := now.Add(2 * time.Minute)
			if onlySecondReturns {
				if _, err := database.pool.Exec(t.Context(), `UPDATE control.relay_leases SET lease_expires_at = $1`, now.Add(time.Minute)); err != nil {
					t.Fatal(err)
				}
				registrations[1].RelayRunID += "-returned"
				if _, err := database.RegisterRelay(t.Context(), registrations[1], at, time.Hour); err != nil {
					t.Fatal(err)
				}
			}
			replaced := heartbeat(at)
			if onlySecondReturns {
				// replacement reserves two distinct services atomically. one
				// returned service cannot steal the other slot's reservation.
				if !reflect.DeepEqual(replaced.Connections, initial) {
					t.Fatal("insufficient placement partially replaced assignments")
				}
				registrations[0].RelayRunID += "-returned"
				if _, err := database.RegisterRelay(t.Context(), registrations[0], at, time.Hour); err != nil {
					t.Fatal(err)
				}
				replaced = heartbeat(at.Add(time.Second))
			}
			for slot, connection := range replaced.Connections {
				previous := initial[slot]
				if connection.RelayServiceID != previous.RelayServiceID || connection.State != "assigned" ||
					connection.Revision != 2 || connection.PublisherConnectionID == previous.PublisherConnectionID {
					t.Fatalf("capacity-one slot %d lost its distinct service or replacement identity", slot)
				}
			}
			tx, err := database.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, tx)
			if _, err := selectRelayServicePlacements(t.Context(), controlstatedb.New(tx), at); !errors.Is(err, ErrInsufficientRelayServices) {
				t.Fatalf("replacement reservations did not consume capacity: %v", err)
			}
		})
	}
}

func TestIntegrationRelayLifecycleServiceBeforeLeaseLocks(t *testing.T) {
	for _, operation := range []string{"claim", "placement"} {
		t.Run(operation, func(t *testing.T) {
			database, now := newRelayLifecycleDatabase(t)
			f, registrations := newRelayLifecycleServiceFixture(t, database, now)
			heartbeatAt := now
			if operation == "placement" {
				heartbeatAt = now.Add(2 * time.Second)
				if _, err := database.pool.Exec(t.Context(), `UPDATE control.service_connection_slots SET credential_expires_at=$2 WHERE service_run_id=$1`, f.run.RunID, heartbeatAt); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			gate, err := database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			slot := 0
			if operation == "placement" {
				slot = 1
			}
			if _, err := gate.Exec(ctx, `SELECT relay_id FROM control.relay_leases WHERE relay_id = $1 FOR UPDATE`, registrations[slot].RelayID); err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			registered := make(chan error, 1)
			workers.Go(func() {
				_, err := database.RegisterRelay(ctx, registrations[slot], now, time.Hour)
				registered <- err
			})
			registrationPID := waitForPostgresBlock(t, ctx, database, int32(gate.Conn().PgConn().PID()), registered)
			completed := make(chan error, 1)
			workers.Go(func() {
				var err error
				if operation == "claim" {
					plan := f.run.Connections[slot]
					_, err = database.ClaimServicePublisherConnection(ctx, plan.PublisherConnectionID, f.service.ID, f.run.RunID, f.run.RunNumber, plan.Revision, plan.Credential, netip.MustParseAddr("127.0.0.1"), f.leases[plan.RelayServiceID].RelayLeaseIdentity, now)
				} else {
					_, err = database.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, heartbeatAt, ServiceRunHealth{StreamCapacity: 64})
				}
				completed <- err
			})
			waitForPostgresBlock(t, ctx, database, registrationPID, completed)
			if operation == "placement" {
				if _, err := gate.Exec(ctx, `SELECT relay_id FROM control.relay_leases WHERE relay_id = $1 FOR UPDATE NOWAIT`, registrations[0].RelayID); err != nil {
					t.Fatalf("placement locked an earlier lease before all services: %v", err)
				}
			}
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			for _, done := range []<-chan error{registered, completed} {
				if err := awaitIntegrationResult(t, ctx, done); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestIntegrationRelayLifecycleCertificateRenewalDeadline(t *testing.T) {
	database, now := newRelayLifecycleDatabase(t)
	work := newRelayLifecycleCertificateWork(t, database, now)
	work.State = "complete"
	if _, err := database.SaveRelayCertificateOrderWork(t.Context(), work, now); err != nil {
		t.Fatal(err)
	}
	if !work.RenewAt.After(now.Add(30 * time.Minute)) {
		t.Fatal("one-hour certificate has no meaningful renewal quiet period")
	}
	for _, at := range []time.Time{now, now.Add(time.Second), work.RenewAt.Add(-time.Microsecond), *work.RenewAt} {
		created, err := database.PrepareRelayCertificateOrder(t.Context(), work.Account.ID, at, time.Hour)
		if err != nil || created != at.Equal(*work.RenewAt) {
			t.Fatalf("renewal at %v: created %v, error %v; deadline %v", at, created, err, *work.RenewAt)
		}
	}
}

func TestIntegrationRelayLifecycleCertificateServiceBeforeOrderLocks(t *testing.T) {
	for _, gateTable := range []string{"relay_services", "relay_certificate_orders"} {
		t.Run(gateTable, func(t *testing.T) {
			database, now := newRelayLifecycleDatabase(t)
			work := newRelayLifecycleCertificateWork(t, database, now)
			work.State = "complete"
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			gate, err := database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err := gate.Exec(ctx, `SELECT 1 FROM control.`+gateTable+` FOR UPDATE`); err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			completed := make(chan error, 1)
			workers.Go(func() {
				_, err := database.SaveRelayCertificateOrderWork(ctx, work, now)
				completed <- err
			})
			waitForPostgresBlock(t, ctx, database, int32(gate.Conn().PgConn().PID()), completed)
			if gateTable == "relay_services" {
				if _, err := gate.Exec(ctx, `SELECT id FROM control.relay_certificate_orders FOR UPDATE NOWAIT`); err != nil {
					t.Fatalf("save locked its order before its service: %v", err)
				}
			} else {
				probe, err := database.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackTestTransaction(t, probe)
				_, err = probe.Exec(ctx, `SELECT relay_service_id FROM control.relay_services FOR UPDATE NOWAIT`)
				var postgresError *pgconn.PgError
				if !errors.As(err, &postgresError) || postgresError.Code != "55P03" {
					t.Fatalf("save did not hold its service while waiting for its order: %v", err)
				}
			}
			if created, err := database.PrepareRelayCertificateOrder(ctx, work.Account.ID, now, time.Hour); err != nil || created {
				t.Fatalf("prepare did not skip the locked service: created %v, error %v", created, err)
			}
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, completed); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func newRelayLifecycleDatabase(t *testing.T) (*Database, time.Time) {
	t.Helper()
	return newControlStateIntegrationDatabase(t, "relay_lifecycle")
}

func relayLifecycleRegistration(name string) RelayRegistration {
	return RelayRegistration{
		RelayServiceID: name, RelayID: name + "-1", RelayRunID: name + "-run", ProtocolVersion: 1,
		RelayAddress: name + ".example.test:443", TLSServerName: name + ".example.test",
		InternalRelayAddress: name + ".internal:9445", ConnectionCapacity: 1, StreamCapacity: 10,
	}
}

func newRelayLifecycleServiceFixture(t *testing.T, database *Database, now time.Time) (servicePublicationFixture, [2]RelayRegistration) {
	t.Helper()
	registrations := [2]RelayRegistration{relayLifecycleRegistration("relay-a"), relayLifecycleRegistration("relay-b")}
	leases := make(map[string]RelayLease)
	for _, registration := range registrations {
		lease, err := database.RegisterRelay(t.Context(), registration, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		leases[lease.RelayServiceID] = lease
	}
	session := newOIDCSession(t, database, now)
	member := session.Identity.Memberships[0]
	actor := session.Identity.Identity.ID
	service, err := database.CreateServiceAt(t.Context(), member.TeamID, actor, "web", "web", ServicePlacement{}, now, ServiceMetadata{}, &ProjectServiceConfiguration{Target: "http://127.0.0.1:3000"})
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := database.IssuePublisherEnrollment(t.Context(), CreatePublisherEnrollmentRequest{
		Scope: PublisherScope{TeamID: service.TeamID, Kind: "service", ServiceID: service.ID},
		Name:  "test", Kind: "installed", EditorID: actor, EditorMembershipID: member.ID,
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
	f := servicePublicationFixture{database: database, now: now, service: service, publisher: publisher, leases: leases}
	f.start(t, "first", now)
	return f, registrations
}

func newRelayLifecycleCertificateWork(t *testing.T, database *Database, now time.Time) RelayCertificateOrderWork {
	t.Helper()
	if _, err := database.RegisterRelay(t.Context(), relayLifecycleRegistration("relay-certificate"), now, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	account, err := database.EnsureACMEAccount(t.Context(), "https://acme.example.test/directory", "operator@example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	if created, err := database.PrepareRelayCertificateOrder(t.Context(), account.ID, now, time.Hour); err != nil || !created {
		t.Fatalf("prepare order: created %v, error %v", created, err)
	}
	work, found, err := database.ClaimRelayCertificateOrderWork(t.Context(), "relay-lifecycle-worker", now, 2*time.Hour)
	if err != nil || !found {
		t.Fatalf("claim order: found %v, error %v", found, err)
	}
	block, rest := decodeTestPEM(t, work.PrivateKeyPEM, "PRIVATE KEY")
	if len(rest) != 0 {
		t.Fatal("unexpected data after relay private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("relay private key type = %T, want ECDSA", key)
	}
	notBefore, notAfter := now.Add(-time.Minute), now.Add(time.Hour)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{work.TLSServerName}, NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	renewAt := notBefore.Add(notAfter.Sub(notBefore) * 2 / 3)
	work.CertificatePEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	work.NotBefore, work.NotAfter, work.RenewAt = &notBefore, &notAfter, &renewAt
	return work
}
