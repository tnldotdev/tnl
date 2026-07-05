package controlstate

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
)

func TestIntegrationRelayLifecycleCapacityOneReplenishment(t *testing.T) {
	for _, onlySecondReturns := range []bool{false, true} {
		name := "expired_credentials"
		if onlySecondReturns {
			name = "only_second_service_returns"
		}
		t.Run(name, func(t *testing.T) {
			database, now := newRelayLifecycleDatabase(t)
			setup, registrations := newRelayLifecycleSession(t, database, now)
			authentication := RouteSessionAuthentication{
				RouteSessionID: setup.RouteSessionID, RouteID: setup.RouteID,
				RouteVersion: setup.RouteVersion, RouteSessionToken: setup.RouteSessionToken,
			}
			heartbeat := func(at time.Time) RouteSessionSetup {
				t.Helper()
				result, err := database.HeartbeatRouteSession(t.Context(), authentication, at, time.Hour, time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				return result
			}
			good := heartbeat(now.Add(30 * time.Second))
			if good.PublisherConnections != setup.PublisherConnections {
				t.Fatal("full services invalidated good assignments")
			}
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
			for slot, connection := range replaced.PublisherConnections {
				previous := setup.PublisherConnections[slot]
				if connection.RelayServiceID != previous.RelayServiceID {
					t.Fatalf("slot %d stole another slot's stored service", slot)
				}
				if onlySecondReturns && slot == 0 {
					if connection.State != PublisherConnectionExpired || connection.PublisherConnectionID != previous.PublisherConnectionID {
						t.Fatalf("unavailable slot was not retired: %#v", connection.ConnectionAssignmentIdentity)
					}
					continue
				}
				if connection.State != PublisherConnectionAssigned || connection.ConnectionAssignmentRevision != 2 ||
					connection.PublisherConnectionID == previous.PublisherConnectionID {
					t.Fatalf("capacity-one slot %d did not replace its expired reservation", slot)
				}
			}
			if onlySecondReturns {
				registrations[0].RelayRunID += "-returned"
				if _, err := database.RegisterRelay(t.Context(), registrations[0], at, time.Hour); err != nil {
					t.Fatal(err)
				}
				recovered := heartbeat(at.Add(time.Second))
				if recovered.PublisherConnections[0].ConnectionAssignmentRevision != 2 ||
					recovered.PublisherConnections[1] != replaced.PublisherConnections[1] {
					t.Fatal("second recovery changed the good slot or failed to replenish the expired slot")
				}
			}
			tx, err := database.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
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
			setup, registrations := newRelayLifecycleSession(t, database, now)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			gate, err := database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer gate.Rollback(context.Background())
			slot := 0
			if operation == "placement" {
				slot = 1
			}
			if _, err := gate.Exec(ctx, `SELECT relay_id FROM control.relay_leases WHERE relay_id = $1 FOR UPDATE`, registrations[slot].RelayID); err != nil {
				t.Fatal(err)
			}
			var workers sync.WaitGroup
			defer func() { cancel(); workers.Wait() }()
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
					plan := setup.PublisherConnections[slot]
					digest, parseErr := credentials.ParsePublisherConnectionCredential(plan.PublisherConnectionCredential)
					if parseErr != nil {
						completed <- parseErr
						return
					}
					_, err = database.ClaimPublisherConnection(ctx, PublisherConnectionClaimRequest{
						ConnectionAssignmentIdentity: plan.ConnectionAssignmentIdentity,
						RelayLeaseIdentity: RelayLeaseIdentity{RelayServiceID: registrations[slot].RelayServiceID,
							RelayID: registrations[slot].RelayID, RelayRunID: registrations[slot].RelayRunID, RelayLeaseRevision: 1},
						ClaimID: "claim-lock-order", CredentialDigest: [32]byte(digest),
					}, now)
				} else {
					_, err = database.HeartbeatRouteSession(ctx, RouteSessionAuthentication{
						RouteSessionID: setup.RouteSessionID, RouteID: setup.RouteID,
						RouteVersion: setup.RouteVersion, RouteSessionToken: setup.RouteSessionToken,
					}, now, time.Hour, time.Minute)
				}
				completed <- err
			})
			// Registration holds the service and waits for the lease. The other
			// operation must wait on registration, not take a lease first.
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
				if err := <-done; err != nil {
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
			defer gate.Rollback(context.Background())
			if _, err := gate.Exec(ctx, `SELECT 1 FROM control.`+gateTable+` FOR UPDATE`); err != nil {
				t.Fatal(err)
			}
			var workers sync.WaitGroup
			defer func() { cancel(); workers.Wait() }()
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
				defer probe.Rollback(context.Background())
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
			if err := <-completed; err != nil {
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

func newRelayLifecycleSession(t *testing.T, database *Database, now time.Time) (RouteSessionSetup, [2]RelayRegistration) {
	t.Helper()
	registrations := [2]RelayRegistration{relayLifecycleRegistration("relay-a"), relayLifecycleRegistration("relay-b")}
	for _, registration := range registrations {
		if _, err := database.RegisterRelay(t.Context(), registration, now, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	seedControlRoute(t, database, now, "relaylifecycle")
	setup, err := database.CreateRouteSession(t.Context(), RouteSessionRequest{
		RouteID: "route_relaylifecycle", TeamID: "team_relaylifecycle", ActingIdentityID: "identity_relaylifecycle",
		MembershipID: "membership_relaylifecycle", RequireLocalAuthority: true,
		RetrySecret: bytes.Repeat([]byte{7}, 32), IdempotencyKey: "session", RequestDigest: sha256.Sum256([]byte("session")),
		PolicyRevision: 1, ExpectedMutationRevision: 1, CertificateCacheKey: "relay_lifecycle", CertificateScope: "route",
		CertificateIdentifiers: []string{"route-relaylifecycle.example.test"}, CertificateChallenge: "tls-alpn-01",
	}, now, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return setup, registrations
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
	block, _ := pem.Decode(work.PrivateKeyPEM)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := key.(*ecdsa.PrivateKey)
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
