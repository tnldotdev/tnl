package controlstate

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

func TestIntegrationACMEWorkWaitsForEveryLiveIngress(t *testing.T) {
	testURL := newDisposableControlStateDatabaseURL(t, "acme_routing")
	if err := Migrate(t.Context(), testURL); err != nil {
		t.Fatal(err)
	}
	database, err := Open(t.Context(), testURL, testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	now := time.Now().UTC().Truncate(time.Microsecond)
	seedACMERoutingBarrierOrder(t, database, now)
	setACMERoutingBarrierRevision(t, database, 1, now)
	assertACMEWorkAvailable(t, database, "no-ingress", now, false)

	ingressA, err := database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "ingress_acme_a", IngressRunID: "run_acme_a", ProtocolVersion: 1, ConnectionCapacity: 10,
	}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ingressB, err := database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "ingress_acme_b", IngressRunID: "run_acme_b", ProtocolVersion: 1, ConnectionCapacity: 10,
	}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	assertACMEWorkAvailable(t, database, "before-ingress", now.Add(time.Millisecond), false)

	ingressA = renewACMEBarrierIngress(t, database, ingressA, 1, now.Add(2*time.Millisecond), time.Minute)
	assertACMEWorkAvailable(t, database, "after-one-ingress", now.Add(3*time.Millisecond), false)
	ingressB = renewACMEBarrierIngress(t, database, ingressB, 1, now.Add(4*time.Millisecond), time.Minute)
	assertACMEWorkAvailable(t, database, "after-every-ingress", now.Add(5*time.Millisecond), true)
	releaseACMEBarrierWork(t, database)

	setACMERoutingBarrierRevision(t, database, 2, now.Add(6*time.Millisecond))
	ingressA = renewACMEBarrierIngress(t, database, ingressA, 2, now.Add(7*time.Millisecond), time.Minute)
	assertACMEWorkAvailable(t, database, "behind-ingress", now.Add(8*time.Millisecond), false)
	if _, err := database.BeginIngressDrain(
		t.Context(), ingressB.IngressLeaseIdentity, now.Add(9*time.Millisecond), now.Add(50*time.Second),
	); err != nil {
		t.Fatal(err)
	}
	assertACMEWorkAvailable(t, database, "draining-ingress", now.Add(10*time.Millisecond), true)
	releaseACMEBarrierWork(t, database)

	ingressC, err := database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "ingress_acme_c", IngressRunID: "run_acme_c", ProtocolVersion: 1, ConnectionCapacity: 10,
	}, now.Add(11*time.Millisecond), 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	setACMERoutingBarrierRevision(t, database, 3, now.Add(12*time.Millisecond))
	renewACMEBarrierIngress(t, database, ingressA, 3, now.Add(13*time.Millisecond), time.Minute)
	assertACMEWorkAvailable(t, database, "live-behind-ingress", now.Add(14*time.Millisecond), false)
	if !ingressC.LeaseExpiresAt.Equal(now.Add(16 * time.Millisecond)) {
		t.Fatalf("short ingress lease expires at %v", ingressC.LeaseExpiresAt)
	}
	assertACMEWorkAvailable(t, database, "expired-behind-ingress", now.Add(17*time.Millisecond), true)
}

func seedACMERoutingBarrierOrder(t *testing.T, database *Database, now time.Time) {
	t.Helper()
	seedControlPublicURL(t, database, now, "acmebarrier")
	account, err := database.EnsureACMEAccount(
		t.Context(), "https://acme.example.test/directory", "operator@example.test", now,
	)
	if err != nil {
		t.Fatal(err)
	}
	account, err = database.UpdateACMEAccountRegistration(
		t.Context(), account.ID, account.ContactEmail, "https://acme.example.test/account/1", "", now,
	)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := sha256.Sum256([]byte("acme-routing-barrier-request"))
	csrDigest := sha256.Sum256([]byte("acme-routing-barrier-csr"))
	challengeDigest := sha256.Sum256([]byte("acme-routing-barrier-challenge"))
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO control.publish_runs (
			id, public_url_id, team_id, acting_identity_id, publish_run_number, idempotency_key,
			request_digest, publish_run_token_id, publish_run_token_digest, policy_revision,
			certificate_cache_key, certificate_scope, certificate_identifiers,
			certificate_challenge, state, created_at, last_heartbeat_at, publisher_expires_at
		) VALUES (
			'session_acme_barrier', 'public_url_acmebarrier', 'team_acmebarrier', 'identity_acmebarrier',
			1, 'session', $2, 'token_acme_barrier', $3, 1,
			'certificate_acme_barrier', 'route', ARRAY['route-acmebarrier.example.test'],
			'tls-alpn-01', 'starting', $1, $1, $4
		)`, []any{now, requestDigest[:], challengeDigest[:], now.Add(time.Hour)}},
		{`INSERT INTO control.acme_orders (
			id, account_id, publish_run_id, public_url_id, publish_run_number, idempotency_key,
			request_digest, certificate_cache_key, certificate_scope, certificate_identifiers,
			challenge_method, csr_der, csr_digest, state, available_at, created_at, updated_at
		) VALUES (
			'issuance_acme_barrier', $2, 'session_acme_barrier', 'public_url_acmebarrier', 1, 'issuance',
			$3, 'certificate_acme_barrier', 'route', ARRAY['route-acmebarrier.example.test'],
			'tls-alpn-01', $4, $5, 'authorizing', $1, $1, $1
		)`, []any{now, account.ID, requestDigest[:], []byte("csr"), csrDigest[:]}},
		{`INSERT INTO control.acme_authorizations (
			id, order_id, identifier, authorization_url, challenge_type, challenge_url,
			challenge_token, challenge_digest, state, available_at, presented_at,
			expires_at, created_at, updated_at
		) VALUES (
			'authorization_acme_barrier', 'issuance_acme_barrier', 'route-acmebarrier.example.test',
			'https://acme.example.test/authz/barrier', 'tls-alpn-01',
			'https://acme.example.test/challenge/barrier', 'challenge', $2, 'presented',
			$1, $1, $3, $1, $1
		)`, []any{now, challengeDigest[:], now.Add(time.Hour)}},
	} {
		if _, err := database.pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
}

func setACMERoutingBarrierRevision(t *testing.T, database *Database, revision int64, now time.Time) {
	t.Helper()
	// Each barrier advance represents an actual change to this challenge.
	got, err := controlstatedb.New(database.pool).InsertFinalIngressRoutingTableEvent(t.Context(), controlstatedb.InsertFinalIngressRoutingTableEventParams{
		EventKind: "challenge_upsert", PublicURLID: "public_url_acmebarrier", PublishRunNumber: 1,
		CanonicalHostname: "route-acmebarrier.example.test", EntryRevision: revision,
		Projection: acmeRoutingBarrierProjection(now.Add(time.Hour)), PublicUrlExpiresAt: timestamptz(now.Add(time.Hour)),
		CreatedAt: timestamptz(now), UpdatedAt: timestamptz(now),
	})
	if err != nil || got != revision {
		t.Fatalf("publish challenge revision %d: got=%d error=%v", revision, got, err)
	}
}

func acmeRoutingBarrierProjection(leaseExpiresAt time.Time) []byte {
	return []byte(fmt.Sprintf(
		`{"publisher_connections":[{"lease_expires_at":%q}]}`,
		leaseExpiresAt.Format(time.RFC3339Nano),
	))
}

func TestIntegrationACMEWorkRequiresCurrentChallengeProjection(t *testing.T) {
	for _, kind := range []string{"missing", "tombstone", "expired", "expired_backend", "different_version", "retained"} {
		t.Run(kind, func(t *testing.T) {
			database, now := newControlStateIntegrationDatabase(t, "acme_projection")
			seedACMERoutingBarrierOrder(t, database, now)
			ingress := registerTestIngress(t, database, now)
			setACMERoutingBarrierRevision(t, database, 1, now.Add(-time.Minute))
			setACMERoutingBarrierRevision(t, database, 2, now)
			renewACMEBarrierIngress(t, database, ingress, 2, now, time.Hour)
			switch kind {
			case "missing":
				_, err := database.pool.Exec(t.Context(), `DELETE FROM control.ingress_routing_table_events`)
				if err != nil {
					t.Fatal(err)
				}
			case "different_version":
				_, err := database.pool.Exec(t.Context(), `UPDATE control.ingress_routing_table_events SET publish_run_number = 2`)
				if err != nil {
					t.Fatal(err)
				}
			case "tombstone":
				_, err := database.pool.Exec(t.Context(), `UPDATE control.ingress_routing_table_events
					SET event_kind = 'challenge_tombstone', public_url_expires_at = NULL WHERE routing_table_revision = 2`)
				if err != nil {
					t.Fatal(err)
				}
			case "expired":
				_, err := database.pool.Exec(t.Context(), `UPDATE control.ingress_routing_table_events
					SET public_url_expires_at = $1 WHERE routing_table_revision = 2`, now)
				if err != nil {
					t.Fatal(err)
				}
			case "expired_backend":
				_, err := database.pool.Exec(t.Context(), `UPDATE control.ingress_routing_table_events
					SET projection = $1 WHERE routing_table_revision = 2`, acmeRoutingBarrierProjection(now))
				if err != nil {
					t.Fatal(err)
				}
			case "retained":
				if _, err := database.AdvanceIngressRoutingRetention(t.Context(), now.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				if batch, err := database.PruneIngressRoutingHistory(t.Context(), 0); err != nil || batch.Deleted != 1 {
					t.Fatalf("prune prior challenge: %+v error=%v", batch, err)
				}
			}
			assertACMEWorkAvailable(t, database, kind, now, kind == "retained")
		})
	}
}

func TestIntegrationACMEChallengeRoutingReadyBeforeValidation(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "acme_final_routing_barrier")
	seedACMERoutingBarrierOrder(t, database, now)
	first := registerTestIngress(t, database, now)
	second, err := database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "second", IngressRunID: "second-run", ProtocolVersion: 1, ConnectionCapacity: 100,
	}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ready := func(want bool) {
		t.Helper()
		got, err := database.ACMEChallengeRoutingReady(t.Context(), "issuance_acme_barrier", now)
		if err != nil || got != want {
			t.Fatalf("challenge routing ready=%t, want %t: %v", got, want, err)
		}
	}
	ready(false)
	setACMERoutingBarrierRevision(t, database, 1, now)
	ready(false)
	first = renewACMEBarrierIngress(t, database, first, 1, now, time.Hour)
	ready(false)
	second = renewACMEBarrierIngress(t, database, second, 1, now, time.Hour)
	ready(true)
	setACMERoutingBarrierRevision(t, database, 2, now)
	ready(false)
	_ = renewACMEBarrierIngress(t, database, first, 2, now, time.Hour)
	ready(false)
	_ = renewACMEBarrierIngress(t, database, second, 2, now, time.Hour)
	ready(true)
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.ingress_routing_table_events
		SET projection = $1 WHERE routing_table_revision = 2`, acmeRoutingBarrierProjection(now)); err != nil {
		t.Fatal(err)
	}
	ready(false)
}

func renewACMEBarrierIngress(
	t *testing.T,
	database *Database,
	lease IngressLease,
	revision uint64,
	now time.Time,
	duration time.Duration,
) IngressLease {
	t.Helper()
	renewed, err := database.RenewIngress(t.Context(), IngressRenewal{
		IngressLeaseIdentity: lease.IngressLeaseIdentity, RoutingTableRevision: revision,
	}, now, duration)
	if err != nil {
		t.Fatal(err)
	}
	return renewed
}

func assertACMEWorkAvailable(t *testing.T, database *Database, worker string, now time.Time, want bool) {
	t.Helper()
	work, found, err := database.ClaimACMEOrderWork(t.Context(), worker, now, time.Minute)
	if err != nil || found != want {
		t.Fatalf("ACME work for %q: issuance=%s found=%t error=%v; want found=%t", worker, work.ID, found, err, want)
	}
	if found && work.ID != "issuance_acme_barrier" {
		t.Fatalf("ACME work for %q: unexpected issuance=%s", worker, work.ID)
	}
}

func releaseACMEBarrierWork(t *testing.T, database *Database) {
	t.Helper()
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.acme_orders
		SET work_owner = NULL, work_expires_at = NULL
		WHERE id = 'issuance_acme_barrier'
	`); err != nil {
		t.Fatal(err)
	}
}
