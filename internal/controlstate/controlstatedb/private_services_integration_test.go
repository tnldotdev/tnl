package controlstatedb

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/testutil"
)

func TestIntegrationPrivateServiceInventory(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "private_inventory")
	conn, err := pgx.Connect(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	baseline, err := os.ReadFile("../migrations/00001_baseline.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(t.Context(), string(baseline)); err != nil {
		t.Fatalf("apply fresh private service baseline: %v", err)
	}

	newID := func(prefix string) string {
		t.Helper()
		id, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := conn.Exec(t.Context(), query, args...); err != nil {
			t.Fatalf("seed private service inventory: %v", err)
		}
	}
	now := time.Now().UTC()
	digest := make([]byte, 32)
	owner, visitor, outsider := newID(opaqueid.IdentityPrefix), newID(opaqueid.IdentityPrefix), newID(opaqueid.IdentityPrefix)
	for _, id := range []string{owner, visitor, outsider} {
		exec(`INSERT INTO control.identities(id, kind, display_name, created_at, updated_at)
			VALUES ($1, 'authority', 'tester', $2, $2)`, id, now)
	}
	team, service, session := newID(opaqueid.TeamPrefix), newID(opaqueid.PrivateServicePrefix), newID(opaqueid.PrivateConnectorSessionPrefix)
	exec(`INSERT INTO control.managed_label_reservations(label, created_at) VALUES ('teamlabel', $1)`, now)
	exec(`INSERT INTO control.teams(id, kind, display_name, managed_label, created_by_identity_id, created_at, updated_at)
		VALUES ($1, 'organization', 'shop', 'teamlabel', $2, $3, $3)`, team, owner, now)
	exec(`INSERT INTO control.private_services(id, team_id, name, created_by_identity_id, idempotency_key, request_digest, created_at, updated_at)
		VALUES ($1, $2, 'orders', $3, 'create', $4, $5, $5)`, service, team, owner, digest, now)
	grant := newID(opaqueid.PrivateServiceGrantPrefix)
	exec(`INSERT INTO control.private_service_grants(id, private_service_id, team_id, kind, identity_id,
		created_by_identity_id, idempotency_key, request_digest, created_at)
		VALUES ($1, $2, $3, 'identity', $4, $5, 'visit', $6, $7)`, grant, service, team, visitor, owner, digest, now)
	ingressRun, run := newID(opaqueid.IngressRunPrefix), newID(opaqueid.PrivateRunPrefix)
	exec(`INSERT INTO control.ingress_leases(ingress_id, ingress_run_id, ingress_lease_revision,
		protocol_version, connection_capacity, registered_at, renewed_at, lease_expires_at)
		VALUES ('ingress-a', $1, 1, 1, 8, $2, $2, $3)`, ingressRun, now, now.Add(10*time.Minute))
	exec(`INSERT INTO control.private_connector_sessions(id, credential_digest, private_service_id, identity_id,
		created_at, expires_at, bound_at, source_ip, ingress_id, ingress_run_id, ingress_lease_revision)
		VALUES ($1, $2, $3, $4, $5, $6, $5, '192.0.2.10', 'ingress-a', $7, 1)`, session, digest, service, visitor, now, now.Add(10*time.Minute), ingressRun)

	queries := New(conn)
	list := func(id string) []ListAvailablePrivateServicesRow {
		t.Helper()
		rows, err := queries.ListAvailablePrivateServices(t.Context(), ListAvailablePrivateServicesParams{
			IdentityID: id, Now: pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}, AfterID: "",
		})
		if err != nil {
			t.Fatal(err)
		}
		return rows
	}
	issue := func() error {
		t.Helper()
		_, err := queries.InsertPrivateServiceTicket(t.Context(), InsertPrivateServiceTicketParams{
			Digest: make([]byte, 32), IdentityID: visitor, ConnectorSessionID: session,
			PrivateServiceID: service, PrivateRunID: run,
			Now:       pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true},
			ExpiresAt: pgtype.Timestamptz{Time: time.Now().UTC().Add(30 * time.Second), Valid: true},
		})
		return err
	}
	if rows := list(visitor); len(rows) != 1 || rows[0].ID != service || rows[0].PrivateRunID.Valid || rows[0].RunNumber.Valid {
		t.Fatalf("authorized offline service = %+v", rows)
	}
	if rows := list(outsider); len(rows) != 0 {
		t.Fatalf("unauthorized identity saw private service: %+v", rows)
	}
	if err := issue(); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("offline service ticket error = %v, want no rows", err)
	}

	publisher, key, publisherGrant := newID(opaqueid.PublisherIdentityPrefix), newID(opaqueid.PublisherIdentityKeyPrefix), newID(opaqueid.PublisherGrantPrefix)
	exec(`INSERT INTO control.publisher_identities(id, team_id, name, kind, created_by_identity_id, created_at)
		VALUES ($1, $2, 'publisher', 'installed', $3, $4)`, publisher, team, owner, now)
	exec(`INSERT INTO control.publisher_identity_keys(id, publisher_identity_id, public_key, revision, created_at)
		VALUES ($1, $2, $3, 1, $4)`, key, publisher, digest, now)
	exec(`INSERT INTO control.publisher_grants(id, publisher_identity_id, created_by_identity_id, kind, private_service_id, created_at)
		VALUES ($1, $2, $3, 'private_service', $4, $5)`, publisherGrant, publisher, owner, service, now)
	exec(`INSERT INTO control.private_service_runs(id, private_service_id, team_id, run_number,
		publisher_identity_id, publisher_grant_id, publisher_key_id, idempotency_key, request_digest,
		binding_nonce, binding_expires_at, run_token_digest, stream_public_key, stream_key_binding_signature,
		bound_at, state, created_at, publisher_expires_at, ready_at)
		VALUES ($1, $2, $3, 1, $4, $5, $6, 'run', $7, $7, $8, $7, $7, $9, $10,
			'ready', $10, $11, $10)`, run, service, team, publisher, publisherGrant, key, digest,
		now.Add(2*time.Minute), make([]byte, 64), now, now.Add(10*time.Minute))
	if rows := list(visitor); len(rows) != 1 || rows[0].PrivateRunID.Valid || rows[0].RunNumber.Valid {
		t.Fatalf("run without ready slots appeared routable: %+v", rows)
	}
	for slot := range 2 {
		relay := "relay-a"
		if slot == 1 {
			relay = "relay-b"
		}
		exec(`INSERT INTO control.relay_services(relay_service_id, relay_address, tls_server_name, created_at, updated_at)
			VALUES ($1, $2, $1, $3, $3)`, relay, relay+":443", now)
		exec(`INSERT INTO control.private_service_connection_slots(publisher_connection_id, private_run_id,
			private_service_id, run_number, connection_slot, connection_assignment_revision, relay_service_id,
			relay_address, tls_server_name, credential_digest, credential_expires_at, relay_id, relay_run_id,
			relay_lease_revision, state)
			VALUES ($1, $2, $3, 1, $4, 1, $5, $6, $5, $7, $8, $5, $9, 1, 'ready')`,
			newID(opaqueid.PublisherConnectionPrefix), run, service, slot, relay, relay+":443",
			bytes.Repeat([]byte{byte(slot + 1)}, 32), now.Add(5*time.Minute), newID(opaqueid.RelayRunPrefix))
		if slot == 0 {
			if rows := list(visitor); len(rows) != 1 || rows[0].PrivateRunID.Valid || rows[0].RunNumber.Valid {
				t.Fatalf("one ready slot appeared routable: %+v", rows)
			}
			if err := issue(); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf("one ready slot ticket error = %v, want no rows", err)
			}
		}
	}
	if rows := list(visitor); len(rows) != 1 || !rows[0].PrivateRunID.Valid || rows[0].PrivateRunID.String != run || !rows[0].RunNumber.Valid || rows[0].RunNumber.Int64 != 1 {
		t.Fatalf("ready authorized service = %+v", rows)
	}
	if rows := list(outsider); len(rows) != 0 {
		t.Fatalf("unauthorized identity saw ready private service: %+v", rows)
	}
	if err := issue(); err != nil {
		t.Fatalf("ready service did not issue ticket: %v", err)
	}
	exec(`UPDATE control.private_service_runs SET state = 'closed', closed_at = $2 WHERE id = $1`, run, time.Now().UTC())
	if rows := list(visitor); len(rows) != 1 || rows[0].PrivateRunID.Valid || rows[0].RunNumber.Valid {
		t.Fatalf("closed run removed saved service or retained ready state: %+v", rows)
	}
	if err := issue(); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("closed run ticket error = %v, want no rows", err)
	}
	exec(`UPDATE control.private_service_grants SET revoked_at = $2 WHERE id = $1`, grant, time.Now().UTC())
	if rows := list(visitor); len(rows) != 0 {
		t.Fatalf("revoked visitor grant still lists service: %+v", rows)
	}
}
