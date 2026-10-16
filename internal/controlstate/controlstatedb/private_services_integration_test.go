package controlstatedb

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"sync"
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
		bound_at, state, created_at, publisher_expires_at, ready_at, assignment_seed_ciphertext, assignment_seed_storage_key_id)
		VALUES ($1, $2, $3, 1, $4, $5, $6, 'run', $7, $7, $8, $7, $7, $9, $10,
			'starting', $10, $11, NULL, $7, 'fixture')`, run, service, team, publisher, publisherGrant, key, digest,
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
		relayRun := newID(opaqueid.RelayRunPrefix)
		exec(`INSERT INTO control.relay_leases(relay_id, relay_service_id, relay_run_id, relay_lease_revision,
			protocol_version, internal_relay_address, connection_capacity, stream_capacity, registered_at, renewed_at, lease_expires_at)
			VALUES ($1, $1, $2, 1, 1, $3, 8, 8, $4, $4, $5)`, relay, relayRun, relay+":444", now, now.Add(10*time.Minute))
		exec(`INSERT INTO control.private_service_connection_slots(publisher_connection_id, private_run_id,
			private_service_id, run_number, connection_slot, connection_assignment_revision, relay_service_id,
			relay_address, tls_server_name, credential_digest, credential_expires_at, relay_id, relay_run_id,
			relay_lease_revision, state)
			VALUES ($1, $2, $3, 1, $4, 1, $5, $6, $5, $7, $8, $5, $9, 1, 'ready')`,
			newID(opaqueid.PublisherConnectionPrefix), run, service, slot, relay, relay+":443",
			bytes.Repeat([]byte{byte(slot + 1)}, 32), now.Add(5*time.Minute), relayRun)
		if slot == 0 {
			if rows := list(visitor); len(rows) != 1 || rows[0].PrivateRunID.Valid || rows[0].RunNumber.Valid {
				t.Fatalf("first ready slot appeared routable: %+v", rows)
			}
			if err := issue(); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf("first ready slot ticket error = %v, want no rows", err)
			}
			if _, err := queries.ReadyPrivateServiceRun(t.Context(), ReadyPrivateServiceRunParams{
				ID: run, PrivateServiceID: service, RunNumber: 1,
				Now: pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true},
			}); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf("initial readiness accepted one slot: %v", err)
			}
		}
	}
	if _, err := queries.ReadyPrivateServiceRun(t.Context(), ReadyPrivateServiceRunParams{
		ID: run, PrivateServiceID: service, RunNumber: 1,
		Now: pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true},
	}); err != nil {
		t.Fatalf("initial readiness with two slots: %v", err)
	}
	if rows := list(visitor); len(rows) != 1 || !rows[0].PrivateRunID.Valid || rows[0].PrivateRunID.String != run || !rows[0].RunNumber.Valid || rows[0].RunNumber.Int64 != 1 {
		t.Fatalf("ready authorized service = %+v", rows)
	}
	if rows := list(outsider); len(rows) != 0 {
		t.Fatalf("unauthorized identity saw ready private service: %+v", rows)
	}
	exec(`UPDATE control.relay_leases SET registered_at=$2, renewed_at=$2, lease_expires_at=$3 WHERE relay_id=$1`, "relay-b", now.Add(-10*time.Minute), now.Add(-time.Second))
	if rows := list(visitor); len(rows) != 1 || rows[0].PrivateRunID.String != run {
		t.Fatalf("surviving relay disappeared from ready inventory: %+v", rows)
	}
	if _, err := queries.InsertPrivateServiceTicket(t.Context(), InsertPrivateServiceTicketParams{
		Digest: bytes.Repeat([]byte{9}, 32), IdentityID: visitor, ConnectorSessionID: session,
		PrivateServiceID: service, PrivateRunID: run,
		Now:       pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true},
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().UTC().Add(30 * time.Second), Valid: true},
	}); err != nil {
		t.Fatalf("surviving relay could not issue ticket: %v", err)
	}
	exec(`UPDATE control.relay_leases SET registered_at=$2, renewed_at=$2, lease_expires_at=$3 WHERE relay_id=$1`, "relay-b", now, now.Add(10*time.Minute))
	if err := issue(); err != nil {
		t.Fatalf("ready service did not issue ticket: %v", err)
	}
	lease := pgtype.Int8{Int64: 1, Valid: true}
	claim := func(ctx context.Context, q *Queries, secret []byte, sessionID string, source netip.Addr) error {
		_, err := q.ConsumePrivateServiceTicket(ctx, ConsumePrivateServiceTicketParams{
			Digest: secret, PrivateServiceID: service, PrivateRunID: run, RunNumber: 1,
			ConnectorSessionID: sessionID, ObservedSourceIp: source,
			VisitorConnectionID:  pgtype.Text{String: newID(opaqueid.VisitorConnectionPrefix), Valid: true},
			IngressID:            pgtype.Text{String: "ingress-a", Valid: true},
			IngressRunID:         pgtype.Text{String: ingressRun, Valid: true},
			IngressLeaseRevision: lease, Now: pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true},
		})
		return err
	}
	secondSession := newID(opaqueid.PrivateConnectorSessionPrefix)
	exec(`INSERT INTO control.private_connector_sessions(id, credential_digest, private_service_id, identity_id,
		created_at, expires_at, bound_at, source_ip, ingress_id, ingress_run_id, ingress_lease_revision)
		VALUES ($1, $2, $3, $4, $5, $6, $5, '192.0.2.10', 'ingress-a', $7, 1)`, secondSession,
		bytes.Repeat([]byte{2}, 32), service, visitor, now, now.Add(10*time.Minute), ingressRun)
	claimSession := func(id string, secret []byte) error {
		_, err := queries.ClaimPrivateConnectorSession(t.Context(), ClaimPrivateConnectorSessionParams{
			ID: id, CredentialDigest: secret, PrivateServiceID: service,
			ObservedSourceIp:     netip.MustParseAddr("192.0.2.10"),
			IngressID:            pgtype.Text{String: "ingress-a", Valid: true},
			IngressRunID:         pgtype.Text{String: ingressRun, Valid: true},
			IngressLeaseRevision: lease, Now: pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true},
		})
		return err
	}
	freshSession := newID(opaqueid.PrivateConnectorSessionPrefix)
	freshDigest := bytes.Repeat([]byte{4}, 32)
	exec(`INSERT INTO control.private_connector_sessions(id, credential_digest, private_service_id, identity_id, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, freshSession, freshDigest, service, visitor, now, now.Add(10*time.Minute))
	if err := claimSession(freshSession, freshDigest); err != nil {
		t.Fatalf("first session claim: %v", err)
	}
	if err := claimSession(freshSession, freshDigest); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("one-use session credential reused: %v", err)
	}
	if err := claim(t.Context(), queries, digest, secondSession, netip.MustParseAddr("192.0.2.10")); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("ticket used by another session: %v", err)
	}
	if err := claim(t.Context(), queries, digest, session, netip.MustParseAddr("192.0.2.11")); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("ticket used from another source: %v", err)
	}
	var attempts [2]error
	var wg sync.WaitGroup
	for i := range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			connection, err := pgx.Connect(t.Context(), databaseURL)
			if err != nil {
				attempts[i] = err
				return
			}
			defer connection.Close(context.Background())
			attempts[i] = claim(t.Context(), New(connection), digest, session, netip.MustParseAddr("192.0.2.10"))
		}()
	}
	wg.Wait()
	if !((attempts[0] == nil && errors.Is(attempts[1], pgx.ErrNoRows)) ||
		(attempts[1] == nil && errors.Is(attempts[0], pgx.ErrNoRows))) {
		t.Fatalf("concurrent one-use claims: %v, %v", attempts[0], attempts[1])
	}
	var consumedVisitorID string
	if err := conn.QueryRow(t.Context(), `SELECT visitor_connection_id FROM control.private_service_tickets WHERE digest=$1`, digest).Scan(&consumedVisitorID); err != nil {
		t.Fatal(err)
	}
	recheck := func(at time.Time) bool {
		t.Helper()
		decision, err := queries.RecheckPrivateServiceVisitor(t.Context(), RecheckPrivateServiceVisitorParams{
			PrivateServiceID: service, PrivateRunID: run, RunNumber: 1,
			ConnectorSessionID: session, IdentityID: visitor,
			VisitorConnectionID: pgtype.Text{String: consumedVisitorID, Valid: true},
			ObservedSourceIp:    netip.MustParseAddr("192.0.2.10"), Now: pgtype.Timestamptz{Time: at, Valid: true},
			IngressID:    pgtype.Text{String: "ingress-a", Valid: true},
			IngressRunID: pgtype.Text{String: ingressRun, Valid: true}, IngressLeaseRevision: lease,
		})
		if err != nil {
			t.Fatal(err)
		}
		if decision.Allowed && (!decision.ValidUntil.Valid || !decision.ValidUntil.Time.After(at) || decision.ValidUntil.Time.After(at.Add(2*time.Minute))) {
			t.Fatalf("unbounded recheck decision: %+v", decision)
		}
		return decision.Allowed
	}
	if !recheck(now.Add(65 * time.Second)) {
		t.Fatal("one-use ticket expiration ended an already admitted visitor")
	}
	// the connector credential expires after ten minutes. only new streams use
	// that deadline; an admitted stream still needs a live run, lease and grant.
	exec(`UPDATE control.private_service_runs SET publisher_expires_at=$2 WHERE id=$1`, run, now.Add(15*time.Minute))
	exec(`UPDATE control.ingress_leases SET lease_expires_at=$2 WHERE ingress_id=$1`, "ingress-a", now.Add(15*time.Minute))
	exec(`UPDATE control.relay_leases SET lease_expires_at=$1`, now.Add(15*time.Minute))
	if !recheck(now.Add(11 * time.Minute)) {
		t.Fatal("expired outer connector credential killed admitted visitor")
	}
	// a second, still-unclaimed ticket must be invalidated when its grant ends.
	otherDigest := bytes.Repeat([]byte{3}, 32)
	if _, err := queries.InsertPrivateServiceTicket(t.Context(), InsertPrivateServiceTicketParams{
		Digest: otherDigest, IdentityID: visitor, ConnectorSessionID: session,
		PrivateServiceID: service, PrivateRunID: run,
		Now:       pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true},
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().UTC().Add(30 * time.Second), Valid: true},
	}); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE control.private_service_grants SET revoked_at = $2 WHERE id = $1`, grant, time.Now().UTC())
	if recheck(time.Now().UTC()) {
		t.Fatal("revoked grant kept consumed visitor")
	}
	unclaimed := newID(opaqueid.PrivateConnectorSessionPrefix)
	exec(`INSERT INTO control.private_connector_sessions(id, credential_digest, private_service_id, identity_id, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, unclaimed, bytes.Repeat([]byte{5}, 32), service, visitor, now, now.Add(10*time.Minute))
	if err := claimSession(unclaimed, bytes.Repeat([]byte{5}, 32)); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("revoked visitor grant accepted pending mux session: %v", err)
	}
	if err := claim(t.Context(), queries, otherDigest, session, netip.MustParseAddr("192.0.2.10")); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("revoked visitor grant accepted old ticket: %v", err)
	}
	exec(`UPDATE control.private_service_grants SET revoked_at = NULL WHERE id = $1`, grant)
	exec(`UPDATE control.private_service_runs SET state = 'closed', closed_at = $2 WHERE id = $1`, run, time.Now().UTC())
	replacement := newID(opaqueid.PrivateRunPrefix)
	exec(`INSERT INTO control.private_service_runs(id, private_service_id, team_id, run_number,
		publisher_identity_id, publisher_grant_id, publisher_key_id, idempotency_key, request_digest,
		binding_nonce, binding_expires_at, run_token_digest, stream_public_key, stream_key_binding_signature,
		bound_at, state, created_at, publisher_expires_at, ready_at, assignment_seed_ciphertext, assignment_seed_storage_key_id)
		VALUES ($1, $2, $3, 2, $4, $5, $6, 'replacement', $7, $7, $8, $12, $7, $9, $10,
			'starting', $10, $11, NULL, $7, 'fixture')`, replacement, service, team, publisher, publisherGrant, key, digest,
		now.Add(2*time.Minute), make([]byte, 64), now, now.Add(10*time.Minute), bytes.Repeat([]byte{6}, 32))
	if err := claim(t.Context(), queries, otherDigest, session, netip.MustParseAddr("192.0.2.10")); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("replacement run accepted ticket from closed run: %v", err)
	}
	if rows := list(visitor); len(rows) != 1 || rows[0].PrivateRunID.Valid || rows[0].RunNumber.Valid {
		t.Fatalf("closed run removed saved service or retained ready state: %+v", rows)
	}
	if err := issue(); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("closed run ticket error = %v, want no rows", err)
	}
	for slot := range 2 {
		relay := "relay-a"
		if slot == 1 {
			relay = "relay-b"
		}
		var relayRun string
		if err := conn.QueryRow(t.Context(), `SELECT relay_run_id FROM control.relay_leases WHERE relay_id=$1`, relay).Scan(&relayRun); err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO control.private_service_connection_slots(publisher_connection_id, private_run_id,
			private_service_id, run_number, connection_slot, connection_assignment_revision, relay_service_id,
			relay_address, tls_server_name, credential_digest, credential_expires_at, relay_id, relay_run_id,
			relay_lease_revision, state)
			VALUES ($1, $2, $3, 2, $4, 1, $5, $6, $5, $7, $8, $5, $9, 1, 'ready')`,
			newID(opaqueid.PublisherConnectionPrefix), replacement, service, slot, relay, relay+":443",
			bytes.Repeat([]byte{byte(slot + 7)}, 32), now.Add(5*time.Minute), relayRun)
		if slot == 0 {
			if rows := list(visitor); len(rows) != 1 || rows[0].PrivateRunID.Valid {
				t.Fatalf("replacement first slot appeared ready before promotion: %+v", rows)
			}
		}
	}
	if _, err := queries.ReadyPrivateServiceRun(t.Context(), ReadyPrivateServiceRunParams{
		ID: replacement, PrivateServiceID: service, RunNumber: 2,
		Now: pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true},
	}); err != nil {
		t.Fatalf("ready replacement run: %v", err)
	}
	if rows := list(visitor); len(rows) != 1 || rows[0].PrivateRunID.String != replacement || rows[0].RunNumber.Int64 != 2 {
		t.Fatalf("replacement ready run was not selected: %+v", rows)
	}
	if err := claim(t.Context(), queries, otherDigest, session, netip.MustParseAddr("192.0.2.10")); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("ready replacement accepted old run ticket: %v", err)
	}
	exec(`UPDATE control.private_service_grants SET revoked_at = $2 WHERE id = $1`, grant, time.Now().UTC())
	if rows := list(visitor); len(rows) != 0 {
		t.Fatalf("revoked visitor grant still lists service: %+v", rows)
	}
}
