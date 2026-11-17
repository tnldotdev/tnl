package state

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func connectorPairConstraintInsert(owner, idempotency, parent, delivery string) string {
	return fmt.Sprintf(`INSERT INTO control.connector_peer_pairs
		(id,service_id,service_run_id,run_number,publisher_identity_id,subject_kind,subject_id,parent_control_session_id,
		owner_key,idempotency_key,owner_public_key,request_digest,key_digest,key_ciphertext,delivery_id,storage_key_id,slots,
		delivery_generation,created_at,last_authorized_at,last_request_at,replay_fence_until,expires_at)
		SELECT 'cpp_aaaaaaaaaaaaaaaaaaaaaa',service_id,service_run_id,run_number,publisher_identity_id,subject_kind,subject_id,%s,
		%s,%s,owner_public_key,request_digest,key_digest,key_ciphertext,%s,storage_key_id,slots,
		nextval('control.connector_peer_delivery_generation'),created_at,last_authorized_at,last_request_at,replay_fence_until,expires_at
		FROM control.connector_peer_pairs WHERE id=$1`, parent, owner, idempotency, delivery)
}

func TestIntegrationConnectorPeerPairSchemaConstraints(t *testing.T) {
	f := newConnectorPairFixture(t)
	pair := f.create(t)
	otherRequest := f.request
	otherRequest.IdempotencyKey = "schema-other-owner"
	f.sign(t, &otherRequest)
	other, err := f.d.PrepareConnectorPeerPair(f.visitor, otherRequest, f.now)
	if err != nil {
		t.Fatal(err)
	}
	// the five-minute endpoint is valid; each rejected update below must leave
	// this complete, valid claim intact rather than fail on an unrelated field.
	sourceDigest, err := f.d.serviceIPDigest(t.Context(), controlstatedb.New(f.d.pool), pair.ServiceID, connectorSourceIPKeyPurpose, netip.MustParseAddr("192.0.2.8"))
	if err != nil {
		t.Fatal(err)
	}
	sourceCiphertext, err := f.d.storageKey.Seal(connectorSourceContext(pair.ID, pair.DeliveryGeneration, 0), netip.MustParseAddr("192.0.2.8").AsSlice())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.pool.Exec(t.Context(), `INSERT INTO control.connector_peer_pair_leg_claims
		(pair_id,connection_slot,requested_at,checked_at,confirmed_until,nonce_digest,source_digest,source_ciphertext,source_storage_key_id,relay_id,relay_run_id,relay_lease_revision,delivery_generation)
		VALUES ($1,0,$2,$2,$2::timestamptz+interval '5 minutes',decode(repeat('01',32),'hex'),$7,$8,$9,$3,$4,$5,$6)`,
		pair.ID, f.now, pair.Relays[0].RelayLease.RelayID, pair.Relays[0].RelayLease.RelayRunID, pair.Relays[0].RelayLease.RelayLeaseRevision, pair.DeliveryGeneration, sourceDigest, sourceCiphertext, f.d.storageKey.CurrentID()); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, query, code string
		id                string
	}{
		{"stable owner", `UPDATE control.connector_peer_pairs SET owner_key='different-owner' WHERE id=$1`, "23514", pair.ID},
		{"required owner", connectorPairConstraintInsert("NULL", "'new-owner'", "parent_control_session_id", "delivery_id"), "23502", pair.ID},
		{"parent foreign key", connectorPairConstraintInsert("'new-owner'", "'new-owner'", "'missing-control-session'", "decode(repeat('03',16),'hex')"), "23503", pair.ID},
		{"owner uniqueness", connectorPairConstraintInsert("'observations'", "'observations'", "parent_control_session_id", "decode(repeat('03',16),'hex')"), "23505", other.ID},
		{"delivery uniqueness", connectorPairConstraintInsert("'duplicate-delivery-owner'", "'duplicate-delivery-owner'", "parent_control_session_id", "(SELECT delivery_id FROM control.connector_peer_pairs WHERE id=$2)"), "23505", other.ID},
		{"nonzero delivery", connectorPairConstraintInsert("'new-owner'", "'new-owner'", "parent_control_session_id", "decode(repeat('00',16),'hex')"), "23514", pair.ID},
		{"replay horizon", `UPDATE control.connector_peer_pairs SET replay_fence_until=last_request_at+interval '1 minute' WHERE id=$1`, "23514", pair.ID},
		{"claim positive bound", `UPDATE control.connector_peer_pair_leg_claims SET confirmed_until=checked_at WHERE pair_id=$1`, "23514", pair.ID},
		{"claim negative bound", `UPDATE control.connector_peer_pair_leg_claims SET confirmed_until=checked_at-interval '1 microsecond' WHERE pair_id=$1`, "23514", pair.ID},
		{"claim fixed bound", `UPDATE control.connector_peer_pair_leg_claims SET confirmed_until=checked_at+interval '5 minutes 1 microsecond' WHERE pair_id=$1`, "23514", pair.ID},
		{"required claim expiry", `UPDATE control.connector_peer_pair_leg_claims SET confirmed_until=NULL WHERE pair_id=$1`, "23502", pair.ID},
		{"required claim process", `UPDATE control.connector_peer_pair_leg_claims SET relay_run_id=NULL WHERE pair_id=$1`, "23502", pair.ID},
		{"claim slot", `UPDATE control.connector_peer_pair_leg_claims SET connection_slot=2 WHERE pair_id=$1`, "23514", pair.ID},
		{"required claim generation", `UPDATE control.connector_peer_pair_leg_claims SET delivery_generation=NULL WHERE pair_id=$1`, "23502", pair.ID},
		{"positive claim generation", `UPDATE control.connector_peer_pair_leg_claims SET delivery_generation=0 WHERE pair_id=$1`, "23514", pair.ID},
		{"claim foreign key", `UPDATE control.connector_peer_pair_leg_claims SET pair_id='cpp_0000000000000000000000' WHERE pair_id=$1`, "23503", pair.ID},
		{"process key length", `UPDATE control.relay_leases SET peer_signing_public_key=decode('01','hex') WHERE relay_id=$1`, "23514", pair.Relays[0].RelayLease.RelayID},
		{"required history key", `UPDATE control.relay_run_signing_keys SET peer_signing_public_key=NULL WHERE relay_id=$1`, "23502", pair.Relays[0].RelayLease.RelayID},
		{"history key length", `UPDATE control.relay_run_signing_keys SET peer_signing_public_key=decode('01','hex') WHERE relay_id=$1`, "23514", pair.Relays[0].RelayLease.RelayID},
		{"history key uniqueness", `INSERT INTO control.relay_run_signing_keys (relay_id,relay_run_id,peer_signing_public_key)
			SELECT relay_id,relay_run_id || '-other',peer_signing_public_key FROM control.relay_run_signing_keys WHERE relay_id=$1`, "23505", pair.Relays[0].RelayLease.RelayID},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := []any{test.id}
			if test.name == "delivery uniqueness" {
				args = append(args, pair.ID)
			}
			result, err := f.d.pool.Exec(t.Context(), test.query, args...)
			var constraint *pgconn.PgError
			if !errors.As(err, &constraint) || constraint.Code != test.code {
				t.Fatalf("write affected %d rows with error %v; want SQLSTATE %s", result.RowsAffected(), err, test.code)
			}
		})
	}
	// both leg keys are usable, but neither can be inserted twice.
	if _, err := f.d.pool.Exec(t.Context(), `INSERT INTO control.connector_peer_pair_leg_claims
		SELECT pair_id,1,requested_at,checked_at,confirmed_until,nonce_digest,source_digest,source_ciphertext,source_storage_key_id,relay_id,relay_run_id,relay_lease_revision,delivery_generation
		FROM control.connector_peer_pair_leg_claims WHERE pair_id=$1 AND connection_slot=0`, pair.ID); err != nil {
		t.Fatal("sibling claim", err)
	}
	_, err = f.d.pool.Exec(t.Context(), `INSERT INTO control.connector_peer_pair_leg_claims
		SELECT * FROM control.connector_peer_pair_leg_claims WHERE pair_id=$1 AND connection_slot=0`, pair.ID)
	var constraint *pgconn.PgError
	if !errors.As(err, &constraint) || constraint.Code != "23505" {
		t.Fatal("duplicate claim did not hit its primary key", err)
	}
	tx, err := f.d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	if _, err := tx.Exec(t.Context(), `DELETE FROM control.connector_peer_pairs WHERE id=$1`, pair.ID); err != nil {
		t.Fatal(err)
	}
	var claims int
	if err := tx.QueryRow(t.Context(), `SELECT count(*) FROM control.connector_peer_pair_leg_claims WHERE pair_id=$1`, pair.ID).Scan(&claims); err != nil || claims != 0 {
		t.Fatal("pair deletion did not cascade to both claims", claims, err)
	}
}

func TestIntegrationConnectorPeerPairShapeCatalog(t *testing.T) {
	d, _, _ := newControlStateIntegrationDatabaseWithURL(t, "native_shape_catalog")
	// schema facts belong to migration tests, not repeated serving probes.
	for table, columns := range map[string]map[string]string{
		"connector_peer_pairs": {
			"owner_key": "text NO", "idempotency_key": "text NO", "delivery_id": "bytea NO",
			"parent_control_session_id": "text YES", "replay_fence_until": "timestamp with time zone NO",
			"last_renewal_digest": "bytea YES", "publisher_prepared_until": "timestamp with time zone YES",
			"owner_public_key": "bytea NO", "owner_revision": "bigint NO",
			"retired_at": "timestamp with time zone YES", "retire_request_digest": "bytea YES",
		},
		"connector_peer_pair_leg_claims": {
			"pair_id": "text NO", "connection_slot": "smallint NO", "source_digest": "text NO",
			"source_ciphertext": "bytea NO", "source_storage_key_id": "text NO",
			"checked_at": "timestamp with time zone NO", "confirmed_until": "timestamp with time zone NO",
			"relay_run_id": "text NO", "relay_lease_revision": "bigint NO",
		},
		"relay_leases":           {"peer_signing_public_key": "bytea YES"},
		"relay_run_signing_keys": {"relay_id": "text NO", "relay_run_id": "text NO", "peer_signing_public_key": "bytea NO"},
	} {
		for column, want := range columns {
			var got string
			if err := d.pool.QueryRow(t.Context(), `SELECT data_type || ' ' || is_nullable
				FROM information_schema.columns WHERE table_schema='control' AND table_name=$1 AND column_name=$2`, table, column).Scan(&got); err != nil || got != want {
				t.Errorf("%s.%s = %q, %v; want %q", table, column, got, err, want)
			}
		}
	}
	for _, test := range []struct{ table, constraint, kind string }{
		{"connector_peer_pairs", "connector_peer_pairs_owner_key", "u"},
		{"connector_peer_pairs", "connector_peer_pairs_request_key", "u"},
		{"connector_peer_pairs", "connector_peer_pairs_delivery_id_key", "u"},
		{"connector_peer_pairs", "connector_peer_pairs_stable_owner_key", "c"},
		{"connector_peer_pairs", "connector_peer_pairs_delivery_id_nonzero", "c"},
		{"connector_peer_pair_leg_claims", "connector_peer_pair_leg_claims_pkey", "p"},
		{"connector_peer_pair_leg_claims", "connector_peer_claim_fixed_bound", "c"},
	} {
		var kind string
		var validated, deferred, deferrable bool
		if err := d.pool.QueryRow(t.Context(), `SELECT contype::text,convalidated,condeferred,condeferrable
			FROM pg_constraint WHERE conrelid=('control.' || $1)::regclass AND conname=$2`, test.table, test.constraint).
			Scan(&kind, &validated, &deferred, &deferrable); err != nil || kind != test.kind || !validated || deferred || deferrable {
			t.Errorf("%s enforcement = %q/%t/%t/%t, %v", test.constraint, kind, validated, deferred, deferrable, err)
		}
	}
	for _, index := range []string{"connector_peer_pairs_expiry", "connector_peer_pairs_run_inventory", "relay_run_signing_keys_superseded"} {
		var valid bool
		if err := d.pool.QueryRow(t.Context(), `SELECT indisvalid AND indisready AND indislive FROM pg_index WHERE indexrelid=('control.' || $1)::regclass`, index).Scan(&valid); err != nil || !valid {
			t.Errorf("%s is not a usable index: %v", index, err)
		}
	}
	var enforced bool
	if err := d.pool.QueryRow(t.Context(), `SELECT NOT EXISTS (SELECT 1 FROM pg_trigger t
		LEFT JOIN pg_constraint k ON k.oid=t.tgconstraint WHERE t.tgenabled<>'O' AND
		(t.tgrelid IN ('control.connector_peer_pairs'::regclass,'control.connector_peer_pair_leg_claims'::regclass,'control.relay_run_signing_keys'::regclass)
		OR k.conrelid IN ('control.connector_peer_pairs'::regclass,'control.connector_peer_pair_leg_claims'::regclass,'control.relay_run_signing_keys'::regclass)))`).Scan(&enforced); err != nil || !enforced {
		t.Fatal("native schema enforcement is disabled", err)
	}
	var increment int64
	if err := d.pool.QueryRow(t.Context(), `SELECT seqincrement FROM pg_sequence WHERE seqrelid='control.connector_peer_delivery_generation'::regclass`).Scan(&increment); err != nil || increment != 1 {
		t.Fatal("connector delivery sequence increment", increment, err)
	}
}
