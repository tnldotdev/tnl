package state

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestIntegrationNativePeerPairSchemaConstraints(t *testing.T) {
	f := newNativePairFixture(t)
	pair := f.create(t)
	otherRequest := f.request
	otherRequest.IdempotencyKey = "schema-other-owner"
	f.sign(t, &otherRequest)
	other, err := f.d.PrepareNativePeerPair(f.visitor, otherRequest, f.now)
	if err != nil {
		t.Fatal(err)
	}
	// the five-minute endpoint is valid; each rejected update below must leave
	// this complete, valid claim intact rather than fail on an unrelated field.
	if _, err := f.d.pool.Exec(t.Context(), `INSERT INTO control.native_peer_pair_leg_claims
		(pair_id,connection_slot,requested_at,checked_at,confirmed_until,nonce_digest,source_ip,relay_id,relay_run_id,relay_lease_revision)
		VALUES ($1,0,$2,$2,$2::timestamptz+interval '5 minutes',decode(repeat('01',32),'hex'),'192.0.2.8',$3,$4,$5)`,
		pair.ID, f.now, pair.Relays[0].RelayLease.RelayID, pair.Relays[0].RelayLease.RelayRunID, pair.Relays[0].RelayLease.RelayLeaseRevision); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, query, code string
		id                string
	}{
		{"stable owner", `UPDATE control.native_peer_pairs SET owner_key='different-owner' WHERE id=$1`, "23514", pair.ID},
		{"required owner", `UPDATE control.native_peer_pairs SET owner_key=NULL WHERE id=$1`, "23502", pair.ID},
		{"parent foreign key", `UPDATE control.native_peer_pairs SET parent_control_session_id='missing-control-session' WHERE id=$1`, "23503", pair.ID},
		{"owner uniqueness", `UPDATE control.native_peer_pairs SET owner_key='observations',idempotency_key='observations' WHERE id=$1`, "23505", other.ID},
		{"delivery uniqueness", `UPDATE control.native_peer_pairs SET delivery_id=(SELECT delivery_id FROM control.native_peer_pairs WHERE id=$2) WHERE id=$1`, "23505", other.ID},
		{"nonzero delivery", `UPDATE control.native_peer_pairs SET delivery_id=decode(repeat('00',16),'hex') WHERE id=$1`, "23514", pair.ID},
		{"replay horizon", `UPDATE control.native_peer_pairs SET replay_fence_until=last_request_at+interval '1 minute' WHERE id=$1`, "23514", pair.ID},
		{"claim positive bound", `UPDATE control.native_peer_pair_leg_claims SET confirmed_until=checked_at WHERE pair_id=$1`, "23514", pair.ID},
		{"claim negative bound", `UPDATE control.native_peer_pair_leg_claims SET confirmed_until=checked_at-interval '1 microsecond' WHERE pair_id=$1`, "23514", pair.ID},
		{"claim fixed bound", `UPDATE control.native_peer_pair_leg_claims SET confirmed_until=checked_at+interval '5 minutes 1 microsecond' WHERE pair_id=$1`, "23514", pair.ID},
		{"required claim expiry", `UPDATE control.native_peer_pair_leg_claims SET confirmed_until=NULL WHERE pair_id=$1`, "23502", pair.ID},
		{"required claim process", `UPDATE control.native_peer_pair_leg_claims SET relay_run_id=NULL WHERE pair_id=$1`, "23502", pair.ID},
		{"claim slot", `UPDATE control.native_peer_pair_leg_claims SET connection_slot=2 WHERE pair_id=$1`, "23514", pair.ID},
		{"claim foreign key", `UPDATE control.native_peer_pair_leg_claims SET pair_id='npp_0000000000000000000000' WHERE pair_id=$1`, "23503", pair.ID},
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
	if _, err := f.d.pool.Exec(t.Context(), `INSERT INTO control.native_peer_pair_leg_claims
		SELECT pair_id,1,requested_at,checked_at,confirmed_until,nonce_digest,source_ip,relay_id,relay_run_id,relay_lease_revision
		FROM control.native_peer_pair_leg_claims WHERE pair_id=$1 AND connection_slot=0`, pair.ID); err != nil {
		t.Fatal("sibling claim", err)
	}
	_, err = f.d.pool.Exec(t.Context(), `INSERT INTO control.native_peer_pair_leg_claims
		SELECT * FROM control.native_peer_pair_leg_claims WHERE pair_id=$1 AND connection_slot=0`, pair.ID)
	var constraint *pgconn.PgError
	if !errors.As(err, &constraint) || constraint.Code != "23505" {
		t.Fatal("duplicate claim did not hit its primary key", err)
	}
	tx, err := f.d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	if _, err := tx.Exec(t.Context(), `DELETE FROM control.native_peer_pairs WHERE id=$1`, pair.ID); err != nil {
		t.Fatal(err)
	}
	var claims int
	if err := tx.QueryRow(t.Context(), `SELECT count(*) FROM control.native_peer_pair_leg_claims WHERE pair_id=$1`, pair.ID).Scan(&claims); err != nil || claims != 0 {
		t.Fatal("pair deletion did not cascade to both claims", claims, err)
	}
}

func TestIntegrationNativePeerPairShapeCatalog(t *testing.T) {
	d, _, _ := newControlStateIntegrationDatabaseWithURL(t, "native_shape_catalog")
	// schema facts belong to migration tests, not repeated serving probes.
	for table, columns := range map[string]map[string]string{
		"native_peer_pairs": {
			"owner_key": "text NO", "idempotency_key": "text NO", "delivery_id": "bytea NO",
			"parent_control_session_id": "text YES", "replay_fence_until": "timestamp with time zone NO",
			"last_renewal_digest": "bytea YES", "publisher_prepared_until": "timestamp with time zone YES",
		},
		"native_peer_pair_leg_claims": {
			"pair_id": "text NO", "connection_slot": "smallint NO", "source_ip": "inet NO",
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
		{"native_peer_pairs", "native_peer_pairs_owner_key", "u"},
		{"native_peer_pairs", "native_peer_pairs_request_key", "u"},
		{"native_peer_pairs", "native_peer_pairs_delivery_id_key", "u"},
		{"native_peer_pairs", "native_peer_pairs_stable_owner_key", "c"},
		{"native_peer_pairs", "native_peer_pairs_delivery_id_nonzero", "c"},
		{"native_peer_pair_leg_claims", "native_peer_pair_leg_claims_pkey", "p"},
		{"native_peer_pair_leg_claims", "native_peer_claim_fixed_bound", "c"},
	} {
		var kind string
		var validated, deferred, deferrable bool
		if err := d.pool.QueryRow(t.Context(), `SELECT contype::text,convalidated,condeferred,condeferrable
			FROM pg_constraint WHERE conrelid=('control.' || $1)::regclass AND conname=$2`, test.table, test.constraint).
			Scan(&kind, &validated, &deferred, &deferrable); err != nil || kind != test.kind || !validated || deferred || deferrable {
			t.Errorf("%s enforcement = %q/%t/%t/%t, %v", test.constraint, kind, validated, deferred, deferrable, err)
		}
	}
	for _, index := range []string{"native_peer_pairs_expiry", "native_peer_pairs_run_inventory", "relay_run_signing_keys_superseded"} {
		var valid bool
		if err := d.pool.QueryRow(t.Context(), `SELECT indisvalid AND indisready AND indislive FROM pg_index WHERE indexrelid=('control.' || $1)::regclass`, index).Scan(&valid); err != nil || !valid {
			t.Errorf("%s is not a usable index: %v", index, err)
		}
	}
	var enforced bool
	if err := d.pool.QueryRow(t.Context(), `SELECT NOT EXISTS (SELECT 1 FROM pg_trigger t
		LEFT JOIN pg_constraint k ON k.oid=t.tgconstraint WHERE t.tgenabled<>'O' AND
		(t.tgrelid IN ('control.native_peer_pairs'::regclass,'control.native_peer_pair_leg_claims'::regclass,'control.relay_run_signing_keys'::regclass)
		OR k.conrelid IN ('control.native_peer_pairs'::regclass,'control.native_peer_pair_leg_claims'::regclass,'control.relay_run_signing_keys'::regclass)))`).Scan(&enforced); err != nil || !enforced {
		t.Fatal("native schema enforcement is disabled", err)
	}
	var increment int64
	if err := d.pool.QueryRow(t.Context(), `SELECT seqincrement FROM pg_sequence WHERE seqrelid='control.native_peer_delivery_generation'::regclass`).Scan(&increment); err != nil || increment != 1 {
		t.Fatal("native delivery sequence increment", increment, err)
	}
}
