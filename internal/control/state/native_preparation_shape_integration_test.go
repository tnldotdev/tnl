package state

import "testing"

func TestIntegrationNativePeerPairShapeCatalog(t *testing.T) {
	d, _, _ := newControlStateIntegrationDatabaseWithURL(t, "native_shape_catalog")
	var catalog, digest string
	if err := d.pool.QueryRow(t.Context(), nativePreparationCatalogSQL).Scan(&catalog); err != nil {
		t.Fatal(err)
	}
	if err := d.pool.QueryRow(t.Context(), "SELECT md5(("+nativePreparationCatalogSQL+"))").Scan(&digest); err != nil {
		t.Fatal(err)
	}
	t.Logf("native preparation catalog: %s", catalog)
	t.Logf("native preparation shape fingerprint: %s", digest)
	if digest != nativePreparationShapeFingerprint {
		t.Fatal("migration differs from the required native preparation catalog")
	}
}

func TestIntegrationNativePeerPairShapeAllEntrypoints(t *testing.T) {
	faults := map[string]string{
		"missing pairs":            `DROP TABLE control.native_peer_pairs CASCADE`,
		"missing claims":           `DROP TABLE control.native_peer_pair_leg_claims`,
		"missing owner":            `ALTER TABLE control.native_peer_pairs DROP COLUMN owner_key CASCADE`,
		"nullable owner":           `ALTER TABLE control.native_peer_pairs ALTER COLUMN owner_key DROP NOT NULL`,
		"owner uniqueness":         `ALTER TABLE control.native_peer_pairs DROP CONSTRAINT native_peer_pairs_owner_key`,
		"request uniqueness":       `ALTER TABLE control.native_peer_pairs DROP CONSTRAINT native_peer_pairs_request_key`,
		"stable owner weakened":    `ALTER TABLE control.native_peer_pairs DROP CONSTRAINT native_peer_pairs_stable_owner_key; ALTER TABLE control.native_peer_pairs ADD CONSTRAINT native_peer_pairs_stable_owner_key CHECK (true)`,
		"stable owner unvalidated": `ALTER TABLE control.native_peer_pairs DROP CONSTRAINT native_peer_pairs_stable_owner_key; ALTER TABLE control.native_peer_pairs ADD CONSTRAINT native_peer_pairs_stable_owner_key CHECK (owner_key=idempotency_key) NOT VALID`,
		"delivery zero allowed":    `ALTER TABLE control.native_peer_pairs DROP CONSTRAINT native_peer_pairs_delivery_id_nonzero; ALTER TABLE control.native_peer_pairs ADD CONSTRAINT native_peer_pairs_delivery_id_nonzero CHECK (octet_length(delivery_id)=16)`,
		"delivery uniqueness":      `ALTER TABLE control.native_peer_pairs DROP CONSTRAINT native_peer_pairs_delivery_id_key`,
		"missing parent":           `ALTER TABLE control.native_peer_pairs DROP COLUMN parent_control_session_id CASCADE`,
		"missing replay":           `ALTER TABLE control.native_peer_pairs DROP COLUMN replay_fence_until CASCADE`,
		"missing renewal digest":   `ALTER TABLE control.native_peer_pairs DROP COLUMN last_renewal_digest`,
		"missing report":           `ALTER TABLE control.native_peer_pairs DROP COLUMN publisher_prepared_until`,
		"missing claim check":      `ALTER TABLE control.native_peer_pair_leg_claims DROP COLUMN checked_at CASCADE`,
		"nullable claim expiry":    `ALTER TABLE control.native_peer_pair_leg_claims ALTER COLUMN confirmed_until DROP NOT NULL`,
		"fixed claim weakened":     `ALTER TABLE control.native_peer_pair_leg_claims DROP CONSTRAINT native_peer_claim_fixed_bound; ALTER TABLE control.native_peer_pair_leg_claims ADD CONSTRAINT native_peer_claim_fixed_bound CHECK (confirmed_until>checked_at AND confirmed_until<=checked_at+interval '10 minutes')`,
		"fixed claim unvalidated":  `ALTER TABLE control.native_peer_pair_leg_claims DROP CONSTRAINT native_peer_claim_fixed_bound; ALTER TABLE control.native_peer_pair_leg_claims ADD CONSTRAINT native_peer_claim_fixed_bound CHECK (confirmed_until>checked_at AND confirmed_until<=checked_at+interval '5 minutes') NOT VALID`,
		"claim process":            `ALTER TABLE control.native_peer_pair_leg_claims ALTER COLUMN relay_run_id DROP NOT NULL`,
		"claim source type":        `ALTER TABLE control.native_peer_pair_leg_claims ALTER COLUMN source_ip TYPE cidr USING source_ip::cidr`,
		"claim primary key":        `ALTER TABLE control.native_peer_pair_leg_claims DROP CONSTRAINT native_peer_pair_leg_claims_pkey; ALTER TABLE control.native_peer_pair_leg_claims ADD PRIMARY KEY(pair_id)`,
		"missing process key":      `ALTER TABLE control.relay_leases DROP COLUMN peer_signing_public_key`,
		"missing key history":      `DROP TABLE control.relay_run_signing_keys`,
		"nullable history key":     `ALTER TABLE control.relay_run_signing_keys ALTER COLUMN peer_signing_public_key DROP NOT NULL`,
		"generation sequence":      `ALTER SEQUENCE control.native_peer_delivery_generation INCREMENT 2`,
		"disabled enforcement":     `ALTER TABLE control.native_peer_pairs DISABLE TRIGGER ALL`,
		"unexpected stored shape":  `ALTER TABLE control.native_peer_pairs ADD COLUMN work_revision bigint NOT NULL DEFAULT 0`,
	}
	for fault, statement := range faults {
		t.Run(fault, func(t *testing.T) {
			d, url, _ := newControlStateIntegrationDatabaseWithURL(t, "native_shape_rejection")
			if err := Migrate(t.Context(), url); err != nil {
				t.Fatal("fresh repeated migration", err)
			}
			if _, err := d.pool.Exec(t.Context(), statement); err != nil {
				t.Fatal("shape fault not reached", err)
			}
			var before, after, identity string
			if err := d.pool.QueryRow(t.Context(), nativePreparationCatalogSQL).Scan(&before); err != nil {
				t.Fatal(err)
			}
			if err := d.pool.QueryRow(t.Context(), `SELECT baseline_id FROM control.schema_identity WHERE id=1`).Scan(&identity); err != nil || identity != "tnl-control-fresh-v1-public-reservations" {
				t.Fatal("fault changed the explicit intermediate identity", err)
			}
			if err := d.Readiness(t.Context()); err == nil {
				t.Fatal("readiness accepted incompatible native facts")
			}
			if err := Migrate(t.Context(), url); err == nil {
				t.Fatal("repeated migration accepted or repaired incompatible facts")
			}
			if reopened, err := Open(t.Context(), url, testStorageKey, ""); err == nil {
				reopened.Close()
				t.Fatal("open accepted incompatible native facts")
			}
			if err := d.pool.QueryRow(t.Context(), nativePreparationCatalogSQL).Scan(&after); err != nil || before != after {
				t.Fatal("entrypoint repaired or converted the incompatible catalog", err)
			}
		})
	}
}
