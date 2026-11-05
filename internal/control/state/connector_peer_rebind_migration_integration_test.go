package state

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io/fs"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/tnldotdev/tnl/internal/control/storagekey"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestIntegrationConnectorRebindUpgradesVersionOneWithoutInventingSessions(t *testing.T) {
	ctx := t.Context()
	url := newDisposableControlStateDatabaseURL(t, "connector_rebind_upgrade")
	config, err := parseDirectConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	connection := stdlib.OpenDB(*config)
	defer connection.Close()
	if err := ensureMigrationLock(ctx, connection); err != nil {
		t.Fatal(err)
	}
	migrations, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, connection, migrations, goose.WithTableName(versionTable), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if old, err := Open(ctx, url, testStorageKey, ""); err == nil {
		old.Close()
		t.Fatal("new serving binaries accepted schema version one")
	}
	poolConfig, err := parsePoolConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	keyring, err := storagekey.New(testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	// only the fixture bypasses serving-version checks to create real v1 records.
	d := &Database{pool: pool, storageKey: keyring, activity: new(queryActivity), connections: new(connectionActivity)}
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, _, request, leases := publishRunPrerequisitesInDatabase(t, d, now, func(run string) []byte {
		seed := sha256.Sum256([]byte(run))
		return ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	})
	f := connectorPairFixtureFromRun(t, publishRunFixture{database: d, now: now, request: request, leases: leases})
	id, err := opaqueid.New("cpp_")
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{9}, 32)
	digest := sha256.Sum256(secret)
	ciphertext, err := keyring.Seal(connectorPeerPairKeyContext(id), secret)
	if err != nil {
		t.Fatal(err)
	}
	slots, err := json.Marshal(f.request.ExpectedRelays)
	if err != nil {
		t.Fatal(err)
	}
	parent := f.visitor.Value(controlPrincipalKey{}).(ControlPrincipal)
	_, err = pool.Exec(ctx, `INSERT INTO control.connector_peer_pairs
		(id,service_id,service_run_id,run_number,publisher_identity_id,subject_kind,subject_id,parent_control_session_id,
		owner_key,idempotency_key,request_digest,key_digest,key_ciphertext,delivery_id,storage_key_id,slots,delivery_generation,
		created_at,last_authorized_at,last_request_at,replay_fence_until,expires_at,publisher_prepared_until)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$10,$10,$11,$12,$13,$14,17,$15,$15,$15,$16,$17,$17)`,
		id, f.request.ServiceID, f.run.RunID, f.run.RunNumber, f.request.PublisherIdentityID,
		f.request.Subject.Kind, f.request.Subject.DeviceID, parent.SessionID, f.request.IdempotencyKey, digest[:], ciphertext,
		bytes.Repeat([]byte{7}, 16), keyring.CurrentID(), string(slots), now, now.Add(5*time.Minute), now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	relay := f.request.ExpectedRelays[0].RelayLease
	_, err = pool.Exec(ctx, `INSERT INTO control.connector_peer_pair_leg_claims
		(pair_id,connection_slot,requested_at,nonce_digest,source_ip,relay_id,relay_run_id,relay_lease_revision,checked_at,confirmed_until)
		VALUES($1,0,$2,$3,'192.0.2.10',$4,$5,$6,$2,$7)`, id, now, digest[:], relay.RelayID, relay.RelayRunID, int64(relay.RelayLeaseRevision), now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, url); err != nil {
		t.Fatal("repeat upgrade", err)
	}
	upgraded, err := Open(ctx, url, testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	var retained bool
	if err := pool.QueryRow(ctx, `SELECT pair.delivery_generation=17 AND pair.high_water_generation=17
		AND pair.session_key_ciphertext IS NULL AND pair.publisher_prepared_until IS NULL
		AND pair.key_ciphertext=$2 AND pair.replay_fence_until=$3 AND claim.delivery_generation=17
		AND identity.baseline_id=$4 FROM control.connector_peer_pairs pair
		JOIN control.connector_peer_pair_leg_claims claim ON claim.pair_id=pair.id CROSS JOIN control.schema_identity identity WHERE pair.id=$1`,
		id, ciphertext, now.Add(5*time.Minute), baselineID).Scan(&retained); err != nil || !retained {
		t.Fatal("upgrade lost records, changed baseline, or fabricated a session", err)
	}
	renew := f.request
	renew.Action, renew.PreviousPairID, renew.PreviousGeneration, renew.RequestedAt = "renew", id, 17, now.Add(time.Second)
	f.sign(t, &renew)
	if _, err := upgraded.RenewConnectorPeerPair(f.visitor, "https://control.example.test", renew, renew.RequestedAt); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("upgrade reconstructed a process-local session", err)
	}
}
