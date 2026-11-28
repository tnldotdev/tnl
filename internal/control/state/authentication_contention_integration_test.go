package state

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationLoginWaitDoesNotBlockAnotherSubject(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "login_contention")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	identity := OIDCIdentity{Issuer: "https://identity.example", Subject: "first", DisplayName: "first",
		AssertionDigest: sha256.Sum256([]byte("initial")), AssertionExpiry: now.Add(time.Hour)}
	create := func(ctx context.Context, identity OIDCIdentity) (ControlSession, error) {
		return d.CreateOIDCControlSession(ctx, "tunnels.example.test", identity, time.Hour, 24*time.Hour, now)
	}
	initial, err := create(ctx, identity)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := gate.Exec(ctx, `SELECT id FROM control.identities WHERE id=$1 FOR UPDATE`, initial.Identity.Identity.ID); err != nil {
		t.Fatal(err)
	}
	identity.AssertionDigest = sha256.Sum256([]byte("waiting"))
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	done := make(chan error, 1)
	workers.Go(func() {
		_, err := create(ctx, identity)
		done <- err
	})
	waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
	other := identity
	other.Subject, other.DisplayName = "second", "second"
	other.AssertionDigest = sha256.Sum256([]byte("second"))
	progress, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	session, err := create(progress, other)
	if err != nil || session.Identity.Identity.ID == initial.Identity.Identity.ID {
		t.Fatal("one identity blocked another subject's login", err)
	}
	if _, err := create(progress, other); !errors.Is(err, ErrOIDCAssertionReplay) {
		t.Fatal("concurrent login changed assertion replay protection", err)
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, done); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationDeviceLoginsOutgrowInventoryAndCleanupIsBounded(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "device_inventory")
	ctx := t.Context()
	if _, _, err := d.CreateDeviceLogin(ctx, DeviceLoginOptions{}, now); err != nil {
		t.Fatal(err)
	}
	// saved rows are enough to exercise admission; only the new login's sealed
	// payload is consumed. keep the backlog live while creating it.
	if _, err := d.pool.Exec(ctx, `INSERT INTO control.device_logins(credential_digest,user_code,expires_at,payload,storage_key_id)
	    SELECT sha256(('inventory/'||n)::bytea),'inventory/'||n,$1,payload,storage_key_id
	    FROM generate_series(1,10000) n CROSS JOIN (SELECT payload,storage_key_id FROM control.device_logins LIMIT 1) seed`, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	login, credential, err := d.CreateDeviceLogin(ctx, DeviceLoginOptions{}, now)
	if err != nil {
		t.Fatal("saved login inventory rejected a new device", err)
	}
	if polled, err := d.PollDeviceLogin(ctx, credential, now); err != nil || polled.UserCode != login.UserCode {
		t.Fatal("new device login was not usable above the former ceiling", err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.device_logins SET expires_at=$1 WHERE user_code LIKE 'inventory/%'`, now); err != nil {
		t.Fatal(err)
	}
	if err := controlstatedb.New(d.pool).DeleteExpiredDeviceLogins(ctx, timestamptz(now)); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.device_logins WHERE user_code LIKE 'inventory/%'`).Scan(&remaining); err != nil || remaining != 9000 {
		t.Fatal("cleanup did not stop after its bounded batch", remaining, err)
	}
	if _, err := d.PollDeviceLogin(ctx, credential, now); err != nil {
		t.Fatal("cleanup removed a live device login", err)
	}
}
