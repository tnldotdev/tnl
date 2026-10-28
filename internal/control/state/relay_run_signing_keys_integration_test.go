package state

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func testRelayRunKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public
}

func relayRunKeyBinding(t *testing.T, d *Database, relayID, runID string) (key []byte, superseded *time.Time) {
	t.Helper()
	if err := d.pool.QueryRow(t.Context(), `SELECT peer_signing_public_key, superseded_at
		FROM control.relay_run_signing_keys WHERE relay_id=$1 AND relay_run_id=$2`, relayID, runID).Scan(&key, &superseded); err != nil {
		t.Fatal(err)
	}
	return key, superseded
}

func TestIntegrationRelayRunSigningKeyRetention(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "relay_run_key_retention")
	a := relayLifecycleRegistration("relay-retention")
	a.PeerSigningPublicKey = testRelayRunKey(t)
	current, err := d.RegisterRelay(t.Context(), a, now, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// a current process remains bound long after the superseded-key horizon.
	longRunning := now.Add(25 * time.Hour)
	if removed, err := d.CleanupRelayRunSigningKeys(t.Context(), longRunning, 1); err != nil || removed != 0 {
		t.Fatalf("current run was removed after 25h: %d %v", removed, err)
	}
	if key, superseded := relayRunKeyBinding(t, d, a.RelayID, a.RelayRunID); !bytes.Equal(key, a.PeerSigningPublicKey) || superseded != nil {
		t.Fatal("current run lost its key or received a supersession")
	}
	bad := a
	bad.PeerSigningPublicKey = testRelayRunKey(t)
	if _, err := d.RegisterRelay(t.Context(), bad, longRunning, time.Hour); !errors.Is(err, ErrRelayRegistrationConflict) {
		t.Fatal("current run changed its key after 25h", err)
	}
	if _, err := d.RenewRelay(t.Context(), RelayRenewal{RelayLeaseIdentity: current.RelayLeaseIdentity}, longRunning, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	replacedAt := now.Add(49 * time.Hour)
	b := a
	b.RelayRunID = "relay-retention-second-run"
	b.PeerSigningPublicKey = testRelayRunKey(t)
	if _, err := d.RegisterRelay(t.Context(), b, replacedAt, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, superseded := relayRunKeyBinding(t, d, a.RelayID, a.RelayRunID); superseded == nil || !superseded.Equal(replacedAt) {
		t.Fatalf("prior run superseded at %v, want %v", superseded, replacedAt)
	}
	if _, superseded := relayRunKeyBinding(t, d, b.RelayID, b.RelayRunID); superseded != nil {
		t.Fatal("new current run was marked superseded")
	}
	for _, at := range []time.Time{replacedAt.Add(time.Minute), replacedAt.Add(relayRunSigningKeyRetention)} {
		if _, err := d.RegisterRelay(t.Context(), bad, at, time.Minute); !errors.Is(err, ErrRelayRegistrationConflict) {
			t.Fatalf("superseded run changed key at %v: %v", at, err)
		}
		if removed, err := d.CleanupRelayRunSigningKeys(t.Context(), at, 1); err != nil || removed != 0 {
			t.Fatalf("cleaned key within ten-minute horizon: %d %v", removed, err)
		}
	}
	if removed, err := d.CleanupRelayRunSigningKeys(t.Context(), replacedAt.Add(relayRunSigningKeyRetention+time.Microsecond), 1); err != nil || removed != 1 {
		t.Fatalf("old binding not pruned after horizon: %d %v", removed, err)
	}
	if removed, err := d.CleanupRelayRunSigningKeys(t.Context(), replacedAt.Add(26*time.Hour), 1); err != nil || removed != 0 {
		t.Fatalf("current binding removed after 26h: %d %v", removed, err)
	}
	bad = b
	bad.PeerSigningPublicKey = testRelayRunKey(t)
	if _, err := d.RegisterRelay(t.Context(), bad, replacedAt.Add(26*time.Hour), time.Minute); !errors.Is(err, ErrRelayRegistrationConflict) {
		t.Fatal("cleanup allowed the current run to change its key", err)
	}
	if key, superseded := relayRunKeyBinding(t, d, b.RelayID, b.RelayRunID); !bytes.Equal(key, b.PeerSigningPublicKey) || superseded != nil {
		t.Fatal("current binding changed during cleanup")
	}
}

func TestIntegrationRelayRunSigningKeyReturnClearsSupersession(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "relay_run_key_return")
	a := relayLifecycleRegistration("relay-return")
	a.PeerSigningPublicKey = testRelayRunKey(t)
	if _, err := d.RegisterRelay(t.Context(), a, now, time.Minute); err != nil {
		t.Fatal(err)
	}
	b := a
	b.RelayRunID = "relay-return-second-run"
	b.PeerSigningPublicKey = testRelayRunKey(t)
	if _, err := d.RegisterRelay(t.Context(), b, now.Add(time.Minute), time.Minute); err != nil {
		t.Fatal(err)
	}
	// a previously superseded run may return only with its original key and
	// only after the current lease permits replacement.
	if _, err := d.RegisterRelay(t.Context(), a, now.Add(90*time.Second), time.Hour); !errors.Is(err, ErrRelayRegistrationConflict) {
		t.Fatal("old run replaced live lease", err)
	}
	returnedAt := now.Add(2 * time.Minute)
	if _, err := d.RegisterRelay(t.Context(), a, returnedAt, 48*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, superseded := relayRunKeyBinding(t, d, a.RelayID, a.RelayRunID); superseded != nil {
		t.Fatal("returning run retained supersession")
	}
	if _, superseded := relayRunKeyBinding(t, d, b.RelayID, b.RelayRunID); superseded == nil || !superseded.Equal(returnedAt) {
		t.Fatalf("replaced run superseded at %v, want %v", superseded, returnedAt)
	}
	if removed, err := d.CleanupRelayRunSigningKeys(t.Context(), returnedAt.Add(relayRunSigningKeyRetention+time.Microsecond), 1); err != nil || removed != 1 {
		t.Fatalf("replaced run not removed in bounded batch: %d %v", removed, err)
	}
	if removed, err := d.CleanupRelayRunSigningKeys(t.Context(), returnedAt.Add(25*time.Hour), 1); err != nil || removed != 0 {
		t.Fatalf("returning run key was pruned: %d %v", removed, err)
	}
	bad := a
	bad.PeerSigningPublicKey = testRelayRunKey(t)
	if _, err := d.RegisterRelay(t.Context(), bad, returnedAt.Add(25*time.Hour), time.Minute); !errors.Is(err, ErrRelayRegistrationConflict) {
		t.Fatal("old run key changed after return and cleanup", err)
	}
}

func TestIntegrationRelayRunSigningKeyCleanupBatchesAndSkipsLockedLease(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "relay_run_key_batch")
	r := relayLifecycleRegistration("relay-batch")
	for index, runID := range []string{"first", "second", "third"} {
		r.RelayRunID = runID
		r.PeerSigningPublicKey = testRelayRunKey(t)
		if _, err := d.RegisterRelay(t.Context(), r, now.Add(time.Duration(index)*time.Minute), time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	at := now.Add(12*time.Minute + time.Microsecond)
	gate, err := d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := gate.Exec(t.Context(), `SELECT relay_id FROM control.relay_leases WHERE relay_id=$1 FOR UPDATE`, r.RelayID); err != nil {
		t.Fatal(err)
	}
	if removed, err := d.CleanupRelayRunSigningKeys(t.Context(), at, 1); err != nil || removed != 0 {
		t.Fatalf("cleanup waited for or bypassed locked lease: %d %v", removed, err)
	}
	if err := gate.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []int64{1, 1, 0} {
		if removed, err := d.CleanupRelayRunSigningKeys(t.Context(), at, 1); err != nil || removed != want {
			t.Fatalf("bounded cleanup removed %d, want %d: %v", removed, want, err)
		}
	}
	if key, superseded := relayRunKeyBinding(t, d, r.RelayID, r.RelayRunID); !bytes.Equal(key, r.PeerSigningPublicKey) || superseded != nil {
		t.Fatal("bounded cleanup removed the current binding")
	}
}
