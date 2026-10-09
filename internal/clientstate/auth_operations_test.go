package clientstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestAuthOperationPrivateCheckpointAndFence(t *testing.T) {
	db, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := db.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	id, err := NewAuthOperationID()
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte(`{"device_code":"private-device-secret","nonce":"private-nonce","issued_access":"private-access"}`)
	op := AuthOperation{ID: id, Method: "device_code", Phase: AuthPending, Revision: 1, Private: secret, Interval: 5 * time.Second, NextPollAt: time.Now().Add(time.Second), ExpiresAt: time.Now().Add(time.Minute)}
	if err := store.CreateAuthOperation(t.Context(), op); err != nil {
		t.Fatal(err)
	}
	got, err := store.AuthOperation(t.Context(), id)
	if err != nil || !bytes.Equal(got.Private, secret) || !got.NextPollAt.Equal(op.NextPollAt) {
		t.Fatalf("private checkpoint failed: %v", err)
	}
	public, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(public, []byte("private-")) {
		t.Fatal("private checkpoint serialized")
	}
	var stored []byte
	if err := db.db.QueryRowContext(t.Context(), "SELECT stored_private FROM auth_operations WHERE operation_id = ?", id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	// macOS seals in Keychain; other platforms use the existing private-file protector.
	if runtime.GOOS == "darwin" && bytes.Contains(stored, []byte("private-")) {
		t.Fatal("checkpoint was not sealed")
	}
	lock, err := store.LockControlSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.FenceAuthOperations(t.Context()); err != nil {
		t.Fatal(err)
	}
	_ = lock.Close()
	got.Phase = AuthIssued
	if err := store.UpdateAuthOperation(t.Context(), &got); !errors.Is(err, ErrAuthOperationChanged) {
		t.Fatalf("stale checkpoint was accepted: %v", err)
	}
	got, err = store.AuthOperation(t.Context(), id)
	if err != nil || got.Phase != AuthCancelled || len(got.Private) != 0 {
		t.Fatalf("fence = %s, %v", got.Phase, err)
	}
	other, err := db.Server(t.Context(), "https://other.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.AuthOperation(t.Context(), id); !errors.Is(err, ErrAuthOperationNotFound) {
		t.Fatalf("operation crossed server boundary: %v", err)
	}
}
