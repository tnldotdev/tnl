package state

import (
	"bytes"
	"crypto/ed25519"
	"path/filepath"
	"sync"
	"testing"
)

func TestVisitorDeviceEnrollmentIsProtectedScopedAndStable(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	db := openFileDatabase(t, root)
	store, err := db.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	device, err := store.EnsureVisitorDevice(t.Context(), "identity-one")
	if err != nil || device.ID != "" || len(device.SigningKey) != ed25519.PrivateKeySize {
		t.Fatalf("pending device: %v", err)
	}
	if err := store.EnrollVisitorDevice(t.Context(), "identity-one", "device-one", device.PublicKey); err != nil {
		t.Fatal(err)
	}
	if err := store.EnrollVisitorDevice(t.Context(), "identity-one", "device-two", device.PublicKey); err == nil {
		t.Fatal("stale enrollment replaced device")
	}
	otherKey := bytes.Repeat([]byte{1}, 32)
	if err := store.EnrollVisitorDevice(t.Context(), "identity-one", "device-one", otherKey); err == nil {
		t.Fatal("wrong key enrolled")
	}
	for _, identity := range []string{"identity-two", "identity-three"} {
		other, err := store.EnsureVisitorDevice(t.Context(), identity)
		if err != nil || bytes.Equal(other.PublicKey, device.PublicKey) {
			t.Fatalf("identity isolation: %v", err)
		}
	}
	otherStore, err := db.Server(t.Context(), "https://other.example")
	if err != nil {
		t.Fatal(err)
	}
	other, err := otherStore.EnsureVisitorDevice(t.Context(), "identity-one")
	if err != nil || bytes.Equal(other.PublicKey, device.PublicKey) {
		t.Fatalf("server isolation: %v", err)
	}
	var sealed []byte
	if err := db.db.QueryRowContext(t.Context(), `SELECT signing_key_ciphertext FROM visitor_devices WHERE server_origin=? AND identity_id=?`, store.controlEndpoint, "identity-one").Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, device.SigningKey) || bytes.Contains(sealed, device.SigningKey.Seed()) || !bytes.HasPrefix(sealed, sealedValuePrefix) {
		t.Fatal("visitor key not encrypted")
	}
	// ciphertext substitution across identities and servers fails authentication.
	if _, err := otherStore.secrets.Open(t.Context(), visitorDeviceContext("identity-one", device.PublicKey), sealed); err == nil {
		t.Fatal("ciphertext crossed server scope")
	}
	if _, err := store.secrets.Open(t.Context(), visitorDeviceContext("identity-two", device.PublicKey), sealed); err == nil {
		t.Fatal("ciphertext crossed identity scope")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openFileDatabase(t, root)
	store, err = reopened.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.EnsureVisitorDevice(t.Context(), "identity-one")
	if err != nil || loaded.ID != "device-one" || !bytes.Equal(loaded.SigningKey, device.SigningKey) {
		t.Fatalf("restart lost enrollment: %v", err)
	}
}

func TestConcurrentVisitorDeviceEnrollmentKeepsOneKey(t *testing.T) {
	db := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
	store, err := db.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	const callers = 8
	keys := make(chan VisitorDevice, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			device, err := store.EnsureVisitorDevice(t.Context(), "identity")
			if err != nil {
				t.Error(err)
				return
			}
			keys <- device
		})
	}
	wg.Wait()
	close(keys)
	var first []byte
	for device := range keys {
		if first == nil {
			first = device.PublicKey
		}
		if !bytes.Equal(first, device.PublicKey) {
			t.Fatal("concurrent callers selected different device keys")
		}
	}
}
