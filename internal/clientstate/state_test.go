package clientstate

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
)

const testRouteID = "route_0123456789abcdef0123456789abcdef"

func TestRouteStatePersistsPendingAndCurrentMaterial(t *testing.T) {
	store := testStore(t, filepath.Join(t.TempDir(), "state"), "https://server.example")
	route, err := store.OpenRoute(testRouteID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.OpenRoute(testRouteID); !errors.Is(err, ErrLocked) {
		t.Fatalf("second route lock error = %v", err)
	}
	pending, err := route.Pending(t.Context(), "route.example")
	if err != nil {
		t.Fatal(err)
	}
	firstCSR := bytes.Clone(pending.CSRDER)
	if err := route.Close(); err != nil {
		t.Fatal(err)
	}

	route, err = store.OpenRoute(testRouteID)
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	pending, err = route.Pending(t.Context(), "route.example")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pending.CSRDER, firstCSR) {
		t.Fatal("pending CSR changed across restart")
	}
	renewAt := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
	material, err := route.Commit(
		t.Context(), "route.example", pending, signedCertificate(t, pending.Key, "route.example"), renewAt, "issuance_current", 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if material.Certificate.Leaf == nil || !material.RenewAt.Equal(renewAt) {
		t.Fatalf("committed material = %+v", material)
	}
	loaded, found, err := route.Current(t.Context(), "route.example")
	if err != nil || !found || loaded.Certificate.Leaf == nil || !loaded.RenewAt.Equal(renewAt) {
		t.Fatalf("loaded material = %+v, %v, %v", loaded, found, err)
	}
	if loaded.Installed || loaded.IssuanceID != "issuance_current" || loaded.RouteVersion != 1 {
		t.Fatalf("loaded durable phase = %+v", loaded)
	}
	loaded, err = route.MarkInstalled(t.Context(), "route.example", "issuance_current", 1)
	if err != nil || !loaded.Installed {
		t.Fatalf("installed material = %+v, %v", loaded, err)
	}
	info, err := os.Stat(DatabasePath(store.database.root))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("database mode = %o", info.Mode().Perm())
	}
	replacement, err := route.NewPending(t.Context(), "route.example")
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Key.PublicKey.Equal(&pending.Key.PublicKey) {
		t.Fatal("renewal reused the current application key")
	}
}

func TestCertificateAttemptRecoversUnacknowledgedCurrentCSR(t *testing.T) {
	store := testStore(t, filepath.Join(t.TempDir(), "state"), "https://server.example")
	route, err := store.OpenRoute(testRouteID)
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	pending, err := route.Pending(t.Context(), "route.example")
	if err != nil {
		t.Fatal(err)
	}
	csr := bytes.Clone(pending.CSRDER)
	_, err = route.Commit(
		t.Context(), "route.example", pending, signedCertificate(t, pending.Key, "route.example"),
		time.Now().Add(30*24*time.Hour), "issuance_current", 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := route.CertificateAttempt(t.Context(), "route.example")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered.CSRDER, csr) {
		t.Fatal("certificate attempt did not recover the unacknowledged current CSR")
	}
	replacement, err := route.NewPending(t.Context(), "route.example")
	if err != nil {
		t.Fatal(err)
	}
	selected, err := route.CertificateAttempt(t.Context(), "route.example")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(selected.CSRDER, replacement.CSRDER) || bytes.Equal(selected.CSRDER, csr) {
		t.Fatal("pending replacement did not take precedence over current recovery")
	}
}

func TestStateRejectsSymlinksAndPublicFiles(t *testing.T) {
	parent := t.TempDir()
	real := filepath.Join(parent, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "state")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), link); err == nil {
		t.Fatal("symlink state root accepted")
	}

	root := filepath.Join(parent, "private")
	database, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(DatabasePath(root), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), root); err == nil {
		t.Fatal("publicly readable database accepted")
	}
}

func TestStateLocksHostnameBeforeRouteTakeover(t *testing.T) {
	store := testStore(t, filepath.Join(t.TempDir(), "state"), "https://server.example")
	lock, err := store.LockHostname("route.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LockHostname("route.example"); !errors.Is(err, ErrLocked) {
		t.Fatalf("second hostname lock error = %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	lock, err = store.LockHostname("route.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStateDoesNotChmodAnExistingPublicRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), root); err == nil {
		t.Fatal("public state root accepted")
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("state root mode changed to %04o", info.Mode().Perm())
	}
}

func TestStateRejectsWritableAncestor(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), filepath.Join(parent, "state")); err == nil {
		t.Fatal("state root beneath writable ancestor accepted")
	}
}

func TestStateAllowsStickyWritableAncestor(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	database, err := Open(t.Context(), filepath.Join(parent, "state"))
	if err != nil {
		t.Fatal(err)
	}
	database.Close()
}

func TestControlSessionPersistsPrivatelyAndCanBeRemoved(t *testing.T) {
	store := testStore(t, filepath.Join(t.TempDir(), "state"), "https://server.example")
	token, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	refresh, _, _, err := credentials.NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	want := ControlSession{
		AuthorityEndpoint: "https://accounts.example",
		SessionID:         "control_session_0123456789abcdef0123456789abcdef",
		AccessToken:       token.String(), AccessExpiresAt: time.Now().Add(time.Hour).UTC(),
		RefreshToken: refresh.String(), RefreshExpiresAt: time.Now().Add(24 * time.Hour).UTC(),
	}
	if err := store.SaveControlSession(t.Context(), want); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(DatabasePath(store.database.root))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("client database mode = %o", info.Mode().Perm())
	}
	got, found, err := store.ControlSession(t.Context())
	if err != nil || !found || got.AuthorityEndpoint != want.AuthorityEndpoint || got.SessionID != want.SessionID ||
		got.AccessToken != want.AccessToken || !got.AccessExpiresAt.Equal(want.AccessExpiresAt) ||
		got.RefreshToken != want.RefreshToken || !got.RefreshExpiresAt.Equal(want.RefreshExpiresAt) {
		t.Fatalf("control session = %#v, found = %v, error = %v", got, found, err)
	}
	if err := store.RemoveControlSession(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.ControlSession(t.Context()); err != nil || found {
		t.Fatalf("control session found after removal = %v, error = %v", found, err)
	}
}

func TestControlSessionLockSerializesUpdates(t *testing.T) {
	store := testStore(t, filepath.Join(t.TempDir(), "state"), "https://server.example")
	lock, err := store.LockControlSession()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LockControlSession(); !errors.Is(err, ErrLocked) {
		t.Fatalf("second control session lock error = %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	lock, err = store.LockControlSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentStoreInitialization(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	var wait sync.WaitGroup
	errorsFound := make(chan error, 8)
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			database, err := Open(t.Context(), root)
			if err == nil {
				_, err = database.Server(t.Context(), "https://server.example")
				err = errors.Join(err, database.Close())
			}
			errorsFound <- err
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func testStore(t *testing.T, root, server string) *Store {
	t.Helper()
	database, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	store, err := database.Server(t.Context(), server)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func signedCertificate(t *testing.T, key *ecdsa.PrivateKey, hostname string) []byte {
	t.Helper()
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{}, DNSNames: []string{hostname},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
