package clientstate

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
)

const testRouteID = "route_0123456789abcdef0123456789abcdef"

func TestRouteStatePersistsPendingAndCurrentMaterial(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "state"), "https://server.example")
	if err != nil {
		t.Fatal(err)
	}
	route, err := store.OpenRoute(testRouteID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.OpenRoute(testRouteID); !errors.Is(err, ErrLocked) {
		t.Fatalf("second route lock error = %v", err)
	}
	pending, err := route.Pending("route.example")
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
	pending, err = route.Pending("route.example")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pending.CSRDER, firstCSR) {
		t.Fatal("pending CSR changed across restart")
	}
	pending, err = route.RecordIssuance("route.example", pending, "issuance_pending", 1)
	if err != nil {
		t.Fatal(err)
	}
	renewAt := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
	material, err := route.Commit(
		"route.example", pending, signedCertificate(t, pending.Key, "route.example"), renewAt, "issuance_current", 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if material.Certificate.Leaf == nil || !material.RenewAt.Equal(renewAt) {
		t.Fatalf("committed material = %+v", material)
	}
	loaded, found, err := route.Current("route.example")
	if err != nil || !found || loaded.Certificate.Leaf == nil || !loaded.RenewAt.Equal(renewAt) {
		t.Fatalf("loaded material = %+v, %v, %v", loaded, found, err)
	}
	if loaded.Installed || loaded.IssuanceID != "issuance_current" || loaded.Version != 1 || !bytes.Equal(loaded.CSRDER, firstCSR) {
		t.Fatalf("loaded durable phase = %+v", loaded)
	}
	loaded, err = route.MarkInstalled("route.example", "issuance_current", 1)
	if err != nil || !loaded.Installed {
		t.Fatalf("installed material = %+v, %v", loaded, err)
	}
	if _, err := os.Stat(filepath.Join(route.dir, "pending.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending state remains after commit: %v", err)
	}
	info, err := os.Stat(filepath.Join(route.dir, "current.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("current state mode = %o", info.Mode().Perm())
	}
	replacement, err := route.NewPending("route.example")
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Key.PublicKey.Equal(&pending.Key.PublicKey) {
		t.Fatal("renewal reused the current application key")
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
	if _, err := New(link, "https://server.example"); err == nil {
		t.Fatal("symlink state root accepted")
	}

	store, err := New(filepath.Join(parent, "private"), "https://server.example")
	if err != nil {
		t.Fatal(err)
	}
	route, err := store.OpenRoute(testRouteID)
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	pending, err := route.Pending("route.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := route.Commit(
		"route.example", pending, signedCertificate(t, pending.Key, "route.example"), time.Now().Add(time.Hour),
		"issuance_current", 1,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(route.dir, "current.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := route.Current("route.example"); err == nil {
		t.Fatal("publicly readable state file accepted")
	}
}

func TestStateLocksHostnameBeforeRouteTakeover(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "state"), "https://server.example")
	if err != nil {
		t.Fatal(err)
	}
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
	if _, err := New(root, "https://server.example"); err == nil {
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
	if _, err := New(filepath.Join(parent, "state"), "https://server.example"); err == nil {
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
	if _, err := New(filepath.Join(parent, "state"), "https://server.example"); err != nil {
		t.Fatal(err)
	}
}

func TestControlSessionPersistsPrivatelyAndCanBeRemoved(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "state"), "https://server.example")
	if err != nil {
		t.Fatal(err)
	}
	token, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	refresh, _, _, err := credentials.NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	want := ControlSession{
		Kind: ControlSessionKindCore, ControlEndpoint: "https://server.example",
		SessionID: "control_session_0123456789abcdef0123456789abcdef", Issuer: "https://issuer.example", ClientID: "tnl-cli",
		AccessToken: token.String(), AccessExpiresAt: time.Now().Add(time.Hour).UTC(),
		RefreshToken: refresh.String(), RefreshExpiresAt: time.Now().Add(24 * time.Hour).UTC(), Grants: []string{"publish"},
	}
	if err := store.SaveControlSession(want); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(store.controlSessionPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("control session mode = %o", info.Mode().Perm())
	}
	encoded, err := os.ReadFile(store.controlSessionPath)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"schema_version", "kind", "control_endpoint", "session_id", "issuer", "client_id", "access_token",
		"access_expires_at", "refresh_token", "refresh_expires_at", "grants",
	} {
		if _, found := fields[name]; !found {
			t.Errorf("control session field %q is missing", name)
		}
	}
	if len(fields) != 11 {
		t.Fatalf("control session fields = %v", fields)
	}
	got, found, err := store.ControlSession()
	if err != nil || !found || got.Kind != want.Kind || got.ControlEndpoint != want.ControlEndpoint ||
		got.SessionID != want.SessionID || got.Issuer != want.Issuer || got.ClientID != want.ClientID ||
		got.AccessToken != want.AccessToken || !got.AccessExpiresAt.Equal(want.AccessExpiresAt) ||
		got.RefreshToken != want.RefreshToken || !got.RefreshExpiresAt.Equal(want.RefreshExpiresAt) ||
		!reflect.DeepEqual(got.Grants, want.Grants) {
		t.Fatalf("control session = %#v, found = %v, error = %v", got, found, err)
	}
	if err := store.RemoveControlSession(); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.ControlSession(); err != nil || found {
		t.Fatalf("control session found after removal = %v, error = %v", found, err)
	}
}

func TestAuthorizationAuthoritySessionAllowsOpaqueTokensAndSeparateEndpoint(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "state"), "https://core.example")
	if err != nil {
		t.Fatal(err)
	}
	want := ControlSession{
		Kind: ControlSessionKindAuthorizationAuthority, ControlEndpoint: "https://accounts.example",
		SessionID: "oauth_session_0123456789abcdef0123456789abcdef",
		Issuer:    "https://issuer.example/tenant", ClientID: "tnl-cli",
		AccessToken: "opaque-access", AccessExpiresAt: time.Now().Add(time.Hour).UTC(),
		RefreshToken: "opaque-refresh", Scopes: []string{"openid", "offline_access", "product", "operations"},
	}
	if err := store.SaveControlSession(want); err != nil {
		t.Fatal(err)
	}
	got, found, err := store.ControlSession()
	if err != nil || !found || !reflect.DeepEqual(got, want) {
		t.Fatalf("session = %#v, found = %v, error = %v", got, found, err)
	}
}

func TestControlSessionLockSerializesUpdates(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "state"), "https://server.example")
	if err != nil {
		t.Fatal(err)
	}
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
			_, err := New(root, "https://server.example")
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
