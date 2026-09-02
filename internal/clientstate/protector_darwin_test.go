package clientstate

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/zalando/go-keyring"
)

func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Exit(m.Run())
}

func TestKeychainProtectorPersistsAndAuthenticatesContext(t *testing.T) {
	ring := &memoryKeyring{values: make(map[string]string)}
	lockPath := filepath.Join(t.TempDir(), "keychain.lock")
	first := &keychainSecretProtector{account: "profile", lockPath: lockPath, keyring: ring}
	sealed, err := first.Seal("access-credential", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("secret")) {
		t.Fatal("sealed value contains plaintext")
	}

	second := &keychainSecretProtector{account: "profile", lockPath: lockPath, keyring: ring}
	opened, err := second.Open("access-credential", sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(opened) != "secret" {
		t.Fatalf("opened value = %q", opened)
	}
	if _, err := second.Open("route-private-key:route_other", sealed); err == nil {
		t.Fatal("sealed value opened under a different context")
	}
	corrupted := bytes.Clone(sealed)
	corrupted[len(corrupted)-1] ^= 1
	if _, err := second.Open("access-credential", corrupted); err == nil {
		t.Fatal("corrupted sealed value opened")
	}
}

func TestKeychainProtectorSerializesWrappingKeyCreation(t *testing.T) {
	ring := &memoryKeyring{values: make(map[string]string)}
	lockPath := filepath.Join(t.TempDir(), "keychain.lock")
	protectors := []*keychainSecretProtector{
		{account: "profile", lockPath: lockPath, keyring: ring},
		{account: "profile", lockPath: lockPath, keyring: ring},
	}
	sealed := make([][]byte, len(protectors))
	errorsFound := make([]error, len(protectors))
	var wait sync.WaitGroup
	for index, protector := range protectors {
		wait.Add(1)
		go func() {
			defer wait.Done()
			sealed[index], errorsFound[index] = protector.Seal("value", []byte("secret"))
		}()
	}
	wait.Wait()
	for _, err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	if ring.sets != 1 {
		t.Fatalf("Keychain writes = %d, want 1", ring.sets)
	}
	for index, value := range sealed {
		opened, err := protectors[(index+1)%len(protectors)].Open("value", value)
		if err != nil || string(opened) != "secret" {
			t.Fatalf("opened value = %q, error = %v", opened, err)
		}
	}
}

func TestKeychainProtectorDoesNotReplaceMissingOrInvalidKey(t *testing.T) {
	ring := &memoryKeyring{values: make(map[string]string)}
	protector := &keychainSecretProtector{
		account: "profile", lockPath: filepath.Join(t.TempDir(), "keychain.lock"), keyring: ring,
	}
	if _, err := protector.Open("value", []byte("encrypted")); err == nil {
		t.Fatal("missing wrapping key accepted")
	}
	if ring.sets != 0 {
		t.Fatalf("Keychain writes after open = %d, want 0", ring.sets)
	}
	ring.values[keychainService+"\x00profile"] = "invalid"
	if _, err := protector.Seal("value", []byte("secret")); err == nil {
		t.Fatal("invalid wrapping key replaced")
	}
	if ring.sets != 0 {
		t.Fatalf("Keychain writes after invalid key = %d, want 0", ring.sets)
	}
}

func TestDarwinClientStateEncryptsControlSessionAndRouteKeys(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	store, err := New(root, "https://server.example")
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
	if err := store.SaveControlSession(ControlSession{
		Kind: ControlSessionKindCore, ControlEndpoint: "https://server.example",
		SessionID: "control_session_0123456789abcdef0123456789abcdef", Issuer: "https://server.example",
		AccessToken: token.String(), AccessExpiresAt: time.Now().Add(time.Hour).UTC(),
		RefreshToken: refresh.String(), RefreshExpiresAt: time.Now().Add(24 * time.Hour).UTC(), Grants: []string{"publish"},
	}); err != nil {
		t.Fatal(err)
	}
	credentialJSON, err := os.ReadFile(store.controlSessionPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(credentialJSON, []byte(token)) {
		t.Fatal("credential state contains the access token")
	}
	var storedCredential controlSessionFile
	if err := json.Unmarshal(credentialJSON, &storedCredential); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(storedCredential.AccessToken, sealedValuePrefix) {
		t.Fatal("access token is not encrypted")
	}
	if !bytes.HasPrefix(storedCredential.RefreshToken, sealedValuePrefix) {
		t.Fatal("refresh token is not encrypted")
	}

	route, err := store.OpenRoute(testRouteID)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := route.Pending("route.example")
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(pending.Key)
	if err != nil {
		t.Fatal(err)
	}
	var storedPending pendingFile
	if found, err := readJSON(filepath.Join(route.dir, "pending.json"), &storedPending); err != nil || !found {
		t.Fatalf("pending state found = %v, error = %v", found, err)
	}
	if bytes.Equal(storedPending.KeyDER, keyDER) || !bytes.HasPrefix(storedPending.KeyDER, sealedValuePrefix) {
		t.Fatal("pending state contains an unencrypted private key")
	}
	renewAt := time.Now().Add(time.Hour).UTC()
	material, err := route.Commit(
		"route.example", pending, signedCertificate(t, pending.Key, "route.example"), renewAt, "issuance_current", 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	var storedCurrent currentFile
	if found, err := readJSON(filepath.Join(route.dir, "current.json"), &storedCurrent); err != nil || !found {
		t.Fatalf("current state found = %v, error = %v", found, err)
	}
	if bytes.Equal(storedCurrent.KeyDER, keyDER) || !bytes.HasPrefix(storedCurrent.KeyDER, sealedValuePrefix) {
		t.Fatal("current state contains an unencrypted private key")
	}
	if err := route.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := New(root, "https://server.example")
	if err != nil {
		t.Fatal(err)
	}
	session, found, err := reopened.ControlSession()
	if err != nil || !found || session.AccessToken != token.String() {
		t.Fatalf("control session = %#v, found = %v, error = %v", session, found, err)
	}
	route, err = reopened.OpenRoute(testRouteID)
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	loaded, found, err := route.Current("route.example")
	if err != nil || !found {
		t.Fatalf("current state found = %v, error = %v", found, err)
	}
	if !loaded.Certificate.Leaf.PublicKey.(*ecdsa.PublicKey).Equal(&pending.Key.PublicKey) ||
		!loaded.RenewAt.Equal(material.RenewAt) {
		t.Fatal("reopened route used a different private key")
	}
}

type memoryKeyring struct {
	mu     sync.Mutex
	values map[string]string
	sets   int
}

func (m *memoryKeyring) Get(service, account string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	value, found := m.values[service+"\x00"+account]
	if !found {
		return "", keyring.ErrNotFound
	}
	return value, nil
}

func (m *memoryKeyring) Set(service, account, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.values == nil {
		return errors.New("nil keyring")
	}
	m.values[service+"\x00"+account] = value
	m.sets++
	return nil
}
