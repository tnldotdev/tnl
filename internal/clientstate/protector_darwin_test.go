package clientstate

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
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
	sealed, err := first.Seal(t.Context(), "access-credential", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("secret")) {
		t.Fatal("sealed value contains plaintext")
	}

	second := &keychainSecretProtector{account: "profile", lockPath: lockPath, keyring: ring}
	opened, err := second.Open(t.Context(), "access-credential", sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(opened) != "secret" {
		t.Fatalf("opened value = %q", opened)
	}
	if _, err := second.Open(t.Context(), "route-private-key:public_url_other", sealed); err == nil {
		t.Fatal("sealed value opened under a different context")
	}
	corrupted := bytes.Clone(sealed)
	corrupted[len(corrupted)-1] ^= 1
	if _, err := second.Open(t.Context(), "access-credential", corrupted); err == nil {
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
			sealed[index], errorsFound[index] = protector.Seal(t.Context(), "value", []byte("secret"))
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
		opened, err := protectors[(index+1)%len(protectors)].Open(t.Context(), "value", value)
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
	if _, err := protector.Open(t.Context(), "value", []byte("encrypted")); err == nil {
		t.Fatal("missing wrapping key accepted")
	}
	if ring.sets != 0 {
		t.Fatalf("Keychain writes after open = %d, want 0", ring.sets)
	}
	ring.values[keychainService+"\x00profile"] = "invalid"
	if _, err := protector.Seal(t.Context(), "value", []byte("secret")); err == nil {
		t.Fatal("invalid wrapping key replaced")
	}
	if ring.sets != 0 {
		t.Fatalf("Keychain writes after invalid key = %d, want 0", ring.sets)
	}
}

func TestKeychainProtectorLockWaitCanBeCanceled(t *testing.T) {
	ring := &memoryKeyring{values: make(map[string]string)}
	observed := &observedKeyring{keyringClient: ring, gets: make(chan struct{}, 1)}
	lockPath := filepath.Join(t.TempDir(), "keychain.lock")
	lock, err := openLock(lockPath, "test Keychain initialization")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	protector := &keychainSecretProtector{account: "profile", lockPath: lockPath, keyring: observed}
	firstCtx, cancelFirst := context.WithCancel(t.Context())
	first := make(chan error, 1)
	go func() {
		_, err := protector.Seal(firstCtx, "value", []byte("secret"))
		first <- err
	}()
	select {
	case <-observed.gets:
	case <-time.After(time.Second):
		cancelFirst()
		<-first
		t.Fatal("first protector did not attempt initialization")
	}

	waiterCtx, cancelWaiter := context.WithCancel(t.Context())
	cancelWaiter()
	waiter := make(chan error, 1)
	go func() {
		_, err := protector.Seal(waiterCtx, "value", []byte("secret"))
		waiter <- err
	}()
	select {
	case err := <-waiter:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("contending protector error = %v", err)
		}
	case <-time.After(time.Second):
		cancelFirst()
		<-first
		<-waiter
		t.Fatal("contending protector did not honor cancellation")
	}
	cancelFirst()
	select {
	case err := <-first:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("first protector error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first protector did not finish after cancellation")
	}
	if ring.sets != 0 {
		t.Fatalf("Keychain writes = %d, want 0", ring.sets)
	}
}

func TestDarwinClientStateEncryptsControlSessionAndRouteKeys(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	database, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	store, err := database.Server(t.Context(), "https://server.example")
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
	if err := store.SaveControlSession(t.Context(), ControlSession{
		SessionID:   "cs_0123456789abcdefghijkl",
		AccessToken: token.String(), AccessExpiresAt: time.Now().Add(time.Hour).UTC(),
		RefreshToken: refresh.String(), RefreshExpiresAt: time.Now().Add(24 * time.Hour).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	storedCredential, err := database.queries.GetControlSession(t.Context(), store.controlEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(storedCredential.StoredAccessToken, []byte(token)) {
		t.Fatal("credential state contains the access token")
	}
	if !bytes.HasPrefix(storedCredential.StoredAccessToken, sealedValuePrefix) {
		t.Fatal("access token is not encrypted")
	}
	if !bytes.HasPrefix(storedCredential.StoredRefreshToken, sealedValuePrefix) {
		t.Fatal("refresh token is not encrypted")
	}

	route, err := store.Certificates("team_1", exactCertificateTestPlan())
	if err != nil {
		t.Fatal(err)
	}
	pending, err := route.Pending(t.Context(), "route.example")
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(pending.Key)
	if err != nil {
		t.Fatal(err)
	}
	storedPending, err := route.record(t.Context(), certificatePhasePending)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(storedPending.StoredKey, keyDER) || !bytes.HasPrefix(storedPending.StoredKey, sealedValuePrefix) {
		t.Fatal("pending state contains an unencrypted private key")
	}
	renewAt := time.Now().Add(time.Hour).UTC()
	material, err := route.Stage(
		t.Context(), "route.example", pending, signedCertificate(t, pending.Key, "route.example"), renewAt, "issuance_current",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := route.Promote(t.Context(), "route.example", material.IssuanceID); err != nil {
		t.Fatal(err)
	}
	storedCurrent, err := route.record(t.Context(), certificatePhaseCurrent)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(storedCurrent.StoredKey, keyDER) || !bytes.HasPrefix(storedCurrent.StoredKey, sealedValuePrefix) {
		t.Fatal("current state contains an unencrypted private key")
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	reopenedDatabase, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedDatabase.Close()
	reopened, err := reopenedDatabase.Server(t.Context(), "https://server.example")
	if err != nil {
		t.Fatal(err)
	}
	session, found, err := reopened.ControlSession(t.Context())
	if err != nil || !found || session.AccessToken != token.String() {
		t.Fatalf("control session = %#v, found = %v, error = %v", session, found, err)
	}
	route, err = reopened.Certificates("team_1", exactCertificateTestPlan())
	if err != nil {
		t.Fatal(err)
	}
	loaded, found, err := route.Current(t.Context(), "route.example")
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

type observedKeyring struct {
	keyringClient
	gets chan struct{}
}

func (o *observedKeyring) Get(service, account string) (string, error) {
	value, err := o.keyringClient.Get(service, account)
	select {
	case o.gets <- struct{}{}:
	default:
	}
	return value, err
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
