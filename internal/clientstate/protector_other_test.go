//go:build !darwin

package clientstate

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
)

func TestFileProtectorAuthenticatesContextAndKey(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	database, err := Open(t.Context(), directory)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	first := newSecretProtector("profile", "", directory)
	sealed, err := first.Seal(t.Context(), "session", []byte("private-value"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(sealed, sealedValuePrefix) || bytes.Contains(sealed, []byte("private-value")) {
		t.Fatal("sealed value was not encrypted")
	}
	second := newSecretProtector("profile", "", directory)
	opened, err := second.Open(t.Context(), "session", sealed)
	if err != nil || string(opened) != "private-value" {
		t.Fatalf("opened value = %q, error = %v", opened, err)
	}
	for _, protector := range []secretProtector{second, newSecretProtector("another-profile", "", directory)} {
		if _, err := protector.Open(t.Context(), "another-session", sealed); err == nil {
			t.Fatal("different secret context decrypted the value")
		}
	}
	if _, err := newSecretProtector("another-profile", "", directory).Open(t.Context(), "session", sealed); err == nil {
		t.Fatal("different profile decrypted the value")
	}
	keyPath := filepath.Join(directory, "wrapping-key-v1")
	key, err := os.ReadFile(keyPath)
	if err != nil || len(key) != wrappingKeySize {
		t.Fatalf("wrapping key = %d bytes, error = %v", len(key), err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("wrapping key mode = %v", info.Mode())
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Open(t.Context(), "session", sealed); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing key error = %v", err)
	}
	if _, err := second.Seal(t.Context(), "session", []byte("secret")); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing key on write error = %v", err)
	}
	if _, err := Open(t.Context(), directory); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("reopening without key error = %v", err)
	}
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{42}, wrappingKeySize), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Open(t.Context(), "session", sealed); err == nil || !strings.Contains(err.Error(), "decrypt") {
		t.Fatalf("wrong key error = %v", err)
	}
	if err := os.WriteFile(keyPath, key[:1], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Seal(t.Context(), "session", []byte("secret")); err == nil || !strings.Contains(err.Error(), "invalid wrapping key") {
		t.Fatalf("invalid key error = %v", err)
	}
}

func TestFileProtectorConcurrentInitialization(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	const count = 16
	sealed := make([][]byte, count)
	failures := make([]error, count)
	var wait sync.WaitGroup
	for index := range count {
		wait.Add(1)
		go func() {
			defer wait.Done()
			database, err := Open(t.Context(), directory)
			if err != nil {
				failures[index] = err
				return
			}
			defer database.Close()
			protector := newSecretProtector("profile", "", directory)
			sealed[index], failures[index] = protector.Seal(t.Context(), "session", []byte("secret"))
		}()
	}
	wait.Wait()
	for index := range count {
		if failures[index] != nil {
			t.Fatal(failures[index])
		}
		opened, err := newSecretProtector("profile", "", directory).Open(t.Context(), "session", sealed[index])
		if err != nil || string(opened) != "secret" {
			t.Fatalf("concurrent value = %q, error = %v", opened, err)
		}
	}
	if _, err := newSecretProtector("profile", "", directory).Open(t.Context(), "session", []byte("plaintext")); err == nil {
		t.Fatal("plaintext accepted")
	}
}

func TestNonDarwinClientStateDoesNotStoreSessionInPlaintext(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	database, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	store, err := database.Server(t.Context(), "https://server.example")
	if err != nil {
		t.Fatal(err)
	}
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	refresh, _, _, err := credentials.NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveControlSession(t.Context(), ControlSession{
		SessionID: "cs_0123456789abcdefghijkl", AccessToken: access.String(), RefreshToken: refresh.String(),
		AccessExpiresAt: time.Now().Add(time.Hour), RefreshExpiresAt: time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(DatabasePath(root))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(content, []byte(access)) || bytes.Contains(content, []byte(refresh)) {
		t.Fatal("database contains plaintext credentials")
	}
	reopened, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	server, err := reopened.Server(t.Context(), "https://server.example")
	if err != nil {
		t.Fatal(err)
	}
	session, found, err := server.ControlSession(t.Context())
	if err != nil || !found || session.AccessToken != access.String() {
		t.Fatalf("restored session = %+v, found = %v, error = %v", session, found, err)
	}
	if err := os.Remove(filepath.Join(root, "wrapping-key-v1")); err != nil {
		t.Fatal(err)
	}
	_, _, err = server.ControlSession(t.Context())
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing session key error = %v", err)
	}
}
