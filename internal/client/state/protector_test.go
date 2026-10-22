package state

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
)

func openFileDatabase(t *testing.T, root string) *Database {
	t.Helper()
	database, err := OpenWithOptions(t.Context(), root, OpenOptions{Protection: ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

func TestSharedCipherAuthenticatesRootScopeContextAndCiphertext(t *testing.T) {
	key := make([]byte, wrappingKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	protector := &encryptedProtector{key: key, account: "root"}
	sealed, err := protector.Seal(t.Context(), "field", []byte("private value"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := protector.Seal(t.Context(), "field", []byte("private value"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sealed, second) || bytes.Contains(sealed, []byte("private value")) {
		t.Fatal("ciphertext exposes or deterministically encodes plaintext")
	}
	opened, err := protector.Open(t.Context(), "field", sealed)
	if err != nil || string(opened) != "private value" {
		t.Fatalf("round trip: %q, %v", opened, err)
	}
	corrupted := bytes.Clone(sealed)
	corrupted[len(corrupted)-1] ^= 1
	for _, value := range [][]byte{corrupted, []byte("private value"), sealed[:len(sealed)-1]} {
		if _, err := protector.Open(t.Context(), "field", value); err == nil {
			t.Fatal("unauthenticated value opened")
		}
	}
	if _, err := protector.Open(t.Context(), "other", sealed); err == nil {
		t.Fatal("wrong context accepted")
	}
	if _, err := (&encryptedProtector{key: key, account: "other root"}).Open(t.Context(), "field", sealed); err == nil {
		t.Fatal("wrong root accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := protector.Seal(ctx, "field", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled seal: %v", err)
	}
}

func TestFileProtectorNeverReplacesMissingInvalidOrWrongKey(t *testing.T) {
	for _, mutation := range []string{"missing", "invalid", "different", "public", "symlink"} {
		t.Run(mutation, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			database := openFileDatabase(t, root)
			root = database.Root()
			if err := database.SavePublisherJobRegistry(t.Context(), []byte("secret")); err != nil {
				t.Fatal(err)
			}
			if err := database.Close(); err != nil {
				t.Fatal(err)
			}
			path := WrappingKeyPath(root)
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "missing":
				err = os.Remove(path)
			case "invalid":
				err = os.WriteFile(path, []byte("invalid"), 0o600)
			case "different":
				err = os.WriteFile(path, bytes.Repeat([]byte{7}, wrappingKeySize), 0o600)
			case "public":
				err = os.Chmod(path, 0o644)
			case "symlink":
				err = os.Rename(path, path+".original")
				if err == nil {
					err = os.Symlink(path+".original", path)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if reopened, err := OpenWithOptions(t.Context(), root, OpenOptions{Protection: ProtectionFile}); err == nil {
				reopened.Close()
				t.Fatal("unusable key accepted")
			}
			if mutation == "missing" {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("missing key regenerated: %v", err)
				}
			} else if mutation == "invalid" || mutation == "different" {
				current, err := os.ReadFile(path)
				if err != nil || bytes.Equal(current, original) {
					t.Fatalf("key replaced: %v", err)
				}
			}
		})
	}
}

func TestEncryptedSessionCertificateIdentityAndJobRegistryReopen(t *testing.T) {
	database := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
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
	session := ControlSession{SessionID: "cs_0123456789abcdefghijkl", AccessToken: access.String(), RefreshToken: refresh.String(), AccessExpiresAt: time.Now().Add(time.Hour), RefreshExpiresAt: time.Now().Add(2 * time.Hour)}
	if err := store.SaveControlSession(t.Context(), session); err != nil {
		t.Fatal(err)
	}
	certificate, err := store.CertificatesForPublisher("team", "pub_0123456789abcdefghijkl", exactCertificateTestPlan())
	if err != nil {
		t.Fatal(err)
	}
	pending, err := certificate.Pending(t.Context(), "route.example")
	if err != nil {
		t.Fatal(err)
	}
	identity := PublisherIdentity{ID: "publisher-1", PublicDocument: []byte(`{"client_id":"publisher-1"}`), SigningKey: []byte("opaque-signing-private-value")}
	if err := store.InstallPublisherIdentity(t.Context(), identity, PublisherSelection{Kind: "project", Key: "owner-url:project-a"}); err != nil {
		t.Fatal(err)
	}
	if err := database.SavePublisherJobRegistry(t.Context(), []byte("opaque-system-credential")); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		"SELECT access_token_ciphertext FROM control_sessions", "SELECT refresh_token_ciphertext FROM control_sessions",
		"SELECT signing_key_ciphertext FROM publisher_identities", "SELECT jobs_ciphertext FROM publisher_job_registry",
	} {
		var value []byte
		if err := database.db.QueryRowContext(t.Context(), query).Scan(&value); err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(value, sealedValuePrefix) {
			t.Fatalf("plaintext at rest: %s", query)
		}
	}
	root := database.Root()
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openFileDatabase(t, root)
	store, err = reopened.Server(t.Context(), "https://server.example")
	if err != nil {
		t.Fatal(err)
	}
	gotSession, found, err := store.ControlSession(t.Context())
	if err != nil || !found || gotSession.AccessToken != session.AccessToken {
		t.Fatalf("session reopen: %v, %v", found, err)
	}
	certificate, err = store.CertificatesForPublisher("team", "pub_0123456789abcdefghijkl", exactCertificateTestPlan())
	if err != nil {
		t.Fatal(err)
	}
	gotPending, err := certificate.Pending(t.Context(), "route.example")
	if err != nil || !gotPending.Key.Equal(pending.Key) {
		t.Fatalf("certificate reopen: %v", err)
	}
	gotIdentity, found, err := store.SelectedPublisherIdentity(t.Context(), "project", "owner-url:project-a")
	if err != nil || !found || gotIdentity.ID != identity.ID || !bytes.Equal(gotIdentity.PublicDocument, identity.PublicDocument) || !bytes.Equal(gotIdentity.SigningKey, identity.SigningKey) {
		t.Fatalf("identity reopen: %v, %v", found, err)
	}
	value, found, err := reopened.PublisherJobRegistry(t.Context())
	if err != nil || !found || string(value) != "opaque-system-credential" {
		t.Fatalf("system state reopen: %v, %v", found, err)
	}
	if err := reopened.RemovePublisherJobRegistry(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, found, err := reopened.PublisherJobRegistry(t.Context()); err != nil || found {
		t.Fatalf("removed system state: %v, %v", found, err)
	}
}

func TestFreshV1DoesNotReadOldDatabaseOrJournal(t *testing.T) {
	root, err := PrepareRoot(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"client.db", "client-v2.db", "client-v3.db", "journal.json"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("unreadable old plaintext"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	database := openFileDatabase(t, root)
	if _, found, err := database.SavedServer(t.Context()); err != nil || found {
		t.Fatalf("old state imported: %v, %v", found, err)
	}
	var count int
	if err := database.db.QueryRowContext(t.Context(), "SELECT count(*) FROM goose_db_version WHERE is_applied = 1 AND version_id > 0").Scan(&count); err != nil || count != 1 {
		t.Fatalf("baseline count: %d, %v", count, err)
	}
	info, err := os.Stat(WrappingKeyPath(database.Root()))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("wrapping key permissions: %v, %v", info, err)
	}
}
