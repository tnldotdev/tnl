package clientstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestPublisherSigningScopesUseOneInstalledKey(t *testing.T) {
	database := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
	store, err := database.Server(t.Context(), "https://server.example")
	if err != nil {
		t.Fatal(err)
	}
	id, err := opaqueid.New(opaqueid.PublisherIdentityPrefix)
	if err != nil {
		t.Fatal(err)
	}
	private := []byte("opaque signing value")
	identity := PublisherIdentity{ID: id, PublicDocument: []byte(fmt.Sprintf(`{"client_id":%q}`, id)), SigningKey: private}
	if err := store.ImportPublisherIdentity(t.Context(), identity); err != nil {
		t.Fatal(err)
	}
	if err := store.SelectPublisherIdentity(t.Context(), "default_namespace", "", identity.ID); err != nil {
		t.Fatal(err)
	}
	selected, found, err := store.SelectedPublisherIdentity(t.Context(), "default_namespace", "")
	if err != nil || !found || selected.ID != id || !bytes.Equal(selected.SigningKey, private) {
		t.Fatalf("selected identity = %q, found=%v: %v", selected.ID, found, err)
	}
	var identities int
	if err := database.db.QueryRowContext(t.Context(), `SELECT count(*) FROM publisher_identities`).Scan(&identities); err != nil || identities != 1 {
		t.Fatalf("installed key rows = %d: %v", identities, err)
	}
}

func TestPublisherEnrollmentScopeRetainsOneRetryKey(t *testing.T) {
	database := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
	store, err := database.Server(t.Context(), "https://server.example")
	if err != nil {
		t.Fatal(err)
	}
	id, err := opaqueid.New(opaqueid.PublisherEnrollmentPrefix)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("opaque enrollment secret")
	scope := "owner-namespace:team-domain"
	pending := PendingPublisherEnrollment{EnrollmentID: id, SelectionKind: "namespace", SelectionKey: scope, PublicKey: bytes.Repeat([]byte{7}, 32), SigningKey: []byte("opaque signing key"), EnrollmentSecret: secret, ExpiresAt: database.now().Add(10 * time.Minute)}
	if err := store.SavePendingPublisherEnrollment(t.Context(), pending); err != nil {
		t.Fatal(err)
	}
	initial, found, err := store.PendingPublisherEnrollment(t.Context(), id)
	if err != nil || !found || !bytes.Equal(initial.SigningKey, pending.SigningKey) || !bytes.Equal(initial.EnrollmentSecret, secret) {
		t.Fatalf("pending enrollment: found=%v, %v", found, err)
	}
	var keyCiphertext, secretCiphertext []byte
	if err := database.db.QueryRowContext(t.Context(), `SELECT signing_key_ciphertext, enrollment_secret_ciphertext FROM pending_publisher_enrollments WHERE enrollment_id = ?`, id).Scan(&keyCiphertext, &secretCiphertext); err != nil {
		t.Fatal(err)
	}
	for _, value := range [][]byte{keyCiphertext, secretCiphertext} {
		if !bytes.HasPrefix(value, sealedValuePrefix) || bytes.Contains(value, pending.SigningKey) || bytes.Contains(value, secret) {
			t.Fatal("pending enrollment key or secret was stored in plaintext")
		}
	}
	if _, err := store.secrets.Open(t.Context(), pendingSecretContext(id), keyCiphertext); err == nil {
		t.Fatal("pending signing key was accepted as its enrollment secret")
	}
	root := database.Root()
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	database = openFileDatabase(t, root)
	store, err = database.Server(t.Context(), "https://server.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SavePendingPublisherEnrollment(t.Context(), pending); err != nil {
		t.Fatal(err)
	}
	retry, found, err := store.PendingPublisherEnrollmentForSelection(t.Context(), "namespace", scope)
	if err != nil || !found || !bytes.Equal(retry.SigningKey, initial.SigningKey) || !bytes.Equal(retry.EnrollmentSecret, initial.EnrollmentSecret) || !retry.ExpiresAt.Equal(initial.ExpiresAt) {
		t.Fatalf("enrollment retry changed the signing key: found=%v, %v", found, err)
	}
	identityID, err := opaqueid.New(opaqueid.PublisherIdentityPrefix)
	if err != nil {
		t.Fatal(err)
	}
	installed := PublisherIdentity{ID: identityID, PublicDocument: []byte(fmt.Sprintf(`{"client_id":%q}`, identityID)), SigningKey: retry.SigningKey}
	if err := store.RecordPublisherEnrollmentResult(t.Context(), id, installed.PublicDocument); err != nil {
		t.Fatal(err)
	}
	if err := store.PromotePublisherEnrollment(t.Context(), id, installed); err != nil {
		t.Fatal(err)
	}
	selected, found, err := store.SelectedPublisherIdentity(t.Context(), "namespace", scope)
	if err != nil || !found || selected.ID != identityID || !bytes.Equal(selected.SigningKey, retry.SigningKey) {
		t.Fatalf("enrollment did not promote the scoped identity: found=%v, id=%q, %v", found, selected.ID, err)
	}
	digest := sha256.Sum256(secret)
	receiptKey := hex.EncodeToString(digest[:])
	if receipt, found, err := store.SelectedPublisherIdentity(t.Context(), "enrollment", receiptKey); err != nil || !found || receipt.ID != identityID {
		t.Fatalf("promotion changed the enrollment receipt: found=%v, %v", found, err)
	}
	database.now = func() time.Time { return pending.ExpiresAt }
	if _, found, err := store.SelectedPublisherIdentity(t.Context(), "enrollment", receiptKey); err != nil || found {
		t.Fatalf("expired enrollment receipt was reused: found=%v, %v", found, err)
	}
	if _, found, err := store.SelectedPublisherIdentity(t.Context(), "namespace", scope); err != nil || !found {
		t.Fatalf("receipt expiry removed the installed selection: found=%v, %v", found, err)
	}
}
