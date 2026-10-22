package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// the platform-specific protector tests verify encryption. this scoped test
// protector keeps the enrollment transaction independent of the OS key store.
type publisherTestProtector struct{}

func (publisherTestProtector) Seal(_ context.Context, scope string, value []byte) ([]byte, error) {
	tag := sha256.Sum256([]byte(scope))
	return append(tag[:], value...), nil
}

func (publisherTestProtector) Open(_ context.Context, scope string, sealed []byte) ([]byte, error) {
	tag := sha256.Sum256([]byte(scope))
	if len(sealed) < len(tag) || !bytes.Equal(sealed[:len(tag)], tag[:]) {
		return nil, errors.New("wrong protected scope")
	}
	return bytes.Clone(sealed[len(tag):]), nil
}

func TestPublisherEnrollmentPromotionKeepsOneKeyAndSelection(t *testing.T) {
	database, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	store, err := database.Server(t.Context(), "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	store.secrets = publisherTestProtector{}
	// persistence keeps opaque protected bytes; native enrollment validates crypto.
	private := []byte("opaque signing key")
	pending := PendingPublisherEnrollment{
		EnrollmentID: "enrollment_123", SelectionKind: "namespace", SelectionKey: "team/domain",
		PublicKey: bytes.Repeat([]byte{7}, 32), SigningKey: private,
		EnrollmentSecret: []byte("one-use enrollment key"), ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := store.SavePendingPublisherEnrollment(t.Context(), pending); err != nil {
		t.Fatal(err)
	}
	if err := store.SavePendingPublisherEnrollment(t.Context(), pending); err != nil {
		t.Fatalf("identical pending enrollment was not idempotent: %v", err)
	}
	changed := pending
	changed.SigningKey = bytes.Repeat([]byte{43}, 64)
	if err := store.SavePendingPublisherEnrollment(t.Context(), changed); !errors.Is(err, ErrPublisherStateConflict) {
		t.Fatalf("changed pending key was accepted: %v", err)
	}
	identity := PublisherIdentity{ID: "publisher_123", PublicDocument: []byte(`{"client_id":"publisher_123"}`), SigningKey: private}
	if err := store.RecordPublisherEnrollmentResult(t.Context(), pending.EnrollmentID, identity.PublicDocument); err != nil {
		t.Fatal(err)
	}
	if err := store.SavePendingPublisherEnrollment(t.Context(), pending); err != nil {
		t.Fatalf("idempotent enrollment retry lost its saved redemption: %v", err)
	}
	conflicting := identity
	conflicting.PublicDocument = []byte(`{"client_id":"other"}`)
	if err := store.PromotePublisherEnrollment(t.Context(), pending.EnrollmentID, conflicting); !errors.Is(err, ErrPublisherStateConflict) {
		t.Fatalf("conflicting redemption was accepted: %v", err)
	}
	if err := store.PromotePublisherEnrollment(t.Context(), pending.EnrollmentID, identity); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.PendingPublisherEnrollment(t.Context(), pending.EnrollmentID); err != nil || found {
		t.Fatalf("pending enrollment survived promotion: found=%v, %v", found, err)
	}
	selected, found, err := store.SelectedPublisherIdentity(t.Context(), "namespace", pending.SelectionKey)
	if err != nil || !found || selected.ID != identity.ID || !bytes.Equal(selected.SigningKey, private) ||
		!bytes.Equal(selected.PublicDocument, identity.PublicDocument) {
		t.Fatalf("installed selection differs from redeemed identity: found=%v, id=%q, %v", found, selected.ID, err)
	}
	if err := store.SelectPublisherIdentity(t.Context(), "default_namespace", "", identity.ID); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.SelectedPublisherIdentity(t.Context(), "default_namespace", ""); err != nil || !found {
		t.Fatalf("default selection was not available: found=%v, %v", found, err)
	}
	other, err := database.Server(t.Context(), "https://other.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := other.PublisherIdentity(t.Context(), identity.ID); err != nil || found {
		t.Fatalf("publisher key crossed server scope: found=%v, %v", found, err)
	}
	digest := sha256.Sum256(pending.EnrollmentSecret)
	receiptKey := hex.EncodeToString(digest[:])
	if redeemed, found, err := store.SelectedPublisherIdentity(t.Context(), "enrollment", receiptKey); err != nil || !found || redeemed.ID != identity.ID {
		t.Fatalf("completed enrollment is not resumable: found=%v, id=%q, %v", found, redeemed.ID, err)
	}
	database.now = func() time.Time { return pending.ExpiresAt.Add(time.Second) }
	if _, found, err := store.SelectedPublisherIdentity(t.Context(), "enrollment", receiptKey); err != nil || found {
		t.Fatalf("expired enrollment receipt was reused: found=%v, %v", found, err)
	}
	if _, found, err := store.SelectedPublisherIdentity(t.Context(), "namespace", pending.SelectionKey); err != nil || !found {
		t.Fatalf("expiring a receipt removed the installed grant selection: found=%v, %v", found, err)
	}
}

func TestPublisherIdentityInstallationRollsBackKeyAndSelection(t *testing.T) {
	database := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
	store, err := database.Server(t.Context(), "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	selection := PublisherSelection{Kind: "job", Key: "job:one"}
	old := PublisherIdentity{ID: "opaque-old", PublicDocument: []byte(`{"opaque":"old document"}`), SigningKey: []byte("opaque old signing bytes")}
	if err := store.InstallPublisherIdentity(t.Context(), old, selection); err != nil {
		t.Fatal(err)
	}
	installed := PublisherIdentity{ID: "opaque-new", PublicDocument: []byte("{ \"opaque\" : \"new document\" }"), SigningKey: []byte("opaque new signing bytes")}
	if _, err := database.db.ExecContext(t.Context(), `CREATE TRIGGER reject_publisher_selection BEFORE INSERT ON publisher_selections
        WHEN NEW.selection_key = 'job:one' BEGIN SELECT RAISE(ABORT, 'fixture selection write failed'); END`); err != nil {
		t.Fatal(err)
	}
	if err := store.InstallPublisherIdentity(t.Context(), installed, selection); err == nil {
		t.Fatal("injected selection failure succeeded")
	}
	if _, found, err := store.PublisherIdentity(t.Context(), installed.ID); err != nil || found {
		t.Fatalf("failed installation left its key installed: found=%v, %v", found, err)
	}
	selected, found, err := store.SelectedPublisherIdentity(t.Context(), selection.Kind, selection.Key)
	if err != nil || !found || selected.ID != old.ID || !bytes.Equal(selected.SigningKey, old.SigningKey) {
		t.Fatalf("failed installation replaced the existing selection: found=%v, %v", found, err)
	}
	if _, err := database.db.ExecContext(t.Context(), `DROP TRIGGER reject_publisher_selection`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := store.InstallPublisherIdentity(t.Context(), installed, selection); err != nil {
			t.Fatal(err)
		}
	}
	selected, found, err = store.SelectedPublisherIdentity(t.Context(), selection.Kind, selection.Key)
	if err != nil || !found || selected.ID != installed.ID || !bytes.Equal(selected.SigningKey, installed.SigningKey) || !bytes.Equal(selected.PublicDocument, installed.PublicDocument) {
		t.Fatalf("installed opaque key or exact public document changed: found=%v, %v", found, err)
	}
	var ciphertext []byte
	if err := database.db.QueryRowContext(t.Context(), `SELECT signing_key_ciphertext FROM publisher_identities WHERE identity_id = ?`, installed.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(ciphertext, sealedValuePrefix) || bytes.Contains(ciphertext, installed.SigningKey) {
		t.Fatal("installed opaque key is not protected at rest")
	}
	changed := installed
	changed.SigningKey = []byte("a different opaque signing value")
	otherSelection := PublisherSelection{Kind: "job", Key: "job:two"}
	if err := store.InstallPublisherIdentity(t.Context(), changed, otherSelection); !errors.Is(err, ErrPublisherStateConflict) {
		t.Fatal("installation replaced an existing signing key", err)
	}
	if _, found, err := store.SelectedPublisherIdentity(t.Context(), otherSelection.Kind, otherSelection.Key); err != nil || found {
		t.Fatalf("conflicting key acquired a new selection: found=%v, %v", found, err)
	}
}

func TestPublisherEnrollmentPromotionRollsBackInstallationAndReceipt(t *testing.T) {
	database := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
	store, err := database.Server(t.Context(), "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	pending := PendingPublisherEnrollment{EnrollmentID: "opaque-enrollment", SelectionKind: "namespace", SelectionKey: "owner-namespace:team-domain", PublicKey: bytes.Repeat([]byte{9}, 32), SigningKey: []byte("opaque signing value"), EnrollmentSecret: []byte("opaque enrollment value"), ExpiresAt: database.now().Add(time.Hour)}
	if err := store.SavePendingPublisherEnrollment(t.Context(), pending); err != nil {
		t.Fatal(err)
	}
	identity := PublisherIdentity{ID: "opaque-publisher", PublicDocument: []byte(`{"opaque":"result"}`), SigningKey: pending.SigningKey}
	if err := store.RecordPublisherEnrollmentResult(t.Context(), pending.EnrollmentID, identity.PublicDocument); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.ExecContext(t.Context(), `CREATE TRIGGER reject_pending_delete BEFORE DELETE ON pending_publisher_enrollments
        BEGIN SELECT RAISE(ABORT, 'fixture pending delete failed'); END`); err != nil {
		t.Fatal(err)
	}
	if err := store.PromotePublisherEnrollment(t.Context(), pending.EnrollmentID, identity); err == nil {
		t.Fatal("injected promotion failure succeeded")
	}
	if _, found, err := store.PublisherIdentity(t.Context(), identity.ID); err != nil || found {
		t.Fatalf("failed promotion installed its identity: found=%v, %v", found, err)
	}
	digest := sha256.Sum256(pending.EnrollmentSecret)
	for _, selection := range []PublisherSelection{{Kind: pending.SelectionKind, Key: pending.SelectionKey}, {Kind: "enrollment", Key: hex.EncodeToString(digest[:])}} {
		if _, found, err := store.SelectedPublisherIdentity(t.Context(), selection.Kind, selection.Key); err != nil || found {
			t.Fatalf("failed promotion installed a selection or receipt: found=%v, %v", found, err)
		}
	}
	stored, found, err := store.PendingPublisherEnrollment(t.Context(), pending.EnrollmentID)
	if err != nil || !found || !bytes.Equal(stored.SigningKey, pending.SigningKey) || !bytes.Equal(stored.ResultJSON, identity.PublicDocument) || !stored.ExpiresAt.Equal(pending.ExpiresAt) {
		t.Fatalf("failed promotion lost its retry state: found=%v, %v", found, err)
	}
	if _, err := database.db.ExecContext(t.Context(), `DROP TRIGGER reject_pending_delete`); err != nil {
		t.Fatal(err)
	}
	if err := store.PromotePublisherEnrollment(t.Context(), pending.EnrollmentID, identity); err != nil {
		t.Fatal("retrying the same protected promotion failed", err)
	}
}

func TestPublisherJobDocumentsHaveDistinctProtectedScopes(t *testing.T) {
	database, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	database.secrets = publisherTestProtector{}
	if err := database.SavePublisherJobRegistry(t.Context(), []byte(`[{"job_id":"job_1"}]`)); err != nil {
		t.Fatal(err)
	}
	if err := database.SavePublisherJobFileManifest(t.Context(), []byte(`{"db":"pinned"}`)); err != nil {
		t.Fatal(err)
	}
	jobs, found, err := database.PublisherJobRegistry(t.Context())
	if err != nil || !found || string(jobs) != `[{"job_id":"job_1"}]` {
		t.Fatalf("job registry = %q, found=%v, %v", jobs, found, err)
	}
	manifest, found, err := database.PublisherJobFileManifest(t.Context())
	if err != nil || !found || string(manifest) != `{"db":"pinned"}` {
		t.Fatalf("file manifest = %q, found=%v, %v", manifest, found, err)
	}
	var stored []byte
	if err := database.db.QueryRowContext(t.Context(), `SELECT jobs_ciphertext FROM publisher_job_registry WHERE id = 1`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if _, err := database.secrets.Open(t.Context(), "publisher-job-file-manifest", stored); err == nil {
		t.Fatal("registry was accepted under the manifest scope")
	}
}
