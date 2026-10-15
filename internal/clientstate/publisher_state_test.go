package clientstate

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	private := bytes.Repeat([]byte{42}, 64)
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
