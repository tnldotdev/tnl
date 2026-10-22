package state

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestGroupBootstrapRefreshKeepsTaskKeyAndServerScope(t *testing.T) {
	database, err := OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), OpenOptions{Protection: ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	profile, err := database.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	scope := "project-publisher:group:project-one:cloud:task-one"
	pending := PendingPublisherEnrollment{EnrollmentID: "group-pending", SelectionKind: "project", SelectionKey: scope, PublicKey: public, SigningKey: private, ExpiresAt: time.Now().Add(time.Hour)}
	if err := profile.SavePendingPublisherEnrollment(t.Context(), pending); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"first-bootstrap", "replacement-bootstrap"} {
		if err := profile.SetPublisherGroupEnrollmentSecret(t.Context(), pending.EnrollmentID, scope, []byte(secret)); err != nil {
			t.Fatal(err)
		}
		saved, found, err := profile.PendingPublisherEnrollmentForSelection(t.Context(), "project", scope)
		if err != nil || !found || !bytes.Equal(saved.SigningKey, private) || !bytes.Equal(saved.PublicKey, public) || string(saved.EnrollmentSecret) != secret {
			t.Fatalf("task key changed during refresh: %v", err)
		}
	}
	other, err := database.Server(t.Context(), "https://other.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := other.SetPublisherGroupEnrollmentSecret(t.Context(), pending.EnrollmentID, scope, []byte("wrong-server")); !errors.Is(err, ErrPublisherStateConflict) {
		t.Fatalf("server boundary: %v", err)
	}
	if err := profile.RecordPublisherEnrollmentResult(t.Context(), pending.EnrollmentID, []byte(`{"publisher_identity_id":"task"}`)); err != nil {
		t.Fatal(err)
	}
	if err := profile.SetPublisherGroupEnrollmentSecret(t.Context(), pending.EnrollmentID, scope, []byte("after-redemption")); !errors.Is(err, ErrPublisherStateConflict) {
		t.Fatalf("redemption was overwritten: %v", err)
	}
}
