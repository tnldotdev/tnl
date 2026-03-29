package state

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xcadams/tnl/internal/credentials"
)

func TestAccessCredentialLifecycle(t *testing.T) {
	db, err := Open(context.Background(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	now := time.Unix(1_700_000_000, 0)
	expiresAt := now.Add(30 * 24 * time.Hour)
	token, lookupID, hash, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	want := Principal{ID: "principal", DisplayName: "Principal", Email: "principal@example.com"}
	if err := CreateAccessCredential(
		context.Background(), db, want, lookupID, hash, now, expiresAt,
	); err != nil {
		t.Fatal(err)
	}

	parsedID, parsedHash, err := credentials.ParseAccessToken(token)
	if err != nil {
		t.Fatal(err)
	}
	got, err := AuthenticateAccessCredential(context.Background(), db, parsedID, parsedHash, now)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("principal = %#v, want %#v", got, want)
	}

	var storedHash []byte
	if err := db.QueryRow(
		"SELECT secret_hash FROM access_credentials WHERE id = ?", lookupID.String(),
	).Scan(&storedHash); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(storedHash, hash[:]) {
		t.Fatal("stored secret hash differs")
	}

	wrongHash := hash
	wrongHash[0] ^= 1
	assertInvalidAccessCredential(t, db, lookupID, wrongHash, now)
	assertInvalidAccessCredential(t, db, lookupID, hash, expiresAt)

	if err := RevokeAccessCredential(context.Background(), db, lookupID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := RevokeAccessCredential(context.Background(), db, lookupID, now.Add(2*time.Hour)); err != nil {
		t.Fatalf("repeat revocation: %v", err)
	}
	assertInvalidAccessCredential(t, db, lookupID, hash, now)
	if err := RevokeAccessCredential(
		context.Background(), db, credentials.CredentialID("missing"), now,
	); !errors.Is(err, ErrAccessCredentialNotFound) {
		t.Fatalf("missing revocation error = %v", err)
	}
}

func TestCreateAccessCredentialRollsBack(t *testing.T) {
	db, err := Open(context.Background(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	now := time.Unix(1_700_000_000, 0)
	_, lookupID, hash, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := CreateAccessCredential(
		context.Background(), db, Principal{ID: "first"}, lookupID, hash, now, now.Add(time.Hour),
	); err != nil {
		t.Fatal(err)
	}
	if err := CreateAccessCredential(
		context.Background(), db, Principal{ID: "rolled-back"}, credentials.CredentialID("different"), hash, now, now.Add(time.Hour),
	); err == nil {
		t.Fatal("duplicate secret hash succeeded")
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM principals WHERE id = 'rolled-back'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("rolled-back principals = %d, want 0", count)
	}
}

func assertInvalidAccessCredential(
	t *testing.T,
	db *sql.DB,
	credentialID credentials.CredentialID,
	hash credentials.SecretHash,
	now time.Time,
) {
	t.Helper()
	if _, err := AuthenticateAccessCredential(context.Background(), db, credentialID, hash, now); !errors.Is(err, credentials.ErrInvalidAccessToken) {
		t.Fatalf("authentication error = %v", err)
	}
}
