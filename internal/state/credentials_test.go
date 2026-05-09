package state

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/state/statedb"
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
	want := Identity{ID: "identity", DisplayName: "Identity", Email: "identity@example.com"}
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
		t.Fatalf("identity = %#v, want %#v", got, want)
	}

	stored, err := statedb.New(db).GetAccessCredential(context.Background(), lookupID.String())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored.SecretHash, hash[:]) {
		t.Fatal("stored secret hash differs")
	}

	wrongHash := hash
	wrongHash[0] ^= 1
	assertInvalidAccessCredential(t, db, lookupID, wrongHash, now)
	assertInvalidAccessCredential(t, db, lookupID, hash, expiresAt)

	if err := RevokeAccessCredential(context.Background(), db, want.ID, lookupID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := RevokeAccessCredential(context.Background(), db, want.ID, lookupID, now.Add(2*time.Hour)); err != nil {
		t.Fatalf("repeat revocation: %v", err)
	}
	assertInvalidAccessCredential(t, db, lookupID, hash, now)
	if err := RevokeAccessCredential(
		context.Background(), db, want.ID, credentials.CredentialID("missing"), now,
	); !errors.Is(err, ErrAccessCredentialNotFound) {
		t.Fatalf("missing revocation error = %v", err)
	}
}

func TestRevokeAccessCredentialEnforcesOwnership(t *testing.T) {
	db, err := Open(context.Background(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	now := time.Unix(1_700_000_000, 0)
	token, credentialID, hash, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	owner := Identity{ID: "identity_owner"}
	if err := CreateAccessCredential(
		context.Background(), db, owner, credentialID, hash, now, now.Add(time.Hour),
	); err != nil {
		t.Fatal(err)
	}

	if err := RevokeAccessCredential(
		context.Background(), db, "identity_other", credentialID, now,
	); !errors.Is(err, ErrAccessCredentialNotFound) {
		t.Fatalf("wrong-owner revocation error = %v", err)
	}
	parsedID, parsedHash, err := credentials.ParseAccessToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AuthenticateAccessCredential(context.Background(), db, parsedID, parsedHash, now); err != nil {
		t.Fatalf("wrong-owner revocation invalidated credential: %v", err)
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
		context.Background(), db, Identity{ID: "first"}, lookupID, hash, now, now.Add(time.Hour),
	); err != nil {
		t.Fatal(err)
	}
	if err := CreateAccessCredential(
		context.Background(), db, Identity{ID: "rolled-back"}, credentials.CredentialID("different"), hash, now, now.Add(time.Hour),
	); err == nil {
		t.Fatal("duplicate secret hash succeeded")
	}

	count, err := statedb.New(db).CountIdentityByID(context.Background(), "rolled-back")
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("rolled-back identities = %d, want 0", count)
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
