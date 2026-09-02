package state

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/state/statedb"
)

func TestLoginTokenLifecycle(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	db, err := Open(context.Background(), directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	first, generated, err := EnsureLoginToken(t.Context(), db)
	if err != nil {
		t.Fatal(err)
	}
	if !generated || first == "" {
		t.Fatalf("generated = %t, token = %q", generated, first)
	}
	second, generated, err := EnsureLoginToken(t.Context(), db)
	if err != nil {
		t.Fatal(err)
	}
	if generated || second != first {
		t.Fatalf("second token = %q, generated = %t", second, generated)
	}
	if revision, err := ReadLoginTokenRevision(t.Context(), db); err != nil || revision != 1 {
		t.Fatalf("login token revision = %d, error = %v", revision, err)
	}
	now := time.Now().UTC()
	session, _, refresh := newStoredControlSession(t, 1, now)
	if err := CreateControlSession(t.Context(), db, session, nil, time.Time{}); err != nil {
		t.Fatal(err)
	}
	refreshID, refreshHash, _ := credentials.ParseRefreshToken(refresh)
	_, accessID, accessHash, _ := credentials.NewAccessToken()
	_, nextRefreshID, nextRefreshHash, _ := credentials.NewRefreshToken()
	if _, err := RotateControlSession(
		t.Context(), db, refreshID, refreshHash, accessID, accessHash,
		now.Add(2*time.Hour), nextRefreshID, nextRefreshHash, now.Add(time.Minute),
	); err != nil {
		t.Fatal(err)
	}

	rotated, err := RotateLoginToken(t.Context(), db)
	if err != nil {
		t.Fatal(err)
	}
	if rotated == first {
		t.Fatal("rotation preserved the previous token")
	}
	if stored, err := ReadLoginToken(t.Context(), db); err != nil || stored != rotated {
		t.Fatalf("stored token = %q, %v", stored, err)
	}
	if revision, err := ReadLoginTokenRevision(t.Context(), db); err != nil || revision != 2 {
		t.Fatalf("rotated login token revision = %d, error = %v", revision, err)
	}
	storedSession, err := statedb.New(db).GetControlSession(t.Context(), session.ID)
	if err != nil || !storedSession.RevokedAt.Valid || !storedSession.AccessTokenRevokedAt.Valid || !storedSession.RefreshTokenRevokedAt.Valid {
		t.Fatalf("session after source rotation = %#v, error = %v", storedSession, err)
	}
	if count, err := statedb.New(db).CountControlSessionRefreshHistory(t.Context(), session.ID); err != nil || count != 0 {
		t.Fatalf("refresh history after source rotation = %d, error = %v", count, err)
	}
}

func TestDirectoryLock(t *testing.T) {
	directory := t.TempDir()
	first, err := LockDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LockDirectory(directory); !errors.Is(err, ErrLocked) {
		t.Fatalf("second lock error = %v, want %v", err, ErrLocked)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := LockDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}
