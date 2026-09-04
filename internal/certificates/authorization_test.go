package certificates

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/state"
)

func TestRouteHostnameRejectsExpiredSignedAuthorization(t *testing.T) {
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(ctx, `INSERT INTO routes (
		id, hostname, local_target, status, route_version,
		authorization_issuer, authorization_id, authorization_key_id, authorization_retry_id,
		authorization_revision, authorization_expires_at, authorization_request_hash, created_at
		) VALUES (?, ?, ?, 'enabled', 1, ?, ?, ?, ?, 1, ?, zeroblob(32), 1)`,
		"route_0123456789abcdef0123456789abcdef", "route.example", "localhost:3000",
		"https://authority.example", "authorization_0123456789abcdef0123456789abcdef", "key-1",
		"retry_0123456789abcdef0123456789abcdef", int64(99)); err != nil {
		t.Fatal(err)
	}
	store, err := newStore(db, func() time.Time { return time.Unix(0, 100).UTC() }, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.routeHostname(ctx, "route_0123456789abcdef0123456789abcdef", 1); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("expired signed route error = %v", err)
	}
}

func TestIssuanceMutationsRejectExpiredSignedAuthorization(t *testing.T) {
	ctx := t.Context()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	const routeID = "route_0123456789abcdef0123456789abcdef"
	if _, err := db.ExecContext(ctx, `INSERT INTO routes (
		id, hostname, local_target, status, route_version,
		authorization_issuer, authorization_id, authorization_key_id, authorization_retry_id,
		authorization_revision, authorization_expires_at, authorization_request_hash, created_at
		) VALUES (?, 'route.example', 'localhost:3000', 'enabled', 1, ?, ?, ?, ?, 1, 99, zeroblob(32), 1)`,
		routeID, "https://authority.example", "authorization_0123456789abcdef0123456789abcdef", "key-1",
		"retry_0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	current := time.Unix(0, 98).UTC()
	store, err := newStore(db, func() time.Time { return current }, testDirectoryURL, "tlsserver")
	if err != nil {
		t.Fatal(err)
	}
	issuance, _, err := store.createIssuance(ctx, routeID, 1, "route.example", []byte{1}, [32]byte{1}, [32]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	current = time.Unix(0, 100).UTC()
	issuance.Status = StatusAuthorizing
	if err := store.saveIssuance(ctx, issuance); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("expired save error = %v", err)
	}
	if _, err := store.rebindIssuance(ctx, issuance, 1); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("expired rebind error = %v", err)
	}
	if _, _, err := store.createIssuance(ctx, routeID, 1, "route.example", []byte{2}, [32]byte{3}, [32]byte{4}); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("expired insert error = %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE certificate_issuances
		SET status = 'waiting_for_install', certificate_pem = X'01',
			challenge_url = 'challenge', challenge_digest = zeroblob(32), challenge_expires_at = 200
		WHERE id = ?
	`, issuance.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.removeChallenge(ctx, issuance.ID); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("expired cleanup error = %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE certificate_issuances
		SET challenge_url = NULL, challenge_digest = NULL, challenge_expires_at = NULL
		WHERE id = ?
	`, issuance.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.markInstalled(ctx, issuance.ID, routeID, 1); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("expired installation error = %v", err)
	}
}
