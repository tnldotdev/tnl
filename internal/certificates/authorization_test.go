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
		id, hostname, local_target, status, version,
		authorization_issuer, authorization_id, authorization_key_id, authorization_retry_id,
		authorization_revision, authorization_expires_at, authorization_request_hash, created_at
	) VALUES (?, ?, ?, 'active', 1, ?, ?, ?, ?, 1, ?, zeroblob(32), 1)`,
		"route_0123456789abcdef0123456789abcdef", "route.example", "localhost:3000",
		"https://authority.example", "authorization_0123456789abcdef0123456789abcdef", "key-1",
		"retry_0123456789abcdef0123456789abcdef", int64(99)); err != nil {
		t.Fatal(err)
	}
	store, err := newStore(db, func() time.Time { return time.Unix(0, 100).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.routeHostname(ctx, "route_0123456789abcdef0123456789abcdef", 1); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("expired signed route error = %v", err)
	}
}
