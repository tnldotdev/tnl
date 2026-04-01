package routes

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/internal/state"
)

func TestRouteLeaseLifecycle(t *testing.T) {
	db, err := state.Open(context.Background(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Unix(1_700_000_000, 0).UTC()
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }
	if _, err := db.Exec(`INSERT INTO principals (id, display_name, email, created_at)
		VALUES ('owner', 'Owner', '', ?)`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO principals (id, display_name, email, created_at)
		VALUES ('other', 'Other', '', ?)`, now.Unix()); err != nil {
		t.Fatal(err)
	}

	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(context.Background(), "owner", "Route.Example.", "localhost:3000", "boot-1", routeToken)
	if err != nil {
		t.Fatal(err)
	}
	if created.Route.Hostname != "route.example" || created.Route.Generation != 1 {
		t.Fatalf("created route = %#v", created.Route)
	}
	otherToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(context.Background(), "other", "route.example", "localhost:3001", "boot-1", otherToken); !errors.Is(err, ErrNameUnavailable) {
		t.Fatalf("competing claim error = %v", err)
	}
	lease, err := store.AuthenticateLease(context.Background(), created.Route.ID, 1, created.LeaseToken, "boot-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterTransport(context.Background(), lease, "nodekey:server", "test"); err != nil {
		t.Fatal(err)
	}
	lease, err = store.AuthenticateLease(context.Background(), created.Route.ID, 1, created.LeaseToken, "boot-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Ready(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
	now = now.Add(15 * time.Second)
	if expiresAt, err := store.Heartbeat(context.Background(), lease); err != nil || !expiresAt.Equal(now.Add(LeaseLifetime)) {
		t.Fatalf("heartbeat = %v, %v", expiresAt, err)
	}

	replacement, err := store.Acquire(context.Background(), "owner", created.Route.ID, "boot-1", routeToken)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Route.Generation != 2 || replacement.Lease.Generation != 2 {
		t.Fatalf("replacement = %#v", replacement)
	}
	if _, err := store.AuthenticateLease(context.Background(), created.Route.ID, 1, created.LeaseToken, "boot-1"); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("stale lease error = %v", err)
	}
	if _, err := store.Acquire(context.Background(), "owner", created.Route.ID, "boot-1", credentials.RouteToken(replacement.LeaseToken)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("wrong-class acquire error = %v", err)
	}
	restartedToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := store.Create(
		context.Background(), "owner", "route.example", "localhost:3001", "boot-1", restartedToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Route.ID != created.Route.ID || restarted.Route.Generation != 3 || restarted.Route.DisplayTarget != "localhost:3001" {
		t.Fatalf("restarted route = %#v", restarted.Route)
	}
	if _, err := store.Acquire(context.Background(), "owner", created.Route.ID, "boot-1", routeToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("rotated route token error = %v", err)
	}
	if _, err := store.AuthenticateLease(context.Background(), created.Route.ID, 2, replacement.LeaseToken, "boot-1"); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("replaced lease error = %v", err)
	}

	if err := store.InvalidateOtherBoots(context.Background(), "boot-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthenticateLease(context.Background(), created.Route.ID, 3, restarted.LeaseToken, "boot-2"); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("old boot lease error = %v", err)
	}
	routes, err := store.List(context.Background(), "owner")
	if err != nil || len(routes) != 1 || routes[0].DisplayTarget != "localhost:3001" {
		t.Fatalf("list = %#v, %v", routes, err)
	}
	if err := store.Delete(context.Background(), "owner", created.Route.ID); err != nil {
		t.Fatal(err)
	}
	if routes, err := store.List(context.Background(), "owner"); err != nil || len(routes) != 0 {
		t.Fatalf("list after delete = %#v, %v", routes, err)
	}
}
