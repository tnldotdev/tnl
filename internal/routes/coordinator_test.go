package routes

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/internal/state"
	"github.com/0xcadams/tnl/internal/worker"
	"tailscale.com/types/key"
)

func TestCoordinatorPublishesOnlyReadyCurrentGeneration(t *testing.T) {
	coordinator, owner := newCoordinatorFixture(t)

	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := coordinator.Create(context.Background(), "owner", "route.example", "localhost:3000", routeToken)
	if err != nil {
		t.Fatal(err)
	}
	if created.IngressPublicKey == "" {
		t.Fatal("create omitted ingress key")
	}
	if _, ok := coordinator.Lookup("route.example"); ok {
		t.Fatal("pending route was published")
	}
	if _, ok := coordinator.LookupChallenge("route.example"); ok {
		t.Fatal("pending route was challenge-routable before transport attachment")
	}
	serverKey := key.NewNode().Public().String()
	if err := coordinator.RegisterTransport(
		context.Background(), created.Route.ID, 1, created.LeaseToken, serverKey, "test",
	); err != nil {
		t.Fatal(err)
	}
	if _, ok := coordinator.Lookup("route.example"); ok {
		t.Fatal("starting route was published")
	}
	if challenge, ok := coordinator.LookupChallenge("route.example"); !ok || challenge.Generation != 1 {
		t.Fatalf("starting challenge route = %#v, %v", challenge, ok)
	}
	if err := coordinator.Ready(context.Background(), created.Route.ID, 1, created.LeaseToken); err != nil {
		t.Fatal(err)
	}
	active, ok := coordinator.Lookup("route.example")
	if !ok || active.Generation != 1 {
		t.Fatalf("active route = %#v, %v", active, ok)
	}

	replacement, err := coordinator.Acquire(context.Background(), "owner", created.Route.ID, routeToken)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Lease.Generation != 2 {
		t.Fatalf("replacement generation = %d", replacement.Lease.Generation)
	}
	if _, ok := coordinator.Lookup("route.example"); ok {
		t.Fatal("old generation remained published")
	}
	if _, ok := coordinator.LookupChallenge("route.example"); ok {
		t.Fatal("old generation remained challenge-routable")
	}
	if owner.routes[0].closed.Load() != 1 {
		t.Fatal("old generation was not closed")
	}
	if _, err := coordinator.Heartbeat(context.Background(), created.Route.ID, 1, created.LeaseToken); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("stale heartbeat error = %v", err)
	}

	if err := coordinator.RegisterTransport(
		context.Background(), created.Route.ID, 2, replacement.LeaseToken, serverKey, "test",
	); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Ready(context.Background(), created.Route.ID, 2, replacement.LeaseToken); err != nil {
		t.Fatal(err)
	}
	coordinator.RemoveOwner("local")
	if _, ok := coordinator.Lookup("route.example"); ok {
		t.Fatal("route remained published after owner loss")
	}
	if _, ok := coordinator.LookupChallenge("route.example"); ok {
		t.Fatal("route remained challenge-routable after owner loss")
	}
	if _, err := coordinator.Heartbeat(context.Background(), created.Route.ID, 2, replacement.LeaseToken); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("lost-owner heartbeat error = %v", err)
	}
}

func TestCoordinatorExpiresUnrenewedLease(t *testing.T) {
	coordinator, owner := newCoordinatorFixture(t)
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := coordinator.Create(context.Background(), "owner", "route.example", "localhost:3000", routeToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.RegisterTransport(
		context.Background(), created.Route.ID, 1, created.LeaseToken,
		key.NewNode().Public().String(), "test",
	); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Ready(context.Background(), created.Route.ID, 1, created.LeaseToken); err != nil {
		t.Fatal(err)
	}

	coordinator.expireDue(context.Background(), created.Lease.ExpiresAt)
	if _, ok := coordinator.Lookup("route.example"); ok {
		t.Fatal("expired route remained published")
	}
	if owner.routes[0].closed.Load() != 1 {
		t.Fatal("expired route backend was not closed")
	}
	if provisioning, active := coordinator.Stats(); provisioning != 0 || active != 0 {
		t.Fatalf("stats after expiry = %d provisioning, %d active", provisioning, active)
	}
	if _, err := coordinator.Heartbeat(
		context.Background(), created.Route.ID, 1, created.LeaseToken,
	); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("expired heartbeat error = %v", err)
	}
}

func TestCoordinatorReclaimsDurableRoute(t *testing.T) {
	coordinator, owner := newCoordinatorFixture(t)
	firstToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	first, err := coordinator.Create(context.Background(), "owner", "route.example", "localhost:3000", firstToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.RegisterTransport(
		context.Background(), first.Route.ID, 1, first.LeaseToken, key.NewNode().Public().String(), "test",
	); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Ready(context.Background(), first.Route.ID, 1, first.LeaseToken); err != nil {
		t.Fatal(err)
	}

	replacementToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := coordinator.Create(
		context.Background(), "owner", "route.example", "localhost:3001", replacementToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Route.ID != first.Route.ID || replacement.Route.Generation != 2 {
		t.Fatalf("replacement = %#v", replacement)
	}
	if _, ok := coordinator.Lookup("route.example"); ok {
		t.Fatal("replaced generation remained published")
	}
	if owner.routes[0].closed.Load() != 1 {
		t.Fatal("replaced generation backend was not closed")
	}
	if _, err := coordinator.Acquire(context.Background(), "owner", first.Route.ID, firstToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("rotated route token error = %v", err)
	}
}

func TestCoordinatorAcceptsOnlyExactTransportReplay(t *testing.T) {
	coordinator, owner := newCoordinatorFixture(t)
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := coordinator.Create(context.Background(), "owner", "route.example", "localhost:3000", routeToken)
	if err != nil {
		t.Fatal(err)
	}
	serverKey := key.NewNode().Public().String()
	register := func(key, profile string) error {
		return coordinator.RegisterTransport(
			context.Background(), created.Route.ID, 1, created.LeaseToken, key, profile,
		)
	}
	if err := register(serverKey, "test"); err != nil {
		t.Fatal(err)
	}
	if err := register(serverKey, "test"); err != nil {
		t.Fatalf("exact replay error = %v", err)
	}
	if len(owner.routes) != 1 {
		t.Fatalf("attached routes = %d, want 1", len(owner.routes))
	}
	if err := register(key.NewNode().Public().String(), "test"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("changed key replay error = %v", err)
	}
	if err := register(serverKey, "other"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("changed profile replay error = %v", err)
	}
}

func TestCoordinatorRejectsChangedTransportBeforeAssignment(t *testing.T) {
	coordinator, _ := newCoordinatorFixture(t)
	coordinator.RemoveOwner("local")
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := coordinator.Create(context.Background(), "owner", "route.example", "localhost:3000", routeToken)
	if err != nil {
		t.Fatal(err)
	}
	serverKey := key.NewNode().Public().String()
	if err := coordinator.RegisterTransport(
		context.Background(), created.Route.ID, 1, created.LeaseToken, serverKey, "test",
	); !errors.Is(err, ErrNoWorkerCapacity) {
		t.Fatalf("first registration error = %v", err)
	}
	if err := coordinator.RegisterTransport(
		context.Background(), created.Route.ID, 1, created.LeaseToken,
		key.NewNode().Public().String(), "test",
	); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("changed registration error = %v", err)
	}
}

func newCoordinatorFixture(t *testing.T) (*Coordinator, *fakeOwner) {
	t.Helper()
	db, err := state.Open(context.Background(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO principals (id, display_name, email, created_at)
		VALUES ('owner', 'Owner', '', 1)`); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(context.Background(), store, "boot")
	if err != nil {
		t.Fatal(err)
	}
	owner := &fakeOwner{limit: 2}
	if err := coordinator.AddOwner("local", owner); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = coordinator.Close()
		_ = db.Close()
	})
	return coordinator, owner
}

type fakeOwner struct {
	limit    int
	draining atomic.Bool
	closed   atomic.Bool
	routes   []*fakeOwnedRoute
}

func (o *fakeOwner) Attach(_ context.Context, assignment worker.Assignment) (worker.OwnedRoute, error) {
	if o.draining.Load() {
		return nil, worker.ErrDraining
	}
	route := &fakeOwnedRoute{ref: assignment.RouteRef}
	o.routes = append(o.routes, route)
	return route, nil
}

func (o *fakeOwner) Capacity() worker.Capacity {
	return worker.Capacity{Active: len(o.routes), Limit: o.limit, Draining: o.draining.Load()}
}

func (o *fakeOwner) Drain(context.Context) error {
	o.draining.Store(true)
	return nil
}

func (o *fakeOwner) Close() error {
	o.closed.Store(true)
	for _, route := range o.routes {
		_ = route.Close()
	}
	return nil
}

type fakeOwnedRoute struct {
	ref    worker.RouteRef
	closed atomic.Int32
}

func (*fakeOwnedRoute) Open(context.Context) (net.Conn, error) {
	local, remote := net.Pipe()
	_ = remote.Close()
	return local, nil
}

func (*fakeOwnedRoute) Drain(context.Context) error { return nil }

func (r *fakeOwnedRoute) Close() error {
	r.closed.Add(1)
	return nil
}
