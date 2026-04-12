package routes

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/internal/state"
	"github.com/0xcadams/tnl/internal/worker"
	"tailscale.com/types/key"
)

func TestCoordinatorPublishesOnlyReadyCurrentGeneration(t *testing.T) {
	var removals []RouteRemovalReason
	coordinator, owner := newCoordinatorFixture(t, CoordinatorConfig{
		ObserveRouteRemoval: func(reason RouteRemovalReason) {
			removals = append(removals, reason)
		},
	})

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
	if !slices.Equal(removals, []RouteRemovalReason{RouteRemovalReplaced}) {
		t.Fatalf("replacement removals = %v", removals)
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
	if !slices.Equal(removals, []RouteRemovalReason{RouteRemovalReplaced, RouteRemovalOwnerDisconnected}) {
		t.Fatalf("owner removals = %v", removals)
	}
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
	var removals []RouteRemovalReason
	coordinator, owner := newCoordinatorFixture(t, CoordinatorConfig{
		ObserveRouteRemoval: func(reason RouteRemovalReason) {
			removals = append(removals, reason)
		},
	})
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
	if !slices.Equal(removals, []RouteRemovalReason{RouteRemovalLeaseExpired}) {
		t.Fatalf("expiry removals = %v", removals)
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

func TestCoordinatorRouteLocksArePerRoute(t *testing.T) {
	coordinator, _ := newCoordinatorFixture(t)
	unlockFirst := coordinator.lockRoute("first")

	second := make(chan func(), 1)
	go func() { second <- coordinator.lockRoute("second") }()
	select {
	case unlockSecond := <-second:
		unlockSecond()
	case <-time.After(time.Second):
		unlockFirst()
		t.Fatal("different route shared lock")
	}

	same := make(chan func(), 1)
	go func() { same <- coordinator.lockRoute("first") }()
	select {
	case unlockSame := <-same:
		unlockSame()
		unlockFirst()
		t.Fatal("same route acquired lock twice")
	case <-time.After(25 * time.Millisecond):
	}
	unlockFirst()
	select {
	case unlockSame := <-same:
		unlockSame()
	case <-time.After(time.Second):
		t.Fatal("same route lock was not released")
	}
}

func TestCoordinatorRejectsChangedTransportBeforeAssignment(t *testing.T) {
	capacityRejections := 0
	coordinator, _ := newCoordinatorFixture(t, CoordinatorConfig{
		ObserveWorkerCapacityRejection: func() {
			capacityRejections++
		},
	})
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
	if capacityRejections != 1 {
		t.Fatalf("capacity rejections = %d, want 1", capacityRejections)
	}
	if err := coordinator.RegisterTransport(
		context.Background(), created.Route.ID, 1, created.LeaseToken,
		key.NewNode().Public().String(), "test",
	); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("changed registration error = %v", err)
	}
	if capacityRejections != 1 {
		t.Fatalf("capacity rejections after invalid replay = %d, want 1", capacityRejections)
	}
}

func TestCoordinatorReleaseDeactivatesRoute(t *testing.T) {
	var removals []RouteRemovalReason
	coordinator, owner := newCoordinatorFixture(t, CoordinatorConfig{
		ObserveRouteRemoval: func(reason RouteRemovalReason) {
			removals = append(removals, reason)
		},
	})
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
	claims, err := coordinator.ListHostnameClaims(context.Background(), "owner")
	if err != nil || len(claims) != 1 {
		t.Fatalf("claims = %#v, %v", claims, err)
	}
	if err := coordinator.ReleaseHostnameClaim(context.Background(), "owner", claims[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := coordinator.Lookup("route.example"); ok {
		t.Fatal("released route remained published")
	}
	if owner.routes[0].closed.Load() != 1 {
		t.Fatal("released route was not closed")
	}
	if !slices.Equal(removals, []RouteRemovalReason{RouteRemovalClaimReleased}) {
		t.Fatalf("release removals = %v", removals)
	}
	if _, err := coordinator.Heartbeat(context.Background(), created.Route.ID, 1, created.LeaseToken); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("released lease error = %v", err)
	}
}

func TestCoordinatorObservesHeartbeatResults(t *testing.T) {
	var coordinator *Coordinator
	var results []HeartbeatResult
	coordinator, _ = newCoordinatorFixture(t, CoordinatorConfig{
		ObserveHeartbeat: func(result HeartbeatResult) {
			_ = coordinator.HealthStats()
			results = append(results, result)
		},
	})
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := coordinator.Create(context.Background(), "owner", "route.example", "localhost:3000", routeToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Heartbeat(context.Background(), created.Route.ID, 1, created.LeaseToken); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Heartbeat(
		context.Background(), created.Route.ID, 1, credentials.LeaseToken("invalid"),
	); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("rejected heartbeat error = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := coordinator.Heartbeat(canceled, created.Route.ID, 1, created.LeaseToken); !errors.Is(err, context.Canceled) {
		t.Fatalf("failed heartbeat error = %v", err)
	}
	want := []HeartbeatResult{HeartbeatResultSuccess, HeartbeatResultRejected, HeartbeatResultError}
	if !slices.Equal(results, want) {
		t.Fatalf("heartbeat results = %v, want %v", results, want)
	}
}

func TestCoordinatorObservesStages(t *testing.T) {
	observed := make(map[CoordinatorStage]int)
	coordinator, _ := newCoordinatorFixture(t, CoordinatorConfig{
		ObserveStage: func(stage CoordinatorStage, duration time.Duration) {
			if duration < 0 {
				t.Errorf("stage %q duration = %v", stage, duration)
			}
			observed[stage]++
		},
	})
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
	if _, err := coordinator.Heartbeat(context.Background(), created.Route.ID, 1, created.LeaseToken); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []CoordinatorStage{
		CoordinatorStageTransportRouteLockWait,
		CoordinatorStageTransportWorkerAttach,
		CoordinatorStageReadyRouteLockWait,
		CoordinatorStageReadyPublish,
		CoordinatorStageHeartbeatRouteLockWait,
		CoordinatorStageHeartbeatStateUpdate,
	} {
		if observed[stage] != 1 {
			t.Errorf("stage %q observations = %d, want 1", stage, observed[stage])
		}
	}
}

func TestCoordinatorObservesDeletedAndDrainingRemovals(t *testing.T) {
	for _, test := range []struct {
		name   string
		reason RouteRemovalReason
		remove func(context.Context, *Coordinator, LeaseSetup) error
	}{
		{
			name:   "deleted",
			reason: RouteRemovalDeleted,
			remove: func(ctx context.Context, coordinator *Coordinator, created LeaseSetup) error {
				return coordinator.Delete(ctx, "owner", created.Route.ID)
			},
		},
		{
			name:   "owner draining",
			reason: RouteRemovalOwnerDraining,
			remove: func(ctx context.Context, coordinator *Coordinator, _ LeaseSetup) error {
				return coordinator.DrainOwner(ctx, "local")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var coordinator *Coordinator
			var removals []RouteRemovalReason
			coordinator, _ = newCoordinatorFixture(t, CoordinatorConfig{
				ObserveRouteRemoval: func(reason RouteRemovalReason) {
					_ = coordinator.HealthStats()
					removals = append(removals, reason)
				},
			})
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
			if err := test.remove(context.Background(), coordinator, created); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(removals, []RouteRemovalReason{test.reason}) {
				t.Fatalf("removals = %v, want %q", removals, test.reason)
			}
		})
	}
}

func TestCoordinatorHealthStats(t *testing.T) {
	coordinator, _ := newCoordinatorFixture(t)
	now := time.Now().Add(time.Hour).Truncate(time.Second)
	coordinator.store.now = func() time.Time { return now }
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := coordinator.Create(context.Background(), "owner", "route.example", "localhost:3000", routeToken)
	if err != nil {
		t.Fatal(err)
	}
	stats := coordinator.HealthStats()
	if stats.Provisioning != 1 || stats.Active != 0 || stats.ConnectedOwners != 1 ||
		stats.MinimumProvisioningLeaseSeconds != LeaseLifetime.Seconds() || stats.MinimumActiveLeaseSeconds != 0 {
		t.Fatalf("provisioning health stats = %#v", stats)
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
	now = now.Add(10 * time.Second)
	stats = coordinator.HealthStats()
	if stats.Provisioning != 0 || stats.Active != 1 || stats.ConnectedOwners != 1 ||
		stats.MinimumProvisioningLeaseSeconds != 0 || stats.MinimumActiveLeaseSeconds != 35 {
		t.Fatalf("active health stats = %#v", stats)
	}
}

func newCoordinatorFixture(t *testing.T, configs ...CoordinatorConfig) (*Coordinator, *fakeOwner) {
	t.Helper()
	db, err := state.Open(context.Background(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO principals (id, display_name, email, created_at)
		VALUES ('owner', 'Owner', '', 1)`); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(db, "example")
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(context.Background(), store, "boot", configs...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.ClaimHostname(context.Background(), "owner", "route", "coordinator-test"); err != nil {
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
