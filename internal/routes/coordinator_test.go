package routes

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/state"
	"github.com/tnldotdev/tnl/internal/state/statedb"
	"github.com/tnldotdev/tnl/internal/worker"
	"tailscale.com/types/key"
)

func TestCoordinatorPublishesOnlyReadyCurrentVersion(t *testing.T) {
	var removals []RouteRemovalReason
	coordinator, worker := newCoordinatorFixture(t, CoordinatorConfig{
		ObserveRouteRemoval: func(reason RouteRemovalReason) {
			removals = append(removals, reason)
		},
	})

	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := coordinator.Create(
		context.Background(), "worker", "route.example", "localhost:3000", routeToken,
		[]string{"192.0.2.0/24"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if created.WorkerPublicKey == "" {
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
		context.Background(), created.Route.ID, 1, created.SessionToken, serverKey, "test",
	); err != nil {
		t.Fatal(err)
	}
	if _, ok := coordinator.Lookup("route.example"); ok {
		t.Fatal("starting route was published")
	}
	if challenge, ok := coordinator.LookupChallenge("route.example"); !ok || challenge.Version != 1 {
		t.Fatalf("starting challenge route = %#v, %v", challenge, ok)
	}
	if err := coordinator.Ready(context.Background(), created.Route.ID, 1, created.SessionToken); err != nil {
		t.Fatal(err)
	}
	active, ok := coordinator.Lookup("route.example")
	if !ok || active.Version != 1 ||
		!slices.Equal(active.AllowedIPPrefixes, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}) {
		t.Fatalf("active route = %#v, %v", active, ok)
	}

	replacement, err := coordinator.CreateSession(
		context.Background(), "worker", created.Route.ID, routeToken, []string{"2001:db8::/64"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Session.Version != 2 {
		t.Fatalf("replacement version = %d", replacement.Session.Version)
	}
	if _, ok := coordinator.Lookup("route.example"); ok {
		t.Fatal("old version remained published")
	}
	if _, ok := coordinator.LookupChallenge("route.example"); ok {
		t.Fatal("old version remained challenge-routable")
	}
	if worker.routes[0].closed.Load() != 1 {
		t.Fatal("old version was not closed")
	}
	if !slices.Equal(removals, []RouteRemovalReason{RouteRemovalVersionReplaced}) {
		t.Fatalf("replacement removals = %v", removals)
	}
	if _, err := coordinator.Heartbeat(context.Background(), created.Route.ID, 1, created.SessionToken); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("stale heartbeat error = %v", err)
	}

	if err := coordinator.RegisterTransport(
		context.Background(), created.Route.ID, 2, replacement.SessionToken, serverKey, "test",
	); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Ready(context.Background(), created.Route.ID, 2, replacement.SessionToken); err != nil {
		t.Fatal(err)
	}
	active, ok = coordinator.Lookup("route.example")
	if !ok || active.Version != 2 ||
		!slices.Equal(active.AllowedIPPrefixes, []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")}) {
		t.Fatalf("replacement active route = %#v, %v", active, ok)
	}
	coordinator.RemoveWorker("local")
	if !slices.Equal(removals, []RouteRemovalReason{RouteRemovalVersionReplaced, RouteRemovalWorkerDisconnected}) {
		t.Fatalf("worker removals = %v", removals)
	}
	if _, ok := coordinator.Lookup("route.example"); ok {
		t.Fatal("route remained published after worker loss")
	}
	if _, ok := coordinator.LookupChallenge("route.example"); ok {
		t.Fatal("route remained challenge-routable after worker loss")
	}
	if _, err := coordinator.Heartbeat(context.Background(), created.Route.ID, 2, replacement.SessionToken); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("lost-worker heartbeat error = %v", err)
	}
}

func TestCoordinatorAdminSuspensionUnpublishesAndDrainsRoute(t *testing.T) {
	var removals []RouteRemovalReason
	coordinator, worker := newCoordinatorFixture(t, CoordinatorConfig{
		ObserveRouteRemoval: func(reason RouteRemovalReason) {
			removals = append(removals, reason)
		},
	})
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := coordinator.Create(t.Context(), "worker", "route.example", "localhost:3000", routeToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.RegisterTransport(
		t.Context(), created.Route.ID, 1, created.SessionToken, key.NewNode().Public().String(), "test",
	); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Ready(t.Context(), created.Route.ID, 1, created.SessionToken); err != nil {
		t.Fatal(err)
	}

	suspended, err := coordinator.SuspendAdminRoute(
		t.Context(), created.Route.ID, 1, "maintenance", "identity_local", "req_suspend",
	)
	if err != nil {
		t.Fatal(err)
	}
	if suspended.Status != "suspended" || suspended.SuspensionRevision != 1 {
		t.Fatalf("suspended route = %#v", suspended)
	}
	if _, ok := coordinator.Lookup("route.example"); ok {
		t.Fatal("suspended route remained published")
	}
	if _, ok := coordinator.LookupChallenge("route.example"); ok {
		t.Fatal("suspended route retained its certificate challenge")
	}
	if worker.routes[0].drained.Load() != 1 || worker.routes[0].closed.Load() != 1 {
		t.Fatalf("backend drained=%d closed=%d", worker.routes[0].drained.Load(), worker.routes[0].closed.Load())
	}
	if !slices.Equal(removals, []RouteRemovalReason{RouteRemovalSuspended}) {
		t.Fatalf("suspension removals = %v", removals)
	}
	if _, err := coordinator.Heartbeat(
		t.Context(), created.Route.ID, 1, created.SessionToken,
	); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("suspended heartbeat error = %v", err)
	}
	if provisioning, active := coordinator.Stats(); provisioning != 0 || active != 0 {
		t.Fatalf("stats after suspension = %d provisioning, %d active", provisioning, active)
	}

	resumed, err := coordinator.ResumeAdminRoute(
		t.Context(), created.Route.ID, 2, "identity_local", "req_resume",
	)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Status != "active" || resumed.Version != 2 {
		t.Fatalf("resumed route = %#v", resumed)
	}
	if _, ok := coordinator.Lookup("route.example"); ok {
		t.Fatal("resume restored a session without publisher acquisition")
	}
}

func TestCoordinatorExpiresUnrenewedSession(t *testing.T) {
	var removals []RouteRemovalReason
	coordinator, worker := newCoordinatorFixture(t, CoordinatorConfig{
		ObserveRouteRemoval: func(reason RouteRemovalReason) {
			removals = append(removals, reason)
		},
	})
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := coordinator.Create(context.Background(), "worker", "route.example", "localhost:3000", routeToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.RegisterTransport(
		context.Background(), created.Route.ID, 1, created.SessionToken,
		key.NewNode().Public().String(), "test",
	); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Ready(context.Background(), created.Route.ID, 1, created.SessionToken); err != nil {
		t.Fatal(err)
	}

	coordinator.expireDue(context.Background(), created.Session.ExpiresAt)
	if _, ok := coordinator.Lookup("route.example"); ok {
		t.Fatal("expired route remained published")
	}
	if worker.routes[0].closed.Load() != 1 {
		t.Fatal("expired route backend was not closed")
	}
	if !slices.Equal(removals, []RouteRemovalReason{RouteRemovalSessionExpired}) {
		t.Fatalf("expiry removals = %v", removals)
	}
	if provisioning, active := coordinator.Stats(); provisioning != 0 || active != 0 {
		t.Fatalf("stats after expiry = %d provisioning, %d active", provisioning, active)
	}
	if _, err := coordinator.Heartbeat(
		context.Background(), created.Route.ID, 1, created.SessionToken,
	); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("expired heartbeat error = %v", err)
	}
}

func TestCoordinatorReclaimsDurableRoute(t *testing.T) {
	coordinator, worker := newCoordinatorFixture(t)
	firstToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	first, err := coordinator.Create(context.Background(), "worker", "route.example", "localhost:3000", firstToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.RegisterTransport(
		context.Background(), first.Route.ID, 1, first.SessionToken, key.NewNode().Public().String(), "test",
	); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Ready(context.Background(), first.Route.ID, 1, first.SessionToken); err != nil {
		t.Fatal(err)
	}

	replacementToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := coordinator.Create(
		context.Background(), "worker", "route.example", "localhost:3001", replacementToken, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Route.ID != first.Route.ID || replacement.Route.Version != 2 {
		t.Fatalf("replacement = %#v", replacement)
	}
	if _, ok := coordinator.Lookup("route.example"); ok {
		t.Fatal("replaced version remained published")
	}
	if worker.routes[0].closed.Load() != 1 {
		t.Fatal("replaced version backend was not closed")
	}
	if _, err := coordinator.CreateSession(context.Background(), "worker", first.Route.ID, firstToken, nil); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("rotated route token error = %v", err)
	}
}

func TestCoordinatorAcceptsOnlyExactTransportReplay(t *testing.T) {
	coordinator, worker := newCoordinatorFixture(t)
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := coordinator.Create(context.Background(), "worker", "route.example", "localhost:3000", routeToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	serverKey := key.NewNode().Public().String()
	register := func(key, profile string) error {
		return coordinator.RegisterTransport(
			context.Background(), created.Route.ID, 1, created.SessionToken, key, profile,
		)
	}
	if err := register(serverKey, "test"); err != nil {
		t.Fatal(err)
	}
	if err := register(serverKey, "test"); err != nil {
		t.Fatalf("exact replay error = %v", err)
	}
	if len(worker.routes) != 1 {
		t.Fatalf("attached routes = %d, want 1", len(worker.routes))
	}
	if err := register(key.NewNode().Public().String(), "test"); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("changed key replay error = %v", err)
	}
	if err := register(serverKey, "other"); !errors.Is(err, ErrInvalidStatus) {
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
	coordinator.RemoveWorker("local")
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := coordinator.Create(context.Background(), "worker", "route.example", "localhost:3000", routeToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	serverKey := key.NewNode().Public().String()
	if err := coordinator.RegisterTransport(
		context.Background(), created.Route.ID, 1, created.SessionToken, serverKey, "test",
	); !errors.Is(err, ErrNoWorkerCapacity) {
		t.Fatalf("first registration error = %v", err)
	}
	if capacityRejections != 1 {
		t.Fatalf("capacity rejections = %d, want 1", capacityRejections)
	}
	if err := coordinator.RegisterTransport(
		context.Background(), created.Route.ID, 1, created.SessionToken,
		key.NewNode().Public().String(), "test",
	); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("changed registration error = %v", err)
	}
	if capacityRejections != 1 {
		t.Fatalf("capacity rejections after invalid replay = %d, want 1", capacityRejections)
	}
}

func TestCoordinatorReleaseDeactivatesRoute(t *testing.T) {
	var removals []RouteRemovalReason
	coordinator, worker := newCoordinatorFixture(t, CoordinatorConfig{
		ObserveRouteRemoval: func(reason RouteRemovalReason) {
			removals = append(removals, reason)
		},
	})
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := coordinator.Create(context.Background(), "worker", "route.example", "localhost:3000", routeToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.RegisterTransport(
		context.Background(), created.Route.ID, 1, created.SessionToken,
		key.NewNode().Public().String(), "test",
	); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Ready(context.Background(), created.Route.ID, 1, created.SessionToken); err != nil {
		t.Fatal(err)
	}
	hostnames, err := coordinator.ListHostnames(context.Background(), "worker")
	if err != nil || len(hostnames) != 1 {
		t.Fatalf("hostnames = %#v, %v", hostnames, err)
	}
	if err := coordinator.RemoveHostname(context.Background(), "worker", hostnames[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := coordinator.Lookup("route.example"); ok {
		t.Fatal("removed route remained published")
	}
	if worker.routes[0].closed.Load() != 1 {
		t.Fatal("removed route was not closed")
	}
	if !slices.Equal(removals, []RouteRemovalReason{RouteRemovalHostnameRemoved}) {
		t.Fatalf("removal reasons = %v", removals)
	}
	if _, err := coordinator.Heartbeat(context.Background(), created.Route.ID, 1, created.SessionToken); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("removed session error = %v", err)
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
	created, err := coordinator.Create(context.Background(), "worker", "route.example", "localhost:3000", routeToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Heartbeat(context.Background(), created.Route.ID, 1, created.SessionToken); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Heartbeat(
		context.Background(), created.Route.ID, 1, credentials.SessionToken("invalid"),
	); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("rejected heartbeat error = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := coordinator.Heartbeat(canceled, created.Route.ID, 1, created.SessionToken); !errors.Is(err, context.Canceled) {
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
	created, err := coordinator.Create(context.Background(), "worker", "route.example", "localhost:3000", routeToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.RegisterTransport(
		context.Background(), created.Route.ID, 1, created.SessionToken,
		key.NewNode().Public().String(), "test",
	); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Ready(context.Background(), created.Route.ID, 1, created.SessionToken); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Heartbeat(context.Background(), created.Route.ID, 1, created.SessionToken); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []CoordinatorStage{
		CoordinatorStageTransportRouteLockWait,
		CoordinatorStageTransportWorkerAttach,
		CoordinatorStageReadyRouteLockWait,
		CoordinatorStageReadyPublish,
		CoordinatorStageHeartbeatRouteLockWait,
		CoordinatorStageHeartbeatPersistence,
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
		remove func(context.Context, *Coordinator, SessionSetup) error
	}{
		{
			name:   "deleted",
			reason: RouteRemovalDeleted,
			remove: func(ctx context.Context, coordinator *Coordinator, created SessionSetup) error {
				return coordinator.Delete(ctx, "worker", created.Route.ID)
			},
		},
		{
			name:   "worker draining",
			reason: RouteRemovalWorkerDraining,
			remove: func(ctx context.Context, coordinator *Coordinator, _ SessionSetup) error {
				return coordinator.DrainWorker(ctx, "local")
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
			created, err := coordinator.Create(context.Background(), "worker", "route.example", "localhost:3000", routeToken, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := coordinator.RegisterTransport(
				context.Background(), created.Route.ID, 1, created.SessionToken,
				key.NewNode().Public().String(), "test",
			); err != nil {
				t.Fatal(err)
			}
			if err := coordinator.Ready(context.Background(), created.Route.ID, 1, created.SessionToken); err != nil {
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
	created, err := coordinator.Create(context.Background(), "worker", "route.example", "localhost:3000", routeToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	stats := coordinator.HealthStats()
	if stats.Provisioning != 1 || stats.Active != 0 || stats.ConnectedWorkers != 1 ||
		stats.MinimumProvisioningSessionSeconds != SessionLifetime.Seconds() || stats.MinimumActiveSessionSeconds != 0 {
		t.Fatalf("provisioning health stats = %#v", stats)
	}
	if err := coordinator.RegisterTransport(
		context.Background(), created.Route.ID, 1, created.SessionToken,
		key.NewNode().Public().String(), "test",
	); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Ready(context.Background(), created.Route.ID, 1, created.SessionToken); err != nil {
		t.Fatal(err)
	}
	now = now.Add(10 * time.Second)
	stats = coordinator.HealthStats()
	if stats.Provisioning != 0 || stats.Active != 1 || stats.ConnectedWorkers != 1 ||
		stats.MinimumProvisioningSessionSeconds != 0 || stats.MinimumActiveSessionSeconds != 35 {
		t.Fatalf("active health stats = %#v", stats)
	}
}

func newCoordinatorFixture(t *testing.T, configs ...CoordinatorConfig) (*Coordinator, *fakeWorker) {
	t.Helper()
	db, err := state.Open(context.Background(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	queries := statedb.New(db)
	upsertTestIdentity(t, context.Background(), queries, "worker", "Owner", 1)
	store, err := NewStore(db, "example")
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(context.Background(), store, "instance", configs...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.AddManagedHostname(context.Background(), "worker", "route", "coordinator-test"); err != nil {
		t.Fatal(err)
	}
	worker := &fakeWorker{limit: 2}
	if err := coordinator.AddWorker("local", worker); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = coordinator.Close()
		_ = db.Close()
	})
	return coordinator, worker
}

type fakeWorker struct {
	limit    int
	draining atomic.Bool
	closed   atomic.Bool
	routes   []*fakeWorkerRoute
}

func (o *fakeWorker) Attach(_ context.Context, assignment worker.Assignment) (worker.WorkerRoute, error) {
	if o.draining.Load() {
		return nil, worker.ErrDraining
	}
	route := &fakeWorkerRoute{ref: assignment.RouteRef}
	o.routes = append(o.routes, route)
	return route, nil
}

func (o *fakeWorker) Capacity() worker.Capacity {
	return worker.Capacity{Active: len(o.routes), Limit: o.limit, Draining: o.draining.Load()}
}

func (o *fakeWorker) Drain(context.Context) error {
	o.draining.Store(true)
	return nil
}

func (o *fakeWorker) Close() error {
	o.closed.Store(true)
	for _, route := range o.routes {
		_ = route.Close()
	}
	return nil
}

type fakeWorkerRoute struct {
	ref     worker.RouteRef
	drained atomic.Int32
	closed  atomic.Int32
}

func (*fakeWorkerRoute) Open(context.Context) (net.Conn, error) {
	local, remote := net.Pipe()
	_ = remote.Close()
	return local, nil
}

func (r *fakeWorkerRoute) Drain(context.Context) error {
	r.drained.Add(1)
	return nil
}

func (r *fakeWorkerRoute) Close() error {
	r.closed.Add(1)
	return nil
}
