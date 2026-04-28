package routes

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/state"
	"github.com/tnldotdev/tnl/internal/state/statedb"
)

func TestRouteLeaseLifecycle(t *testing.T) {
	db, err := state.Open(context.Background(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	now := time.Unix(1_700_000_000, 0).UTC()
	recorder := &testLifecycleRecorder{seen: make(map[string]struct{})}
	store, err := NewStore(db, "example", StoreConfig{LifecycleRecorder: recorder})
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }
	upsertTestPrincipal(t, context.Background(), queries, "owner", "Owner", now.Unix())
	upsertTestPrincipal(t, context.Background(), queries, "other", "Other", now.Unix())

	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimHostname(context.Background(), "owner", "route", "route-test"); err != nil {
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
	wantTransitions := []LifecycleTransition{
		LifecycleGenerationStarted,
		LifecycleReady,
		LifecycleDisconnected,
		LifecycleGenerationStarted,
		LifecycleDisconnected,
		LifecycleGenerationStarted,
		LifecycleDisconnected,
		LifecycleDeleted,
	}
	wantGenerations := []uint64{1, 1, 1, 2, 2, 3, 3, 3}
	if len(recorder.changes) != len(wantTransitions) {
		t.Fatalf("lifecycle changes = %#v", recorder.changes)
	}
	for index, change := range recorder.changes {
		if change.RouteID != created.Route.ID || change.Generation != wantGenerations[index] || change.Transition != wantTransitions[index] {
			t.Fatalf("lifecycle change %d = %#v", index, change)
		}
	}
}

func TestLifecycleFailureRollsBackRouteMutation(t *testing.T) {
	ctx := t.Context()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	upsertTestPrincipal(t, ctx, queries, "owner", "Owner", 1)
	recordErr := errors.New("record lifecycle")
	store, err := NewStore(db, "example", StoreConfig{LifecycleRecorder: failingLifecycleRecorder{err: recordErr}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimHostname(ctx, "owner", "route", "rollback-test"); err != nil {
		t.Fatal(err)
	}
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, "owner", "route.example", "localhost:3000", "boot", routeToken); !errors.Is(err, recordErr) {
		t.Fatalf("Create error = %v", err)
	}
	if routes, err := store.List(ctx, "owner"); err != nil || len(routes) != 0 {
		t.Fatalf("routes after rollback = %#v, %v", routes, err)
	}
}

func TestStoreObservesHealthOperationsExactlyOnce(t *testing.T) {
	type observation struct {
		operation StoreOperation
		duration  time.Duration
		err       error
	}
	var observations []observation
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	upsertTestPrincipal(t, ctx, queries, "owner", "Owner", 1)
	store, err := NewStore(db, "example", StoreConfig{
		ObserveOperation: func(operation StoreOperation, duration time.Duration, err error) {
			observations = append(observations, observation{operation: operation, duration: duration, err: err})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimHostname(ctx, "owner", "route", "observer-test"); err != nil {
		t.Fatal(err)
	}
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(ctx, "owner", "route.example", "localhost:3000", "boot", routeToken)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.AuthenticateLease(ctx, created.Route.ID, 1, created.LeaseToken, "boot")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterTransport(ctx, lease, "nodekey:server", "test"); err != nil {
		t.Fatal(err)
	}
	if err := store.Ready(ctx, lease); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Heartbeat(ctx, lease); err != nil {
		t.Fatal(err)
	}
	replacement, err := store.Acquire(ctx, "owner", created.Route.ID, "boot", routeToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Expire(ctx, replacement.Route.ID, replacement.Lease.Generation); err != nil {
		t.Fatal(err)
	}
	claims, err := store.ListHostnameClaims(ctx, "owner")
	if err != nil || len(claims) != 1 {
		t.Fatalf("claims = %#v, %v", claims, err)
	}
	if err := store.ReleaseHostnameClaim(ctx, "owner", claims[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthenticateLease(
		ctx, replacement.Route.ID, replacement.Lease.Generation, replacement.LeaseToken, "boot",
	); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("expired lease error = %v", err)
	}

	want := []StoreOperation{
		StoreOperationHostnameClaim,
		StoreOperationRouteCreate,
		StoreOperationLeaseAuthenticate,
		StoreOperationTransportRegister,
		StoreOperationRouteReady,
		StoreOperationLeaseHeartbeat,
		StoreOperationRouteAcquire,
		StoreOperationLeaseExpire,
		StoreOperationHostnameRelease,
		StoreOperationLeaseAuthenticate,
	}
	if len(observations) != len(want) {
		t.Fatalf("observations = %#v, want %d", observations, len(want))
	}
	for index, operation := range want {
		if observations[index].operation != operation {
			t.Fatalf("observation %d operation = %q, want %q", index, observations[index].operation, operation)
		}
		if observations[index].duration < 0 {
			t.Fatalf("observation %d duration = %v", index, observations[index].duration)
		}
		if index < len(want)-1 && observations[index].err != nil {
			t.Fatalf("observation %d error = %v", index, observations[index].err)
		}
	}
	if !errors.Is(observations[len(observations)-1].err, ErrStaleLease) {
		t.Fatalf("terminal observation error = %v", observations[len(observations)-1].err)
	}
}

type testLifecycleRecorder struct {
	changes []LifecycleChange
	seen    map[string]struct{}
}

func (r *testLifecycleRecorder) RecordLifecycle(_ context.Context, _ *statedb.Queries, change LifecycleChange) error {
	key := change.RouteID + "/" + string(change.Transition) + "/" + fmt.Sprint(change.Generation)
	if _, ok := r.seen[key]; ok {
		return nil
	}
	r.seen[key] = struct{}{}
	r.changes = append(r.changes, change)
	return nil
}

type failingLifecycleRecorder struct{ err error }

func (r failingLifecycleRecorder) RecordLifecycle(context.Context, *statedb.Queries, LifecycleChange) error {
	return r.err
}
