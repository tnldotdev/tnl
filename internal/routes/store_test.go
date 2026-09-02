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

func TestRouteSessionLifecycle(t *testing.T) {
	db, err := state.Open(context.Background(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	now := time.Unix(0, 1_700_000_000).UTC()
	recorder := &testLifecycleRecorder{seen: make(map[string]struct{})}
	store, err := NewStore(db, "example", StoreConfig{LifecycleRecorder: recorder})
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }
	upsertTestIdentity(t, context.Background(), queries, "owner", "Owner", now.UnixNano())
	upsertTestIdentity(t, context.Background(), queries, "other", "Other", now.UnixNano())

	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddManagedHostname(context.Background(), "owner", "route", "route-test"); err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(context.Background(), "owner", "Route.Example.", "localhost:3000", "instance-1", routeToken)
	if err != nil {
		t.Fatal(err)
	}
	if created.Route.Hostname != "route.example" || created.Route.Version != 1 {
		t.Fatalf("created route = %#v", created.Route)
	}
	otherToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(context.Background(), "other", "route.example", "localhost:3001", "instance-1", otherToken); !errors.Is(err, ErrNameUnavailable) {
		t.Fatalf("competing hostname error = %v", err)
	}
	session, err := store.AuthenticateSession(context.Background(), created.Route.ID, 1, created.SessionToken, "instance-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterTransport(context.Background(), session, "nodekey:server", "test"); err != nil {
		t.Fatal(err)
	}
	session, err = store.AuthenticateSession(context.Background(), created.Route.ID, 1, created.SessionToken, "instance-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Ready(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	now = now.Add(15 * time.Second)
	if expiresAt, err := store.Heartbeat(context.Background(), session); err != nil || !expiresAt.Equal(now.Add(SessionLifetime)) {
		t.Fatalf("heartbeat = %v, %v", expiresAt, err)
	}

	replacement, err := store.CreateSession(context.Background(), "owner", created.Route.ID, "instance-1", routeToken)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Route.Version != 2 || replacement.Session.Version != 2 {
		t.Fatalf("replacement = %#v", replacement)
	}
	if _, err := store.AuthenticateSession(context.Background(), created.Route.ID, 1, created.SessionToken, "instance-1"); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("stale session error = %v", err)
	}
	if _, err := store.CreateSession(context.Background(), "owner", created.Route.ID, "instance-1", credentials.RouteToken(replacement.SessionToken)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("wrong-class session error = %v", err)
	}
	restartedToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := store.Create(
		context.Background(), "owner", "route.example", "localhost:3001", "instance-1", restartedToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Route.ID != created.Route.ID || restarted.Route.Version != 3 || restarted.Route.LocalTarget != "localhost:3001" {
		t.Fatalf("restarted route = %#v", restarted.Route)
	}
	if _, err := store.CreateSession(context.Background(), "owner", created.Route.ID, "instance-1", routeToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("rotated route token error = %v", err)
	}
	if _, err := store.AuthenticateSession(context.Background(), created.Route.ID, 2, replacement.SessionToken, "instance-1"); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("replaced session error = %v", err)
	}

	if err := store.InvalidateOtherServerInstances(context.Background(), "instance-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthenticateSession(context.Background(), created.Route.ID, 3, restarted.SessionToken, "instance-2"); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("old server instance session error = %v", err)
	}
	routes, err := store.List(context.Background(), "owner")
	if err != nil || len(routes) != 1 || routes[0].LocalTarget != "localhost:3001" {
		t.Fatalf("list = %#v, %v", routes, err)
	}
	if err := store.Delete(context.Background(), "owner", created.Route.ID); err != nil {
		t.Fatal(err)
	}
	if routes, err := store.List(context.Background(), "owner"); err != nil || len(routes) != 0 {
		t.Fatalf("list after delete = %#v, %v", routes, err)
	}
	wantTransitions := []LifecycleTransition{
		LifecycleVersionStarted,
		LifecycleReady,
		LifecycleDisconnected,
		LifecycleVersionStarted,
		LifecycleDisconnected,
		LifecycleVersionStarted,
		LifecycleDisconnected,
		LifecycleDeleted,
	}
	wantVersions := []uint64{1, 1, 1, 2, 2, 3, 3, 3}
	if len(recorder.changes) != len(wantTransitions) {
		t.Fatalf("lifecycle changes = %#v", recorder.changes)
	}
	for index, change := range recorder.changes {
		if change.RouteID != created.Route.ID || change.Version != wantVersions[index] || change.Transition != wantTransitions[index] {
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
	upsertTestIdentity(t, ctx, queries, "owner", "Owner", 1)
	recordErr := errors.New("record lifecycle")
	store, err := NewStore(db, "example", StoreConfig{LifecycleRecorder: failingLifecycleRecorder{err: recordErr}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddManagedHostname(ctx, "owner", "route", "rollback-test"); err != nil {
		t.Fatal(err)
	}
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, "owner", "route.example", "localhost:3000", "instance", routeToken); !errors.Is(err, recordErr) {
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
	upsertTestIdentity(t, ctx, queries, "owner", "Owner", 1)
	store, err := NewStore(db, "example", StoreConfig{
		ObserveOperation: func(operation StoreOperation, duration time.Duration, err error) {
			observations = append(observations, observation{operation: operation, duration: duration, err: err})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddManagedHostname(ctx, "owner", "route", "observer-test"); err != nil {
		t.Fatal(err)
	}
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(ctx, "owner", "route.example", "localhost:3000", "instance", routeToken)
	if err != nil {
		t.Fatal(err)
	}
	session, err := store.AuthenticateSession(ctx, created.Route.ID, 1, created.SessionToken, "instance")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterTransport(ctx, session, "nodekey:server", "test"); err != nil {
		t.Fatal(err)
	}
	if err := store.Ready(ctx, session); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Heartbeat(ctx, session); err != nil {
		t.Fatal(err)
	}
	replacement, err := store.CreateSession(ctx, "owner", created.Route.ID, "instance", routeToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Expire(ctx, replacement.Route.ID, replacement.Session.Version); err != nil {
		t.Fatal(err)
	}
	hostnames, err := store.ListHostnames(ctx, "owner")
	if err != nil || len(hostnames) != 1 {
		t.Fatalf("hostnames = %#v, %v", hostnames, err)
	}
	if err := store.RemoveHostname(ctx, "owner", hostnames[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthenticateSession(
		ctx, replacement.Route.ID, replacement.Session.Version, replacement.SessionToken, "instance",
	); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("expired session error = %v", err)
	}

	want := []StoreOperation{
		StoreOperationHostname,
		StoreOperationRouteCreate,
		StoreOperationSessionAuthenticate,
		StoreOperationTransportRegister,
		StoreOperationRouteReady,
		StoreOperationSessionHeartbeat,
		StoreOperationSessionCreate,
		StoreOperationSessionExpire,
		StoreOperationHostnameRemove,
		StoreOperationSessionAuthenticate,
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
	if !errors.Is(observations[len(observations)-1].err, ErrStaleSession) {
		t.Fatalf("terminal observation error = %v", observations[len(observations)-1].err)
	}
}

type testLifecycleRecorder struct {
	changes []LifecycleChange
	seen    map[string]struct{}
}

func (r *testLifecycleRecorder) RecordLifecycle(_ context.Context, _ *statedb.Queries, change LifecycleChange) error {
	key := change.RouteID + "/" + string(change.Transition) + "/" + fmt.Sprint(change.Version)
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
