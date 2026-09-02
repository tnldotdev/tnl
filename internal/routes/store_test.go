package routes

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
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
	if _, err := store.ClaimManagedHostname(context.Background(), "owner", "route", "route-test"); err != nil {
		t.Fatal(err)
	}
	createdPolicy := []string{"192.0.2.0/24"}
	created, err := store.Create(
		context.Background(), "owner", "Route.Example.", "localhost:3000", "instance-1", routeToken, createdPolicy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if created.Route.Hostname != "route.example" || created.Route.RouteVersion != 1 {
		t.Fatalf("created route = %#v", created.Route)
	}
	otherToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(context.Background(), "other", "route.example", "localhost:3001", "instance-1", otherToken, nil); !errors.Is(err, ErrNameUnavailable) {
		t.Fatalf("competing hostname error = %v", err)
	}
	session, err := store.AuthenticateSession(context.Background(), created.Route.ID, 1, created.SessionToken, "instance-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AttachRouteTransport(context.Background(), session, "nodekey:server", "test"); err != nil {
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

	replacementPolicy := []string{"2001:db8::/64"}
	replacement, err := store.CreateSession(
		context.Background(), "owner", created.Route.ID, "instance-1", routeToken, replacementPolicy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Route.RouteVersion != 2 || replacement.Session.RouteVersion != 2 {
		t.Fatalf("replacement = %#v", replacement)
	}
	if !slices.Equal(created.Route.AllowedIPPrefixes, createdPolicy) ||
		!slices.Equal(replacement.Route.AllowedIPPrefixes, replacementPolicy) {
		t.Fatalf("route policies = %#v, %#v", created.Route.AllowedIPPrefixes, replacement.Route.AllowedIPPrefixes)
	}
	if _, err := store.AuthenticateSession(context.Background(), created.Route.ID, 1, created.SessionToken, "instance-1"); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("stale session error = %v", err)
	}
	if _, err := store.CreateSession(context.Background(), "owner", created.Route.ID, "instance-1", credentials.RouteToken(replacement.SessionToken), nil); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("wrong-class session error = %v", err)
	}
	restartedToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := store.Create(
		context.Background(), "owner", "route.example", "localhost:3001", "instance-1", restartedToken, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Route.ID != created.Route.ID || restarted.Route.RouteVersion != 3 || restarted.Route.LocalTarget != "localhost:3001" {
		t.Fatalf("restarted route = %#v", restarted.Route)
	}
	for routeVersion, want := range map[int64][]string{1: createdPolicy, 2: replacementPolicy, 3: {}} {
		stored, err := queries.ListRouteAllowedIPPrefixesForTesting(
			context.Background(), statedb.ListRouteAllowedIPPrefixesForTestingParams{
				RouteID: created.Route.ID, RouteVersion: routeVersion,
			},
		)
		if err != nil || !slices.Equal(stored, want) {
			t.Fatalf("route version %d policy = %#v, %v; want %#v", routeVersion, stored, err, want)
		}
	}
	if _, err := store.CreateSession(context.Background(), "owner", created.Route.ID, "instance-1", routeToken, nil); !errors.Is(err, ErrUnauthenticated) {
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
		LifecycleRouteVersionStarted,
		LifecycleReady,
		LifecycleDisconnected,
		LifecycleRouteVersionStarted,
		LifecycleDisconnected,
		LifecycleRouteVersionStarted,
		LifecycleDisconnected,
		LifecycleDeleted,
	}
	wantVersions := []uint64{1, 1, 1, 2, 2, 3, 3, 3}
	if len(recorder.changes) != len(wantTransitions) {
		t.Fatalf("lifecycle changes = %#v", recorder.changes)
	}
	for index, change := range recorder.changes {
		if change.RouteID != created.Route.ID || change.RouteVersion != wantVersions[index] || change.Transition != wantTransitions[index] {
			t.Fatalf("lifecycle change %d = %#v", index, change)
		}
	}
	if len(recorder.registrations) != 0 {
		t.Fatalf("local route registrations = %#v, want none", recorder.registrations)
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
	if _, err := store.ClaimManagedHostname(ctx, "owner", "route", "rollback-test"); err != nil {
		t.Fatal(err)
	}
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, "owner", "route.example", "localhost:3000", "instance", routeToken, nil); !errors.Is(err, recordErr) {
		t.Fatalf("Create error = %v", err)
	}
	if routes, err := store.List(ctx, "owner"); err != nil || len(routes) != 0 {
		t.Fatalf("routes after rollback = %#v, %v", routes, err)
	}
}

func TestAdminRouteSuspensionFencesSessionsAndRequiresMonotonicRevision(t *testing.T) {
	ctx := t.Context()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	now := time.Unix(1_700_000_000, 0).UTC()
	store, err := NewStore(db, "example", StoreConfig{})
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }
	upsertTestIdentity(t, ctx, queries, "owner", "Owner", now.UnixNano())
	if _, err := store.ClaimManagedHostname(ctx, "owner", "route", "admin-suspension"); err != nil {
		t.Fatal(err)
	}
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(ctx, "owner", "route.example", "localhost:3000", "instance", routeToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	suspended, err := store.SuspendAdminRoute(ctx, created.Route.ID, 1, "maintenance", "identity_local", "req_suspend")
	if err != nil {
		t.Fatal(err)
	}
	if suspended.Status != RouteStatusSuspended || suspended.SuspensionRevision != 1 ||
		suspended.SuspensionReason != "maintenance" || !suspended.SuspendedAt.Equal(now) {
		t.Fatalf("suspended route = %#v", suspended)
	}
	if _, err := store.AuthenticateSession(
		ctx, created.Route.ID, created.Route.RouteVersion, created.SessionToken, "instance",
	); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("suspended session error = %v", err)
	}
	if _, err := store.CreateSession(ctx, "owner", created.Route.ID, "instance", routeToken, nil); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("suspended route session error = %v", err)
	}
	if _, err := store.SuspendAdminRoute(
		ctx, created.Route.ID, 1, "retry", "identity_local", "req_retry",
	); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("duplicate suspension error = %v", err)
	}
	if _, err := store.ResumeAdminRoute(
		ctx, created.Route.ID, 1, "identity_local", "req_stale",
	); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("stale resume error = %v", err)
	}
	resumed, err := store.ResumeAdminRoute(ctx, created.Route.ID, 2, "identity_local", "req_resume")
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Status != RouteStatusEnabled || resumed.RouteVersion != 2 || resumed.SuspensionRevision != 2 || !resumed.SuspendedAt.IsZero() {
		t.Fatalf("resumed route = %#v", resumed)
	}
	if _, err := store.AuthenticateSession(
		ctx, created.Route.ID, created.Route.RouteVersion, created.SessionToken, "instance",
	); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("old session after resume error = %v", err)
	}
	replacement, err := store.CreateSession(ctx, "owner", created.Route.ID, "instance", routeToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Route.RouteVersion != 3 || replacement.Session.RouteVersion != 3 {
		t.Fatalf("replacement after resume = %#v", replacement)
	}
	if count, err := queries.CountAdminAuditEvents(ctx); err != nil || count != 2 {
		t.Fatalf("audit event count = %d, %v", count, err)
	}
}

func TestAdminRemovesQuarantinedHostnameWithSuspendedRoute(t *testing.T) {
	ctx := t.Context()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	now := time.Unix(1_700_000_000, 0).UTC()
	store, err := NewStore(db, "example", StoreConfig{})
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }
	upsertTestIdentity(t, ctx, queries, "owner", "Owner", now.UnixNano())
	hostname, err := store.ClaimManagedHostname(ctx, "owner", "route", "admin-hostname")
	if err != nil {
		t.Fatal(err)
	}
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(ctx, "owner", "route.example", "localhost:3000", "instance", routeToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SuspendAdminRoute(
		ctx, created.Route.ID, 1, "route maintenance", "identity_local", "req_suspend",
	); err != nil {
		t.Fatal(err)
	}
	routeIDs, err := store.QuarantineAdminHostname(
		ctx, hostname.ID, "hostname review", "identity_local", "req_quarantine",
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(routeIDs) != 1 || routeIDs[0] != created.Route.ID {
		t.Fatalf("quarantined route IDs = %#v", routeIDs)
	}
	quarantined, err := store.GetAdminHostname(ctx, hostname.ID)
	if err != nil {
		t.Fatal(err)
	}
	if quarantined.Status != HostnameStatusQuarantined || quarantined.QuarantineReason != "hostname review" {
		t.Fatalf("quarantined hostname = %#v", quarantined)
	}
	if _, err := store.ResumeAdminRoute(
		ctx, created.Route.ID, 2, "identity_local", "req_blocked_resume",
	); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("quarantined hostname resume error = %v", err)
	}
	if _, err := store.RemoveAdminHostname(ctx, hostname.ID, "identity_local", "req_remove"); err != nil {
		t.Fatal(err)
	}
	removedRoute, err := store.GetAdminRoute(ctx, created.Route.ID)
	if err != nil {
		t.Fatal(err)
	}
	if removedRoute.Status != RouteStatusDeleted || !removedRoute.SuspendedAt.IsZero() {
		t.Fatalf("removed route = %#v", removedRoute)
	}
	removedHostname, err := store.GetAdminHostname(ctx, hostname.ID)
	if err != nil {
		t.Fatal(err)
	}
	if removedHostname.Status != HostnameStatusInactive || removedHostname.QuarantineReason != "" ||
		!removedHostname.QuarantinedAt.IsZero() {
		t.Fatalf("removed hostname = %#v", removedHostname)
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
	if _, err := store.ClaimManagedHostname(ctx, "owner", "route", "observer-test"); err != nil {
		t.Fatal(err)
	}
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(ctx, "owner", "route.example", "localhost:3000", "instance", routeToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	session, err := store.AuthenticateSession(ctx, created.Route.ID, 1, created.SessionToken, "instance")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AttachRouteTransport(ctx, session, "nodekey:server", "test"); err != nil {
		t.Fatal(err)
	}
	if err := store.Ready(ctx, session); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Heartbeat(ctx, session); err != nil {
		t.Fatal(err)
	}
	replacement, err := store.CreateSession(ctx, "owner", created.Route.ID, "instance", routeToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Expire(ctx, replacement.Route.ID, replacement.Session.RouteVersion); err != nil {
		t.Fatal(err)
	}
	hostnames, err := store.ListHostnames(ctx, "owner")
	if err != nil || len(hostnames) != 1 {
		t.Fatalf("hostnames = %#v, %v", hostnames, err)
	}
	if err := store.ReleaseHostname(ctx, "owner", hostnames[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthenticateSession(
		ctx, replacement.Route.ID, replacement.Session.RouteVersion, replacement.SessionToken, "instance",
	); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("expired session error = %v", err)
	}

	want := []StoreOperation{
		StoreOperationHostnameClaim,
		StoreOperationRouteCreate,
		StoreOperationSessionAuthenticate,
		StoreOperationTransportRegister,
		StoreOperationRouteReady,
		StoreOperationSessionHeartbeat,
		StoreOperationSessionCreate,
		StoreOperationSessionExpire,
		StoreOperationHostnameRelease,
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
	changes         []LifecycleChange
	registrations   []RouteRegistration
	seen            map[string]struct{}
	registrationErr error
}

func (r *testLifecycleRecorder) RecordRegistration(
	_ context.Context,
	_ *statedb.Queries,
	registration RouteRegistration,
) error {
	if r.registrationErr != nil {
		return r.registrationErr
	}
	r.registrations = append(r.registrations, registration)
	return nil
}

func (r *testLifecycleRecorder) RecordLifecycle(_ context.Context, _ *statedb.Queries, change LifecycleChange) error {
	key := change.RouteID + "/" + string(change.Transition) + "/" + fmt.Sprint(change.RouteVersion)
	if _, ok := r.seen[key]; ok {
		return nil
	}
	r.seen[key] = struct{}{}
	r.changes = append(r.changes, change)
	return nil
}

type failingLifecycleRecorder struct{ err error }

func (failingLifecycleRecorder) RecordRegistration(context.Context, *statedb.Queries, RouteRegistration) error {
	return nil
}

func (r failingLifecycleRecorder) RecordLifecycle(context.Context, *statedb.Queries, LifecycleChange) error {
	return r.err
}
