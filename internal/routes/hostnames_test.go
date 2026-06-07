package routes

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/state"
	"github.com/tnldotdev/tnl/internal/state/statedb"
)

func TestStoreHostnameQuotaConfig(t *testing.T) {
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store, err := NewStore(db, "example")
	if err != nil {
		t.Fatal(err)
	}
	if store.maxActiveHostnames != DefaultMaxActiveHostnames ||
		store.maxHostnameRequests != DefaultMaxHostnameRequests {
		t.Fatalf("default hostname quotas = %d, %d, want %d, %d",
			store.maxActiveHostnames, store.maxHostnameRequests,
			DefaultMaxActiveHostnames, DefaultMaxHostnameRequests)
	}

	config := StoreConfig{MaxActiveHostnames: 2, MaxHostnameRequests: 3}
	store, err = NewStore(db, "example", config)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxActiveHostnames = 100
	config.MaxHostnameRequests = 100
	if store.maxActiveHostnames != 2 || store.maxHostnameRequests != 3 {
		t.Fatalf("configured hostname quotas = %d, %d, want 2, 3",
			store.maxActiveHostnames, store.maxHostnameRequests)
	}

	for name, config := range map[string]StoreConfig{
		"negative active hostnames":  {MaxActiveHostnames: -1, MaxHostnameRequests: 1},
		"negative hostname requests": {MaxActiveHostnames: 1, MaxHostnameRequests: -1},
		"requests below active":      {MaxActiveHostnames: 2, MaxHostnameRequests: 1},
		"active hostnames too large": {MaxActiveHostnames: maximumHostnameQuota + 1, MaxHostnameRequests: maximumHostnameQuota + 1},
		"requests too large":         {MaxActiveHostnames: 1, MaxHostnameRequests: maximumHostnameQuota + 1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewStore(db, "example", config); err == nil {
				t.Fatal("NewStore succeeded")
			}
		})
	}
}

func TestConfiguredReservationConflictsFailClosed(t *testing.T) {
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	upsertTestIdentity(t, ctx, queries, "owner", "Owner", 1)
	if _, err := queries.InsertHostname(ctx, statedb.InsertHostnameParams{
		ID: "hostname_00000000000000000000000000000001", IdentityID: "owner",
		Hostname: "control.example", CreatedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(db, "example", StoreConfig{ReservedRouteNames: []string{"control"}}); err == nil {
		t.Fatal("reservation conflicting with ownership succeeded")
	}
	store, err := NewStore(db, "example", StoreConfig{ReservedRouteNames: []string{"domains"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimHostname(ctx, "owner", HostnameKindManaged, "domains", "reserved"); !errors.Is(err, ErrNameUnavailable) {
		t.Fatalf("reserved hostname error = %v", err)
	}
}

func TestTemporaryClaimsDoNotConsumePersistentQuota(t *testing.T) {
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	upsertTestIdentity(t, ctx, queries, "owner", "Owner", 1)
	store, err := NewStore(db, "example", StoreConfig{MaxActiveHostnames: 1, MaxHostnameRequests: 10})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimHostname(ctx, "owner", HostnameKindManaged, "owned", "persistent"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimHostname(ctx, "owner", HostnameKindTemporary, "", "temporary"); err != nil {
		t.Fatalf("temporary hostname with full persistent quota: %v", err)
	}
	total, remaining, err := store.GeneratedHostnameCapacity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if total != 4_429_593 || remaining != total-2 {
		t.Fatalf("generated hostname capacity = %d/%d", remaining, total)
	}
}

func TestRetiredTemporaryClaimsDoNotConsumeRequestQuota(t *testing.T) {
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	upsertTestIdentity(t, ctx, queries, "owner", "Owner", 1)
	store, err := NewStore(db, "example", StoreConfig{MaxActiveHostnames: 1, MaxHostnameRequests: 1})
	if err != nil {
		t.Fatal(err)
	}
	hostname, err := store.ClaimHostname(ctx, "owner", HostnameKindTemporary, "", "first")
	if err != nil {
		t.Fatal(err)
	}
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(ctx, "owner", hostname.Hostname, "localhost:3000", "instance", routeToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, "owner", created.Route.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimHostname(ctx, "owner", HostnameKindTemporary, "", "second"); err != nil {
		t.Fatalf("hostname after temporary burn: %v", err)
	}
}

func TestTemporaryRestartReacquisitionAndAbandonedCleanup(t *testing.T) {
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	upsertTestIdentity(t, ctx, queries, "owner", "Owner", 1)
	t0 := time.Unix(0, 1_700_000_000).UTC()
	store, err := NewStore(db, "example")
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return t0 }
	hostname, err := store.ClaimHostname(ctx, "owner", HostnameKindTemporary, "", "route")
	if err != nil {
		t.Fatal(err)
	}
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(ctx, "owner", hostname.Hostname, "localhost:3000", "instance-one", routeToken, nil)
	if err != nil {
		t.Fatal(err)
	}

	restarted, err := NewStore(db, "example")
	if err != nil {
		t.Fatal(err)
	}
	restartedAt := t0.Add(time.Minute)
	restarted.now = func() time.Time { return restartedAt }
	replacementToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := restarted.Create(ctx, "owner", hostname.Hostname, "localhost:3000", "instance-two", replacementToken, nil)
	if err != nil || replacement.Route.ID != created.Route.ID || replacement.Route.RouteVersion != 2 {
		t.Fatalf("restart reacquisition = %#v, %v", replacement, err)
	}
	temporary, err := restarted.ClaimHostname(ctx, "owner", HostnameKindTemporary, "", "temporary")
	if err != nil {
		t.Fatal(err)
	}
	cleanupAt := restartedAt.Add(TemporaryReacquisitionWindow + SessionLifetime + time.Second)
	removed, err := restarted.CleanupAbandonedTemporary(ctx, cleanupAt)
	if err != nil || len(removed) != 1 || removed[0] != created.Route.ID {
		t.Fatalf("abandoned cleanup = %q, %v", removed, err)
	}
	for _, hostname := range []string{hostname.Hostname, temporary.Hostname} {
		stored, err := queries.GetHostnameByHostname(ctx, hostname)
		if err != nil || stored.Status != HostnameStatusRetired {
			t.Fatalf("cleaned hostname %s = %#v, %v", hostname, stored, err)
		}
	}
}

func TestConcurrentGeneratedHostnameAllocationsAreUnique(t *testing.T) {
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	upsertTestIdentity(t, ctx, queries, "owner", "Owner", 1)
	store, err := NewStore(db, "example", StoreConfig{MaxActiveHostnames: 32, MaxHostnameRequests: 32})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan Hostname, 32)
	errors := make(chan error, 32)
	for index := range 32 {
		go func() {
			<-start
			hostname, err := store.ClaimHostname(ctx, "owner", HostnameKindManaged, "", fmt.Sprintf("request-%d", index))
			results <- hostname
			errors <- err
		}()
	}
	close(start)
	names := make(map[string]struct{}, 32)
	for range 32 {
		hostname, err := <-results, <-errors
		if err != nil {
			t.Fatal(err)
		}
		names[hostname.Hostname] = struct{}{}
	}
	if len(names) != 32 {
		t.Fatalf("unique names = %d, want 32", len(names))
	}
}

func TestHostnameLifecycle(t *testing.T) {
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	now := time.Unix(0, 1_700_000_000).UTC()
	upsertTestIdentity(t, ctx, queries, "owner", "Owner", now.UnixNano())
	upsertTestIdentity(t, ctx, queries, "other", "Other", now.UnixNano())
	store, err := NewStore(db, "example")
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }

	hostname, err := store.ClaimManagedHostname(ctx, "owner", "Demo", "exact-request")
	if err != nil {
		t.Fatal(err)
	}
	if hostname.Hostname != "demo.example" || hostname.Kind != HostnameKindManaged ||
		hostname.Status != HostnameStatusActive || hostname.Source != HostnameSourceUser || hostname.CreatedAt != now {
		t.Fatalf("hostname = %#v", hostname)
	}
	replayed, err := store.ClaimManagedHostname(ctx, "owner", "demo", "exact-request")
	if err != nil || replayed.ID != hostname.ID {
		t.Fatalf("replayed hostname = %#v, %v", replayed, err)
	}
	alias, err := store.ClaimManagedHostname(ctx, "owner", "demo", "alias-request")
	if err != nil || alias.ID != hostname.ID {
		t.Fatalf("aliased hostname = %#v, %v", alias, err)
	}
	exactRequests, err := queries.CountHostnameRequestsByHostname(ctx, hostname.ID)
	if err != nil {
		t.Fatal(err)
	}
	if exactRequests != 2 {
		t.Fatalf("exact hostname request records = %d", exactRequests)
	}
	if _, err := store.ClaimManagedHostname(ctx, "owner", "other", "alias-request"); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("aliased idempotency key error = %v", err)
	}
	if _, err := store.ClaimManagedHostname(ctx, "owner", "other", "exact-request"); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("changed replay error = %v", err)
	}
	if _, err := store.ClaimManagedHostname(ctx, "other", "demo", "competing-request"); !errors.Is(err, ErrNameUnavailable) {
		t.Fatalf("competing hostname error = %v", err)
	}
	random, err := store.ClaimManagedHostname(ctx, "owner", "", "random-request")
	if err != nil {
		t.Fatal(err)
	}
	if random.Hostname == hostname.Hostname || !strings.HasSuffix(random.Hostname, ".example") {
		t.Fatalf("random hostname = %#v", random)
	}
	if replayed, err := store.ClaimManagedHostname(ctx, "owner", "", "random-request"); err != nil || replayed.ID != random.ID {
		t.Fatalf("replayed random hostname = %#v, %v", replayed, err)
	}

	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(ctx, "owner", hostname.Hostname, "http://127.0.0.1:3000", "instance", routeToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostnames, err := store.ListHostnames(ctx, "owner")
	if err != nil || len(hostnames) != 2 {
		t.Fatalf("hostnames = %#v, %v", hostnames, err)
	}
	for _, listed := range hostnames {
		if listed.ID == hostname.ID && listed.Status != HostnameStatusActive {
			t.Fatalf("routed hostname status = %q", listed.Status)
		}
	}
	if err := store.ReleaseHostname(ctx, "owner", hostname.ID); err != nil {
		t.Fatal(err)
	}
	if routes, err := store.List(ctx, "owner"); err != nil || len(routes) != 0 {
		t.Fatalf("routes after release = %#v, %v", routes, err)
	}
	if _, err := store.AuthenticateSession(ctx, created.Route.ID, 1, created.SessionToken, "instance"); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("released session error = %v", err)
	}
	reactivated, err := store.ClaimManagedHostname(ctx, "owner", "demo", "replacement-request")
	if err != nil || reactivated.ID != hostname.ID || reactivated.Status != HostnameStatusActive {
		t.Fatalf("managed reactivation = %#v, %v", reactivated, err)
	}
	if _, err := store.ClaimManagedHostname(ctx, "other", "demo", "other-replacement"); !errors.Is(err, ErrNameUnavailable) {
		t.Fatalf("managed transfer error = %v", err)
	}
	if replayed, err := store.ClaimManagedHostname(ctx, "owner", "demo", "exact-request"); err != nil || replayed.ID != hostname.ID {
		t.Fatalf("original replay = %#v, %v", replayed, err)
	}
}

func TestRouteCreationRequiresOwnedClaim(t *testing.T) {
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	upsertTestIdentity(t, ctx, queries, "owner", "Owner", 1)
	upsertTestIdentity(t, ctx, queries, "other", "Other", 1)
	store, err := NewStore(db, "example")
	if err != nil {
		t.Fatal(err)
	}
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, "owner", "missing.example", "http://127.0.0.1:3000", "instance", routeToken, nil); !errors.Is(err, ErrNameUnavailable) {
		t.Fatalf("unclaimed route error = %v", err)
	}
	if _, err := store.ClaimHostname(ctx, "owner", HostnameKindManaged, "base", "base"); err != nil {
		t.Fatal(err)
	}
	deep := "a.b.c.d.e.f.g.h.base.example"
	if _, err := store.Create(ctx, "owner", deep, "http://127.0.0.1:3000", "instance", routeToken, nil); err != nil {
		t.Fatalf("eight-level route: %v", err)
	}
	if _, err := store.Create(ctx, "owner", "x."+deep, "http://127.0.0.1:3000", "instance", routeToken, nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("ninth-level route error = %v", err)
	}
	if _, err := store.Create(ctx, "other", deep, "http://127.0.0.1:3000", "instance", routeToken, nil); !errors.Is(err, ErrNameUnavailable) {
		t.Fatalf("cross-identity route error = %v", err)
	}
}

func TestExistingClaimBypassesNewActiveQuota(t *testing.T) {
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	upsertTestIdentity(t, ctx, queries, "owner", "Owner", 1)
	for index := range DefaultMaxActiveHostnames {
		if _, err := queries.InsertHostname(ctx, statedb.InsertHostnameParams{
			ID:         fmt.Sprintf("hostname_%032x", index),
			IdentityID: "owner",
			Hostname:   fmt.Sprintf("route%d.example", index),
			CreatedAt:  1,
		}); err != nil {
			t.Fatal(err)
		}
	}
	store, err := NewStore(db, "example")
	if err != nil {
		t.Fatal(err)
	}
	hostname, err := store.ClaimManagedHostname(ctx, "owner", "route0", "migrated-hostname")
	if err != nil || hostname.Hostname != "route0.example" {
		t.Fatalf("existing hostname = %#v, %v", hostname, err)
	}
	hostnames, err := store.ListHostnames(ctx, "owner")
	if err != nil || len(hostnames) != DefaultMaxActiveHostnames {
		t.Fatalf("listed hostnames = %d, %v", len(hostnames), err)
	}
	first, next, err := store.ListHostnamesPage(ctx, "owner", "")
	if err != nil || len(first) != hostnamePageSize || next == "" {
		t.Fatalf("first hostname page = %d, %q, %v", len(first), next, err)
	}
	second, final, err := store.ListHostnamesPage(ctx, "owner", next)
	if err != nil || len(second) != DefaultMaxActiveHostnames-hostnamePageSize || final != "" {
		t.Fatalf("second hostname page = %d, %q, %v", len(second), final, err)
	}
	if _, err := store.ClaimManagedHostname(ctx, "owner", "new", "over-quota"); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("new hostname over quota error = %v", err)
	}
}

func TestHostnameActiveLimitOverride(t *testing.T) {
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	upsertTestIdentity(t, ctx, queries, "owner", "Owner", 1)
	store, err := NewStore(db, "example", StoreConfig{
		MaxActiveHostnames:  2,
		MaxHostnameRequests: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.ClaimManagedHostname(ctx, "owner", "first", "first-request")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimManagedHostname(ctx, "owner", "second", "second-request"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimManagedHostname(ctx, "owner", "third", "over-limit"); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("hostname over active limit error = %v", err)
	}
	if err := store.ReleaseHostname(ctx, "owner", first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimManagedHostname(ctx, "owner", "third", "replacement-request"); err != nil {
		t.Fatalf("replacement hostname: %v", err)
	}
	if _, err := store.ClaimManagedHostname(ctx, "owner", "first", "reactivation-over-limit"); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("reactivation over limit error = %v", err)
	}
}

func TestHostnameRequestLimitStillAllowsKnownReplay(t *testing.T) {
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	upsertTestIdentity(t, ctx, queries, "owner", "Owner", 1)
	hostnameID := "hostname_0123456789abcdef0123456789abcdef"
	if _, err := queries.InsertHostname(ctx, statedb.InsertHostnameParams{
		ID:         hostnameID,
		IdentityID: "owner",
		Hostname:   "route.example",
		CreatedAt:  1,
	}); err != nil {
		t.Fatal(err)
	}
	const requestLimit = 2
	store, err := NewStore(db, "example", StoreConfig{
		MaxActiveHostnames:  requestLimit,
		MaxHostnameRequests: requestLimit,
	})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	txQueries := queries.WithTx(tx)
	for index := range requestLimit {
		if err := txQueries.InsertHostnameRequest(ctx, statedb.InsertHostnameRequestParams{
			IdentityID:     "owner",
			RequestKey:     fmt.Sprintf("request-%04d", index),
			RequestedLabel: "route",
			RequestedKind:  HostnameKindManaged,
			HostnameID:     hostnameID,
			CreatedAt:      1,
		}); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if replayed, err := store.ClaimManagedHostname(ctx, "owner", "route", "request-0000"); err != nil || replayed.ID != hostnameID {
		t.Fatalf("known replay = %#v, %v", replayed, err)
	}
	if _, err := store.ClaimManagedHostname(ctx, "owner", "route", "new-request"); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("new request at limit error = %v", err)
	}
	requests, err := queries.CountHostnameRequests(ctx, "owner")
	if err != nil {
		t.Fatal(err)
	}
	if requests != requestLimit {
		t.Fatalf("hostname request records = %d, want %d", requests, requestLimit)
	}
}

func TestHostnameObserverReportsValidationAndReleaseErrors(t *testing.T) {
	type observation struct {
		operation StoreOperation
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
		ObserveOperation: func(operation StoreOperation, _ time.Duration, err error) {
			observations = append(observations, observation{operation: operation, err: err})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimManagedHostname(ctx, "owner", "route", " bad "); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("invalid hostname error = %v", err)
	}
	hostname, err := store.ClaimManagedHostname(ctx, "owner", "route", "valid")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReleaseHostname(ctx, "owner", hostname.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.ReleaseHostname(ctx, "owner", hostname.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("repeated release error = %v", err)
	}

	wantOperations := []StoreOperation{
		StoreOperationHostnameClaim,
		StoreOperationHostnameClaim,
		StoreOperationHostnameRelease,
		StoreOperationHostnameRelease,
	}
	if len(observations) != len(wantOperations) {
		t.Fatalf("observations = %#v", observations)
	}
	for index, operation := range wantOperations {
		if observations[index].operation != operation {
			t.Fatalf("observation %d operation = %q, want %q", index, observations[index].operation, operation)
		}
	}
	if !errors.Is(observations[0].err, ErrInvalidArgument) || observations[1].err != nil ||
		observations[2].err != nil || !errors.Is(observations[3].err, ErrNotFound) {
		t.Fatalf("observation errors = %#v", observations)
	}
}

func upsertTestIdentity(
	t *testing.T,
	ctx context.Context,
	queries *statedb.Queries,
	identityID string,
	displayName string,
	createdAt int64,
) {
	t.Helper()
	if err := queries.UpsertIdentity(ctx, statedb.UpsertIdentityParams{
		IdentityID:  identityID,
		DisplayName: displayName,
		Email:       "",
		CreatedAt:   createdAt,
	}); err != nil {
		t.Fatal(err)
	}
}
