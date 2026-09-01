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

func TestStoreHostnameClaimQuotaConfig(t *testing.T) {
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
	if store.maxActiveHostnameClaims != DefaultMaxActiveHostnameClaims ||
		store.maxHostnameClaimRequests != DefaultMaxHostnameClaimRequests {
		t.Fatalf("default hostname claim quotas = %d, %d, want %d, %d",
			store.maxActiveHostnameClaims, store.maxHostnameClaimRequests,
			DefaultMaxActiveHostnameClaims, DefaultMaxHostnameClaimRequests)
	}

	config := StoreConfig{MaxActiveHostnameClaims: 2, MaxHostnameClaimRequests: 3}
	store, err = NewStore(db, "example", config)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxActiveHostnameClaims = 100
	config.MaxHostnameClaimRequests = 100
	if store.maxActiveHostnameClaims != 2 || store.maxHostnameClaimRequests != 3 {
		t.Fatalf("configured hostname claim quotas = %d, %d, want 2, 3",
			store.maxActiveHostnameClaims, store.maxHostnameClaimRequests)
	}

	for name, config := range map[string]StoreConfig{
		"negative active claims":  {MaxActiveHostnameClaims: -1, MaxHostnameClaimRequests: 1},
		"negative claim requests": {MaxActiveHostnameClaims: 1, MaxHostnameClaimRequests: -1},
		"requests below active":   {MaxActiveHostnameClaims: 2, MaxHostnameClaimRequests: 1},
		"active claims too large": {MaxActiveHostnameClaims: maximumHostnameClaimQuota + 1, MaxHostnameClaimRequests: maximumHostnameClaimQuota + 1},
		"requests too large":      {MaxActiveHostnameClaims: 1, MaxHostnameClaimRequests: maximumHostnameClaimQuota + 1},
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
	upsertTestPrincipal(t, ctx, queries, "owner", "Owner", 1)
	if _, err := queries.InsertClaim(ctx, statedb.InsertClaimParams{
		ID: "claim_00000000000000000000000000000001", PrincipalID: "owner",
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
	if _, err := store.ClaimName(ctx, "owner", NameKindPersistentManaged, "domains", "reserved"); !errors.Is(err, ErrNameUnavailable) {
		t.Fatalf("reserved claim error = %v", err)
	}
}

func TestEphemeralClaimsDoNotConsumePersistentQuota(t *testing.T) {
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	upsertTestPrincipal(t, ctx, queries, "owner", "Owner", 1)
	store, err := NewStore(db, "example", StoreConfig{MaxActiveHostnameClaims: 1, MaxHostnameClaimRequests: 10})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimName(ctx, "owner", NameKindPersistentManaged, "owned", "persistent"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimName(ctx, "owner", NameKindEphemeral, "", "ephemeral"); err != nil {
		t.Fatalf("ephemeral claim with full persistent quota: %v", err)
	}
	total, remaining, err := store.FriendlyNameCapacity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if total != 4_429_593 || remaining != total-2 {
		t.Fatalf("friendly name capacity = %d/%d", remaining, total)
	}
}

func TestBurnedEphemeralClaimsDoNotConsumeRequestQuota(t *testing.T) {
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	upsertTestPrincipal(t, ctx, queries, "owner", "Owner", 1)
	store, err := NewStore(db, "example", StoreConfig{MaxActiveHostnameClaims: 1, MaxHostnameClaimRequests: 1})
	if err != nil {
		t.Fatal(err)
	}
	claim, err := store.ClaimName(ctx, "owner", NameKindEphemeral, "", "first")
	if err != nil {
		t.Fatal(err)
	}
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(ctx, "owner", claim.Hostname, "localhost:3000", "boot", routeToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, "owner", created.Route.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimName(ctx, "owner", NameKindEphemeral, "", "second"); err != nil {
		t.Fatalf("claim after ephemeral burn: %v", err)
	}
}

func TestEphemeralRestartReacquisitionAndAbandonedCleanup(t *testing.T) {
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	upsertTestPrincipal(t, ctx, queries, "owner", "Owner", 1)
	t0 := time.Unix(1_700_000_000, 0).UTC()
	store, err := NewStore(db, "example")
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return t0 }
	claim, err := store.ClaimName(ctx, "owner", NameKindEphemeral, "", "route")
	if err != nil {
		t.Fatal(err)
	}
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(ctx, "owner", claim.Hostname, "localhost:3000", "boot-one", routeToken)
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
	replacement, err := restarted.Create(ctx, "owner", claim.Hostname, "localhost:3000", "boot-two", replacementToken)
	if err != nil || replacement.Route.ID != created.Route.ID || replacement.Route.Generation != 2 {
		t.Fatalf("restart reacquisition = %#v, %v", replacement, err)
	}
	held, err := restarted.ClaimName(ctx, "owner", NameKindEphemeral, "", "held")
	if err != nil {
		t.Fatal(err)
	}
	cleanupAt := restartedAt.Add(EphemeralReacquisitionWindow + LeaseLifetime + time.Second)
	removed, err := restarted.CleanupAbandonedEphemeral(ctx, cleanupAt)
	if err != nil || len(removed) != 1 || removed[0] != created.Route.ID {
		t.Fatalf("abandoned cleanup = %q, %v", removed, err)
	}
	for _, hostname := range []string{claim.Hostname, held.Hostname} {
		stored, err := queries.GetClaimByHostname(ctx, hostname)
		if err != nil || stored.State != NameStateBurned {
			t.Fatalf("cleaned claim %s = %#v, %v", hostname, stored, err)
		}
	}
}

func TestConcurrentFriendlyAllocationsAreUnique(t *testing.T) {
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	upsertTestPrincipal(t, ctx, queries, "owner", "Owner", 1)
	store, err := NewStore(db, "example", StoreConfig{MaxActiveHostnameClaims: 32, MaxHostnameClaimRequests: 32})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan HostnameClaim, 32)
	errors := make(chan error, 32)
	for index := range 32 {
		go func() {
			<-start
			claim, err := store.ClaimName(ctx, "owner", NameKindPersistentManaged, "", fmt.Sprintf("request-%d", index))
			results <- claim
			errors <- err
		}()
	}
	close(start)
	names := make(map[string]struct{}, 32)
	for range 32 {
		claim, err := <-results, <-errors
		if err != nil {
			t.Fatal(err)
		}
		names[claim.Hostname] = struct{}{}
	}
	if len(names) != 32 {
		t.Fatalf("unique names = %d, want 32", len(names))
	}
}

func TestHostnameClaimLifecycle(t *testing.T) {
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	now := time.Unix(1_700_000_000, 0).UTC()
	upsertTestPrincipal(t, ctx, queries, "owner", "Owner", now.Unix())
	upsertTestPrincipal(t, ctx, queries, "other", "Other", now.Unix())
	store, err := NewStore(db, "example")
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }

	claim, err := store.ClaimHostname(ctx, "owner", "Demo", "exact-request")
	if err != nil {
		t.Fatal(err)
	}
	if claim.Hostname != "demo.example" || claim.Kind != NameKindPersistentManaged ||
		claim.State != NameStateActive || claim.Source != NameSourceCustom || claim.CreatedAt != now {
		t.Fatalf("claim = %#v", claim)
	}
	replayed, err := store.ClaimHostname(ctx, "owner", "demo", "exact-request")
	if err != nil || replayed.ID != claim.ID {
		t.Fatalf("replayed claim = %#v, %v", replayed, err)
	}
	alias, err := store.ClaimHostname(ctx, "owner", "demo", "alias-request")
	if err != nil || alias.ID != claim.ID {
		t.Fatalf("aliased claim = %#v, %v", alias, err)
	}
	exactRequests, err := queries.CountClaimRequestsByClaim(ctx, claim.ID)
	if err != nil {
		t.Fatal(err)
	}
	if exactRequests != 2 {
		t.Fatalf("exact claim request records = %d", exactRequests)
	}
	if _, err := store.ClaimHostname(ctx, "owner", "other", "alias-request"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("aliased request key error = %v", err)
	}
	if _, err := store.ClaimHostname(ctx, "owner", "other", "exact-request"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("changed replay error = %v", err)
	}
	if _, err := store.ClaimHostname(ctx, "other", "demo", "competing-request"); !errors.Is(err, ErrNameUnavailable) {
		t.Fatalf("competing claim error = %v", err)
	}
	random, err := store.ClaimHostname(ctx, "owner", "", "random-request")
	if err != nil {
		t.Fatal(err)
	}
	if random.Hostname == claim.Hostname || !strings.HasSuffix(random.Hostname, ".example") {
		t.Fatalf("random claim = %#v", random)
	}
	if replayed, err := store.ClaimHostname(ctx, "owner", "", "random-request"); err != nil || replayed.ID != random.ID {
		t.Fatalf("replayed random claim = %#v, %v", replayed, err)
	}

	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(ctx, "owner", claim.Hostname, "http://127.0.0.1:3000", "boot", routeToken)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := store.ListHostnameClaims(ctx, "owner")
	if err != nil || len(claims) != 2 {
		t.Fatalf("claims = %#v, %v", claims, err)
	}
	for _, listed := range claims {
		if listed.ID == claim.ID && listed.State != NameStateActive {
			t.Fatalf("routed claim state = %q", listed.State)
		}
	}
	if err := store.ReleaseHostnameClaim(ctx, "owner", claim.ID); err != nil {
		t.Fatal(err)
	}
	if routes, err := store.List(ctx, "owner"); err != nil || len(routes) != 0 {
		t.Fatalf("routes after release = %#v, %v", routes, err)
	}
	if _, err := store.AuthenticateLease(ctx, created.Route.ID, 1, created.LeaseToken, "boot"); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("released lease error = %v", err)
	}
	reactivated, err := store.ClaimHostname(ctx, "owner", "demo", "replacement-request")
	if err != nil || reactivated.ID != claim.ID || reactivated.State != NameStateActive {
		t.Fatalf("managed reactivation = %#v, %v", reactivated, err)
	}
	if _, err := store.ClaimHostname(ctx, "other", "demo", "other-replacement"); !errors.Is(err, ErrNameUnavailable) {
		t.Fatalf("managed transfer error = %v", err)
	}
	if replayed, err := store.ClaimHostname(ctx, "owner", "demo", "exact-request"); err != nil || replayed.ID != claim.ID {
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
	upsertTestPrincipal(t, ctx, queries, "owner", "Owner", 1)
	upsertTestPrincipal(t, ctx, queries, "other", "Other", 1)
	store, err := NewStore(db, "example")
	if err != nil {
		t.Fatal(err)
	}
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, "owner", "missing.example", "http://127.0.0.1:3000", "boot", routeToken); !errors.Is(err, ErrNameUnavailable) {
		t.Fatalf("unclaimed route error = %v", err)
	}
	if _, err := store.ClaimName(ctx, "owner", NameKindPersistentManaged, "base", "base"); err != nil {
		t.Fatal(err)
	}
	deep := "a.b.c.d.e.f.g.h.base.example"
	if _, err := store.Create(ctx, "owner", deep, "http://127.0.0.1:3000", "boot", routeToken); err != nil {
		t.Fatalf("eight-level route: %v", err)
	}
	if _, err := store.Create(ctx, "owner", "x."+deep, "http://127.0.0.1:3000", "boot", routeToken); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("ninth-level route error = %v", err)
	}
	if _, err := store.Create(ctx, "other", deep, "http://127.0.0.1:3000", "boot", routeToken); !errors.Is(err, ErrNameUnavailable) {
		t.Fatalf("cross-principal route error = %v", err)
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
	upsertTestPrincipal(t, ctx, queries, "owner", "Owner", 1)
	for index := range DefaultMaxActiveHostnameClaims {
		if _, err := queries.InsertClaim(ctx, statedb.InsertClaimParams{
			ID:          fmt.Sprintf("claim_%032x", index),
			PrincipalID: "owner",
			Hostname:    fmt.Sprintf("route%d.example", index),
			CreatedAt:   1,
		}); err != nil {
			t.Fatal(err)
		}
	}
	store, err := NewStore(db, "example")
	if err != nil {
		t.Fatal(err)
	}
	claim, err := store.ClaimHostname(ctx, "owner", "route0", "migrated-claim")
	if err != nil || claim.Hostname != "route0.example" {
		t.Fatalf("existing claim = %#v, %v", claim, err)
	}
	claims, err := store.ListHostnameClaims(ctx, "owner")
	if err != nil || len(claims) != DefaultMaxActiveHostnameClaims {
		t.Fatalf("listed claims = %d, %v", len(claims), err)
	}
	first, next, err := store.ListHostnameClaimsPage(ctx, "owner", "")
	if err != nil || len(first) != hostnameClaimPageSize || next == "" {
		t.Fatalf("first claim page = %d, %q, %v", len(first), next, err)
	}
	second, final, err := store.ListHostnameClaimsPage(ctx, "owner", next)
	if err != nil || len(second) != DefaultMaxActiveHostnameClaims-hostnameClaimPageSize || final != "" {
		t.Fatalf("second claim page = %d, %q, %v", len(second), final, err)
	}
	if _, err := store.ClaimHostname(ctx, "owner", "new", "over-quota"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("new claim over quota error = %v", err)
	}
}

func TestHostnameClaimActiveLimitOverride(t *testing.T) {
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	upsertTestPrincipal(t, ctx, queries, "owner", "Owner", 1)
	store, err := NewStore(db, "example", StoreConfig{
		MaxActiveHostnameClaims:  2,
		MaxHostnameClaimRequests: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.ClaimHostname(ctx, "owner", "first", "first-request")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimHostname(ctx, "owner", "second", "second-request"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimHostname(ctx, "owner", "third", "over-limit"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("claim over active limit error = %v", err)
	}
	if err := store.ReleaseHostnameClaim(ctx, "owner", first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimHostname(ctx, "owner", "third", "replacement-request"); err != nil {
		t.Fatalf("replacement claim: %v", err)
	}
	if _, err := store.ClaimHostname(ctx, "owner", "first", "reactivation-over-limit"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("reactivation over limit error = %v", err)
	}
}

func TestClaimRequestLimitStillAllowsKnownReplay(t *testing.T) {
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	upsertTestPrincipal(t, ctx, queries, "owner", "Owner", 1)
	claimID := "claim_0123456789abcdef0123456789abcdef"
	if _, err := queries.InsertClaim(ctx, statedb.InsertClaimParams{
		ID:          claimID,
		PrincipalID: "owner",
		Hostname:    "route.example",
		CreatedAt:   1,
	}); err != nil {
		t.Fatal(err)
	}
	const requestLimit = 2
	store, err := NewStore(db, "example", StoreConfig{
		MaxActiveHostnameClaims:  requestLimit,
		MaxHostnameClaimRequests: requestLimit,
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
		if err := txQueries.InsertClaimRequest(ctx, statedb.InsertClaimRequestParams{
			PrincipalID:    "owner",
			RequestKey:     fmt.Sprintf("request-%04d", index),
			RequestedLabel: "route",
			RequestedKind:  NameKindPersistentManaged,
			ClaimID:        claimID,
			CreatedAt:      1,
		}); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if replayed, err := store.ClaimHostname(ctx, "owner", "route", "request-0000"); err != nil || replayed.ID != claimID {
		t.Fatalf("known replay = %#v, %v", replayed, err)
	}
	if _, err := store.ClaimHostname(ctx, "owner", "route", "new-request"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("new request at limit error = %v", err)
	}
	requests, err := queries.CountClaimRequests(ctx, "owner")
	if err != nil {
		t.Fatal(err)
	}
	if requests != requestLimit {
		t.Fatalf("claim request records = %d, want %d", requests, requestLimit)
	}
}

func TestHostnameClaimObserverReportsValidationAndReleaseErrors(t *testing.T) {
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
	upsertTestPrincipal(t, ctx, queries, "owner", "Owner", 1)
	store, err := NewStore(db, "example", StoreConfig{
		ObserveOperation: func(operation StoreOperation, _ time.Duration, err error) {
			observations = append(observations, observation{operation: operation, err: err})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimHostname(ctx, "owner", "route", " bad "); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("invalid claim error = %v", err)
	}
	claim, err := store.ClaimHostname(ctx, "owner", "route", "valid")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReleaseHostnameClaim(ctx, "owner", claim.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.ReleaseHostnameClaim(ctx, "owner", claim.ID); !errors.Is(err, ErrNotFound) {
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

func upsertTestPrincipal(
	t *testing.T,
	ctx context.Context,
	queries *statedb.Queries,
	principalID string,
	displayName string,
	createdAt int64,
) {
	t.Helper()
	if err := queries.UpsertPrincipal(ctx, statedb.UpsertPrincipalParams{
		PrincipalID: principalID,
		DisplayName: displayName,
		Email:       "",
		CreatedAt:   createdAt,
	}); err != nil {
		t.Fatal(err)
	}
}
