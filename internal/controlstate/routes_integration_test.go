package controlstate

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestIntegrationRouteCreationAndDeletion(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "route_creation")
	request := builtinRouteRequest(t, database, now)
	route, err := database.CreateRoute(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	if route.TeamID != request.TeamID || route.MembershipID != request.MembershipID || route.CanonicalHostname != request.CanonicalHostname || route.PolicyRevision != 1 || route.NextRouteVersion != 1 || route.LifecycleState != "enabled" {
		t.Fatalf("created route = %#v", route)
	}
	repeated, err := database.CreateRoute(t.Context(), request, now.Add(time.Second))
	if err != nil || !reflect.DeepEqual(repeated, route) {
		t.Fatalf("route replay = %#v, %v", repeated, err)
	}
	changed := request
	changed.RequestDigest = sha256.Sum256([]byte("changed"))
	if _, err := database.CreateRoute(t.Context(), changed, now); !errors.Is(err, ErrRouteIdempotency) {
		t.Fatalf("route idempotency: %v", err)
	}
	conflict := request
	conflict.IdempotencyKey, conflict.RequestDigest = "conflict", sha256.Sum256([]byte("conflict"))
	if _, err := database.CreateRoute(t.Context(), conflict, now); !errors.Is(err, ErrRouteConflict) {
		t.Fatalf("hostname conflict: %v", err)
	}
	deeper := conflict
	deeper.CanonicalHostname = "too.deep." + request.CanonicalHostname
	if _, err := database.CreateRoute(t.Context(), deeper, now); !errors.Is(err, ErrRouteAccess) {
		t.Fatalf("deep member hostname: %v", err)
	}
	page, err := database.ListRoutes(t.Context(), request.ActingIdentityID, request.TeamID, "")
	if err != nil || len(page.Routes) != 1 || page.NextCursor != "" || page.Routes[0].ID != route.ID {
		t.Fatalf("route page = %#v, %v", page, err)
	}
	loaded, err := database.GetRoute(t.Context(), request.ActingIdentityID, route.ID)
	if err != nil || !reflect.DeepEqual(loaded, route) {
		t.Fatalf("loaded route = %#v, %v", loaded, err)
	}
	if err := database.DeleteRoute(t.Context(), request.ActingIdentityID, route.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.GetRoute(t.Context(), request.ActingIdentityID, route.ID); !errors.Is(err, ErrRouteNotFound) {
		t.Fatalf("deleted route read: %v", err)
	}
	if _, err := database.CreateRoute(t.Context(), request, now); !errors.Is(err, ErrRouteIdempotency) {
		t.Fatalf("deleted route retry: %v", err)
	}
}

func TestIntegrationConcurrentRouteCreation(t *testing.T) {
	for _, sameRequest := range []bool{true, false} {
		t.Run(fmt.Sprintf("same_request_%t", sameRequest), func(t *testing.T) {
			database, now := newControlStateIntegrationDatabase(t, "route_contention")
			request := builtinRouteRequest(t, database, now)
			request.Ephemeral = !sameRequest
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			workers := newIntegrationWorkers(t, cancel)
			type result struct {
				route Route
				err   error
			}
			const callers = 4
			results := make(chan result, callers)
			for index := range callers {
				workers.Go(func() {
					candidate := request
					if !sameRequest {
						candidate.IdempotencyKey = fmt.Sprintf("contender-%d", index)
						candidate.RequestDigest = sha256.Sum256([]byte(candidate.IdempotencyKey))
					}
					route, err := database.CreateRoute(ctx, candidate, now)
					results <- result{route, err}
				})
			}
			var winner Route
			successes, conflicts := 0, 0
			for range callers {
				result := awaitIntegrationResult(t, ctx, results)
				switch {
				case result.err == nil:
					successes++
					if winner.ID != "" && !reflect.DeepEqual(result.route, winner) {
						t.Fatalf("concurrent retry changed route: %#v", result.route)
					}
					winner = result.route
				case errors.Is(result.err, ErrRouteConflict):
					conflicts++
				default:
					t.Fatal(result.err)
				}
			}
			wantSuccesses := 1
			if sameRequest {
				wantSuccesses = callers
			}
			if successes != wantSuccesses || conflicts != callers-wantSuccesses {
				t.Fatalf("contention = %d successes, %d conflicts", successes, conflicts)
			}
			if !sameRequest {
				if winner.ExpiresAt == nil {
					t.Fatal("ephemeral winner has no expiry")
				}
				if count, err := database.DeleteExpiredEphemeralRoutes(ctx, *winner.ExpiresAt); err != nil || count != 1 {
					t.Fatalf("winner expiry = %d, %v", count, err)
				}
			}
		})
	}
}

func TestIntegrationRouteMutationAndExpiredSession(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "route_mutation")
	request := builtinRouteRequest(t, database, now)
	route := createTestRoute(t, database, request, now)
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.teams SET policy_revision = 2, updated_at = $2 WHERE id = $1`, route.TeamID, now); err != nil {
		t.Fatal(err)
	}
	update := AuthorizedRouteUpdateRequest{RouteID: route.ID, TeamID: route.TeamID, ActingIdentityID: request.ActingIdentityID,
		Target: "http://127.0.0.1:4000", AllowedIPPrefixes: []string{"192.0.2.0/24"}, PolicyRevision: 2, ExpectedMutationRevision: route.MutationRevision}
	updated, err := database.UpdateAuthorizedRoute(t.Context(), update, now)
	if err != nil || updated.Target != update.Target || updated.PolicyRevision != 2 || !reflect.DeepEqual(updated.AllowedIPPrefixes, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}) || updated.TeamID != route.TeamID || updated.DomainID != route.DomainID || updated.MembershipID != route.MembershipID || updated.CanonicalHostname != route.CanonicalHostname || updated.RouteScope != route.RouteScope {
		t.Fatalf("updated route = %#v, %v", updated, err)
	}
	if _, err := database.UpdateAuthorizedRoute(t.Context(), update, now); !errors.Is(err, ErrRouteMutationStale) {
		t.Fatalf("stale mutation: %v", err)
	}
	update.ExpectedMutationRevision, update.AllowedIPPrefixes = updated.MutationRevision, []string{"192.0.2.9/24"}
	if _, err := database.UpdateAuthorizedRoute(t.Context(), update, now); !errors.Is(err, ErrRouteInvalid) {
		t.Fatalf("noncanonical policy: %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `INSERT INTO control.route_sessions (
		id, route_id, team_id, membership_id, acting_identity_id, route_version, idempotency_key,
		request_digest, session_token_id, session_token_digest, policy_revision, certificate_cache_key,
		certificate_scope, certificate_identifiers, certificate_challenge, state, created_at, last_heartbeat_at, publisher_expires_at
	) VALUES ('session_stale_update', $1, $2, $3, $4, 1, 'stale-update', decode(repeat('08', 32), 'hex'),
		'token_stale_update', decode(repeat('09', 32), 'hex'), 2, 'stale-update', 'route', ARRAY[$5], 'tls-alpn-01', 'starting', $6, $6, $7)`,
		route.ID, route.TeamID, route.MembershipID, request.ActingIdentityID, route.CanonicalHostname, now, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	update.Target, update.AllowedIPPrefixes = "http://127.0.0.1:5000", []string{}
	updated, err = database.UpdateAuthorizedRoute(t.Context(), update, now.Add(2*time.Second))
	if err != nil || updated.Target != update.Target {
		t.Fatalf("update after expiry = %#v, %v", updated, err)
	}
	var state string
	if err := database.pool.QueryRow(t.Context(), `SELECT state FROM control.route_sessions WHERE id = 'session_stale_update'`).Scan(&state); err != nil || state != "expired" {
		t.Fatalf("stale session = %q, %v", state, err)
	}
}

func TestIntegrationEphemeralRouteExpiry(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "ephemeral_expiry")
	request := builtinRouteRequest(t, database, now)
	request.Ephemeral = true
	route, err := database.CreateRoute(t.Context(), request, now)
	if err != nil || !route.Ephemeral || route.ExpiresAt == nil || !route.ExpiresAt.Equal(now.Add(ephemeralRouteGracePeriod)) {
		t.Fatalf("ephemeral route = %#v, %v", route, err)
	}
	if count, err := database.DeleteExpiredEphemeralRoutes(t.Context(), route.ExpiresAt.Add(-time.Microsecond)); err != nil || count != 0 {
		t.Fatalf("early expiry = %d, %v", count, err)
	}
	if count, err := database.DeleteExpiredEphemeralRoutes(t.Context(), *route.ExpiresAt); err != nil || count != 1 {
		t.Fatalf("expiry = %d, %v", count, err)
	}
	if _, err := database.GetRoute(t.Context(), request.ActingIdentityID, route.ID); !errors.Is(err, ErrRouteNotFound) {
		t.Fatalf("expired route read: %v", err)
	}
}

func TestIntegrationDNSRouteWork(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "dns_route_work")
	request := builtinRouteRequest(t, database, now)
	request.DNSState = RouteDNSPending
	route, err := database.CreateRoute(t.Context(), request, now)
	if err != nil || route.DNSState != RouteDNSPending || route.DNSAuthorityReference != "" {
		t.Fatalf("DNS route = %#v, %v", route, err)
	}
	work, found, err := database.ClaimDNSRouteWork(t.Context(), "dns-worker", now, time.Minute)
	if err != nil || !found || work.RouteID != route.ID || work.Attempts != 1 || work.WorkEpoch != 1 {
		t.Fatalf("claim DNS work = %#v, %t, %v", work, found, err)
	}
	if _, found, err := database.ClaimDNSRouteWork(t.Context(), "other", now, time.Minute); err != nil || found {
		t.Fatalf("concurrent DNS claim = %t, %v", found, err)
	}
	stale := work
	work.State, work.AvailableAt = RouteDNSPublished, time.Time{}
	saved, err := database.SaveDNSRouteWork(t.Context(), work, now)
	if err != nil || saved.State != RouteDNSPublished || !saved.AvailableAt.IsZero() || saved.DNSRevision != 2 {
		t.Fatalf("published DNS work = %#v, %v", saved, err)
	}
	if _, err := database.SaveDNSRouteWork(t.Context(), stale, now); !errors.Is(err, ErrDNSRouteWorkStale) {
		t.Fatalf("stale DNS save: %v", err)
	}
	if err := database.DeleteRoute(t.Context(), request.ActingIdentityID, route.ID, now); err != nil {
		t.Fatal(err)
	}
	removal, found, err := database.ClaimDNSRouteWork(t.Context(), "dns-worker", now, time.Minute)
	if err != nil || !found || removal.RouteID != route.ID || removal.State != RouteDNSRemoving || removal.Attempts != 2 {
		t.Fatalf("DNS removal = %#v, %t, %v", removal, found, err)
	}
	removal.State, removal.AvailableAt = RouteDNSRemoved, time.Time{}
	removed, err := database.SaveDNSRouteWork(t.Context(), removal, now)
	if err != nil || removed.State != RouteDNSRemoved || !removed.AvailableAt.IsZero() {
		t.Fatalf("removed DNS work = %#v, %v", removed, err)
	}
	request.IdempotencyKey, request.RequestDigest, request.Ephemeral = "replacement", sha256.Sum256([]byte("replacement")), true
	ephemeral := createTestRoute(t, database, request, now)
	if ephemeral.ExpiresAt == nil {
		t.Fatal("ephemeral replacement has no expiry")
	}
	if count, err := database.DeleteExpiredEphemeralRoutes(t.Context(), *ephemeral.ExpiresAt); err != nil || count != 1 {
		t.Fatalf("DNS-managed expiry = %d, %v", count, err)
	}
	var lifecycle, dns string
	if err := database.pool.QueryRow(t.Context(), `SELECT lifecycle_state, dns_state FROM control.routes WHERE id = $1`, ephemeral.ID).Scan(&lifecycle, &dns); err != nil || lifecycle != "deleted" || dns != "removing" {
		t.Fatalf("expired DNS route = %s/%s, %v", lifecycle, dns, err)
	}
	removal, found, err = database.ClaimDNSRouteWork(t.Context(), "expiry-worker", *ephemeral.ExpiresAt, time.Minute)
	if err != nil || !found || removal.RouteID != ephemeral.ID || removal.State != RouteDNSRemoving {
		t.Fatalf("expired DNS cleanup = %#v, %t, %v", removal, found, err)
	}
}

func builtinRouteRequest(t *testing.T, database *Database, now time.Time) CreateRouteRequest {
	t.Helper()
	session := newBuiltinSession(t, database, now)
	membership := session.Identity.Memberships[0]
	domains, err := database.ListTeamDomains(t.Context(), session.Identity.Identity.ID, membership.TeamID)
	if err != nil || len(domains) != 1 {
		t.Fatalf("managed domain prerequisite: %#v, %v", domains, err)
	}
	return CreateRouteRequest{TeamID: membership.TeamID, DomainID: domains[0].ID, MembershipID: membership.ID,
		ActingIdentityID: session.Identity.Identity.ID, IdempotencyKey: "route", RequestDigest: sha256.Sum256([]byte("route")),
		CanonicalHostname: "demo." + membership.ManagedLabel + ".tunnels.example.test", Target: "http://127.0.0.1:3000", RouteScope: RouteScopeMember, DNSState: RouteDNSUnmanaged}
}

func createTestRoute(t *testing.T, database *Database, request CreateRouteRequest, now time.Time) Route {
	t.Helper()
	route, err := database.CreateRoute(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	return route
}
