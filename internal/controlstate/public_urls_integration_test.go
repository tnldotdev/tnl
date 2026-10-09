package controlstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationRouteCreationAndDeletion(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "public_url_creation")
	request := builtinRouteRequest(t, database, now)
	route, err := database.CreatePublicURL(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	if route.TeamID != request.TeamID || route.MembershipID != request.MembershipID || route.CanonicalHostname != request.CanonicalHostname || route.PolicyRevision != 1 || route.NextPublishRunNumber != 1 || route.LifecycleState != "enabled" {
		t.Fatalf("created route = %#v", route)
	}
	repeated, err := database.CreatePublicURL(t.Context(), request, now.Add(time.Second))
	if err != nil || !reflect.DeepEqual(repeated, route) {
		t.Fatalf("route replay = %#v, %v", repeated, err)
	}
	changed := request
	changed.RequestDigest = sha256.Sum256([]byte("changed"))
	if _, err := database.CreatePublicURL(t.Context(), changed, now); !errors.Is(err, ErrPublicURLIdempotency) {
		t.Fatalf("route idempotency: %v", err)
	}
	conflict := request
	conflict.IdempotencyKey, conflict.RequestDigest = "conflict", sha256.Sum256([]byte("conflict"))
	if _, err := database.CreatePublicURL(t.Context(), conflict, now); !errors.Is(err, ErrPublicURLConflict) {
		t.Fatalf("hostname conflict: %v", err)
	}
	deeper := conflict
	deeper.CanonicalHostname = "nested.api." + request.CanonicalHostname
	nested, err := database.CreatePublicURL(t.Context(), deeper, now)
	if err != nil {
		t.Fatalf("nested member hostname: %v", err)
	}
	if nested.CanonicalHostname != deeper.CanonicalHostname || nested.PublicURLScope != PublicURLScopeMember || nested.MembershipID != request.MembershipID || nested.TeamID != request.TeamID {
		t.Fatalf("nested public URL changed its member ownership: %#v", nested)
	}
	if err := database.DeletePublicURL(t.Context(), request.ActingIdentityID, nested.ID, now); err != nil {
		t.Fatal(err)
	}
	page, err := database.ListPublicURLs(t.Context(), request.ActingIdentityID, request.TeamID, "")
	if err != nil || len(page.PublicURLs) != 1 || page.NextCursor != "" || page.PublicURLs[0].ID != route.ID {
		t.Fatalf("route page = %#v, %v", page, err)
	}
	loaded, err := database.GetPublicURL(t.Context(), request.ActingIdentityID, route.ID)
	if err != nil || !reflect.DeepEqual(loaded, route) {
		t.Fatalf("loaded route = %#v, %v", loaded, err)
	}
	if err := database.DeletePublicURL(t.Context(), request.ActingIdentityID, route.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.GetPublicURL(t.Context(), request.ActingIdentityID, route.ID); !errors.Is(err, ErrPublicURLNotFound) {
		t.Fatalf("deleted route read: %v", err)
	}
	if _, err := database.CreatePublicURL(t.Context(), request, now); !errors.Is(err, ErrPublicURLIdempotency) {
		t.Fatalf("deleted route retry: %v", err)
	}
}

func TestIntegrationSimpleManagedDirectNameReservation(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "simple_managed_direct")
	request := builtinRouteRequest(t, database, now)
	request.ManagedURLMode = naming.ManagedURLModeSimple
	request.MembershipID, request.PublicURLScope = "", PublicURLScopeShared
	request.CanonicalHostname = "app.tunnels.example.test"
	first, err := database.CreatePublicURL(t.Context(), request, now)
	if err != nil || first.PublicURLScope != PublicURLScopeShared || first.MembershipID != "" {
		t.Fatalf("simple direct public URL = %#v, %v", first, err)
	}
	if replay, err := database.CreatePublicURL(t.Context(), request, now.Add(time.Second)); err != nil || replay.ID != first.ID {
		t.Fatalf("direct public URL retry = %#v, %v", replay, err)
	}
	teamRequest := authorityTeamRequest(request.ActingIdentityID)
	teamRequest.DisplayName = "app"
	if _, err := database.CreateTeam(t.Context(), teamRequest, now); !errors.Is(err, ErrTeamNameUnavailable) {
		t.Fatalf("direct URL name was assigned to a team: %v", err)
	}
	request.IdempotencyKey = "reserved-label"
	request.RequestDigest = sha256.Sum256([]byte(request.IdempotencyKey))
	request.CanonicalHostname = "local-administrator.tunnels.example.test"
	if _, err := database.CreatePublicURL(t.Context(), request, now); !errors.Is(err, ErrPublicURLConflict) {
		t.Fatalf("personal team name was claimed as a direct URL: %v", err)
	}
}

func TestIntegrationSimpleManagedOrganizationNamespace(t *testing.T) {
	database, now, owner, team := newAuthorityTeam(t)
	members, err := database.ListTeamMemberships(t.Context(), owner, team.ID)
	if err != nil || len(members) != 1 {
		t.Fatalf("owner membership = %#v, %v", members, err)
	}
	domains, err := database.ListTeamDomains(t.Context(), owner, team.ID)
	if err != nil || len(domains) == 0 {
		t.Fatalf("team domains = %#v, %v", domains, err)
	}
	request := CreatePublicURLRequest{
		ManagedURLMode: naming.ManagedURLModeSimple, TeamID: team.ID, DomainID: domains[0].ID,
		MembershipID: members[0].ID, ActingIdentityID: owner, PublicURLScope: PublicURLScopeMember,
		IdempotencyKey: "simple-organization", RequestDigest: sha256.Sum256([]byte("simple-organization")),
		Target: "http://127.0.0.1:3000", DNSState: PublicURLDNSUnmanaged,
	}
	request.CanonicalHostname = "app." + members[0].MemberSlug + "." + team.DisplayName + "." + domains[0].CanonicalDomain
	if _, err := database.CreatePublicURL(t.Context(), request, now); err != nil {
		t.Fatalf("organization public URL: %v", err)
	}
	request.IdempotencyKey, request.RequestDigest = "managed-label", sha256.Sum256([]byte("managed-label"))
	request.CanonicalHostname = "app." + members[0].ManagedLabel + "." + domains[0].CanonicalDomain
	if _, err := database.CreatePublicURL(t.Context(), request, now); !errors.Is(err, ErrPublicURLAccess) {
		t.Fatalf("generated label bypassed simple namespace: %v", err)
	}
}

func TestIntegrationLargePublicURLIPPolicy(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "large_public_url_ip_policy")
	request := builtinRouteRequest(t, database, now)
	request.AllowedIPPrefixes = make([]string, 512)
	for index := range request.AllowedIPPrefixes {
		request.AllowedIPPrefixes[index] = fmt.Sprintf("198.18.%d.%d/32", index/256, index%256)
	}
	slices.Sort(request.AllowedIPPrefixes)
	route, err := database.CreatePublicURL(t.Context(), request, now)
	if err != nil || len(route.AllowedIPPrefixes) != 512 {
		t.Fatalf("created large public URL IP policy: %d prefixes, %v", len(route.AllowedIPPrefixes), err)
	}
	loaded, err := database.GetPublicURL(t.Context(), request.ActingIdentityID, route.ID)
	if err != nil || !slices.Equal(loaded.AllowedIPPrefixes, route.AllowedIPPrefixes) {
		t.Fatalf("loaded policy: %d prefixes, %v", len(loaded.AllowedIPPrefixes), err)
	}
	var ciphertext, hashes, sealedDigest []byte
	if err := database.pool.QueryRow(t.Context(), `SELECT allowed_ip_policy_ciphertext,
		allowed_ip_hashes, request_digest_ciphertext
		FROM control.public_urls WHERE id = $1`, route.ID).Scan(
		&ciphertext, &hashes, &sealedDigest,
	); err != nil || bytes.Contains(ciphertext, []byte("198.18.")) ||
		bytes.Contains(hashes, []byte("198.18.")) || len(sealedDigest) <= 32 {
		t.Fatalf("saved public URL retained raw policy or digest: %v", err)
	}
	update := AuthorizedPublicURLUpdateRequest{
		PublicURLID: route.ID, TeamID: route.TeamID, ActingIdentityID: request.ActingIdentityID,
		Target: route.Target, AllowedIPPrefixes: request.AllowedIPPrefixes[1:],
		PolicyRevision: uint64(route.PolicyRevision), ExpectedMutationRevision: route.MutationRevision,
	}
	updated, err := database.UpdateAuthorizedPublicURL(t.Context(), update, now.Add(time.Second))
	if err != nil || len(updated.AllowedIPPrefixes) != 511 {
		t.Fatalf("updated large public URL IP policy: %d prefixes, %v", len(updated.AllowedIPPrefixes), err)
	}
}

func TestIntegrationConcurrentRouteCreation(t *testing.T) {
	for _, sameRequest := range []bool{true, false} {
		t.Run(fmt.Sprintf("same_request_%t", sameRequest), func(t *testing.T) {
			database, now := newControlStateIntegrationDatabase(t, "public_url_contention")
			request := builtinRouteRequest(t, database, now)
			request.Ephemeral = !sameRequest
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			workers := newIntegrationWorkers(t, cancel)
			type result struct {
				route PublicURL
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
					route, err := database.CreatePublicURL(ctx, candidate, now)
					results <- result{route, err}
				})
			}
			var winner PublicURL
			successes, conflicts := 0, 0
			for range callers {
				result := awaitIntegrationResult(t, ctx, results)
				switch {
				case result.err == nil:
					successes++
					if winner.ID != "" && !reflect.DeepEqual(result.route, winner) {
						t.Fatalf("concurrent retry changed public_url: %#v", result.route)
					}
					winner = result.route
				case errors.Is(result.err, ErrPublicURLConflict):
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
				if count, err := database.DeleteExpiredEphemeralPublicURLs(ctx, *winner.ExpiresAt); err != nil || count != 1 {
					t.Fatalf("winner expiry = %d, %v", count, err)
				}
			}
		})
	}
}

func TestIntegrationRouteMutationAndExpiredSession(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "public_url_mutation")
	request := builtinRouteRequest(t, database, now)
	route := createTestPublicURL(t, database, request, now)
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.teams SET policy_revision = 2, updated_at = $2 WHERE id = $1`, route.TeamID, now); err != nil {
		t.Fatal(err)
	}
	update := AuthorizedPublicURLUpdateRequest{PublicURLID: route.ID, TeamID: route.TeamID, ActingIdentityID: request.ActingIdentityID,
		Target: "http://127.0.0.1:4000", AllowedIPPrefixes: []string{"192.0.2.0/24"}, PolicyRevision: 2, ExpectedMutationRevision: route.MutationRevision}
	updated, err := database.UpdateAuthorizedPublicURL(t.Context(), update, now)
	if err != nil || updated.Target != update.Target || updated.PolicyRevision != 2 || !reflect.DeepEqual(updated.AllowedIPPrefixes, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}) || updated.TeamID != route.TeamID || updated.DomainID != route.DomainID || updated.MembershipID != route.MembershipID || updated.CanonicalHostname != route.CanonicalHostname || updated.PublicURLScope != route.PublicURLScope {
		t.Fatalf("updated route = %#v, %v", updated, err)
	}
	if _, err := database.UpdateAuthorizedPublicURL(t.Context(), update, now); !errors.Is(err, ErrPublicURLMutationStale) {
		t.Fatalf("stale mutation: %v", err)
	}
	update.ExpectedMutationRevision, update.AllowedIPPrefixes = updated.MutationRevision, []string{"192.0.2.9/24"}
	if _, err := database.UpdateAuthorizedPublicURL(t.Context(), update, now); !errors.Is(err, ErrPublicURLInvalid) {
		t.Fatalf("noncanonical policy: %v", err)
	}
	insertTestPublishRun(t, database, testPublishRun{
		ID: "session_stale_update", PublicURLID: route.ID, TeamID: route.TeamID,
		MembershipID: route.MembershipID, ActingIdentityID: request.ActingIdentityID, PolicyRevision: 2,
		CertificateCacheKey: "stale-update", CertificateScope: "route", CertificateIdentifiers: []string{route.CanonicalHostname},
		ChallengeMethod: "tls-alpn-01", CreatedAt: now, ExpiresAt: now.Add(time.Second),
	})
	update.Target, update.AllowedIPPrefixes = "http://127.0.0.1:5000", []string{}
	updated, err = database.UpdateAuthorizedPublicURL(t.Context(), update, now.Add(2*time.Second))
	if err != nil || updated.Target != update.Target {
		t.Fatalf("update after expiry = %#v, %v", updated, err)
	}
	var state string
	if err := database.pool.QueryRow(t.Context(), `SELECT state FROM control.publish_runs WHERE id = 'session_stale_update'`).Scan(&state); err != nil || state != "expired" {
		t.Fatalf("stale session = %q, %v", state, err)
	}
}

func TestIntegrationEphemeralRouteExpiry(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "ephemeral_expiry")
	request := builtinRouteRequest(t, database, now)
	request.Ephemeral = true
	route, err := database.CreatePublicURL(t.Context(), request, now)
	if err != nil || !route.Ephemeral || route.ExpiresAt == nil || !route.ExpiresAt.Equal(now.Add(ephemeralPublicURLGracePeriod)) {
		t.Fatalf("ephemeral route = %#v, %v", route, err)
	}
	if count, err := database.DeleteExpiredEphemeralPublicURLs(t.Context(), route.ExpiresAt.Add(-time.Microsecond)); err != nil || count != 0 {
		t.Fatalf("early expiry = %d, %v", count, err)
	}
	if count, err := database.DeleteExpiredEphemeralPublicURLs(t.Context(), *route.ExpiresAt); err != nil || count != 1 {
		t.Fatalf("expiry = %d, %v", count, err)
	}
	if _, err := database.GetPublicURL(t.Context(), request.ActingIdentityID, route.ID); !errors.Is(err, ErrPublicURLNotFound) {
		t.Fatalf("expired route read: %v", err)
	}
}

func TestIntegrationDNSPublicURLWork(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "dns_route_work")
	request := builtinRouteRequest(t, database, now)
	request.DNSState = PublicURLDNSPending
	route, err := database.CreatePublicURL(t.Context(), request, now)
	if err != nil || route.DNSState != PublicURLDNSPending || route.DNSAuthorityReference != "" {
		t.Fatalf("DNS route = %#v, %v", route, err)
	}
	work, found, err := database.ClaimDNSPublicURLWork(t.Context(), "dns-worker", now, time.Minute)
	if err != nil || !found || work.PublicURLID != route.ID || work.Attempts != 1 || work.WorkEpoch != 1 {
		t.Fatalf("claim DNS work = %#v, %t, %v", work, found, err)
	}
	if _, found, err := database.ClaimDNSPublicURLWork(t.Context(), "other", now, time.Minute); err != nil || found {
		t.Fatalf("concurrent DNS claim = %t, %v", found, err)
	}
	stale := work
	work.State, work.AvailableAt = PublicURLDNSPublished, time.Time{}
	saved, err := database.SaveDNSPublicURLWork(t.Context(), work, now)
	if err != nil || saved.State != PublicURLDNSPublished || !saved.AvailableAt.IsZero() || saved.DNSRevision != 2 {
		t.Fatalf("published DNS work = %#v, %v", saved, err)
	}
	if _, err := database.SaveDNSPublicURLWork(t.Context(), stale, now); !errors.Is(err, ErrDNSPublicURLWorkStale) {
		t.Fatalf("stale DNS save: %v", err)
	}
	if err := database.DeletePublicURL(t.Context(), request.ActingIdentityID, route.ID, now); err != nil {
		t.Fatal(err)
	}
	removal, found, err := database.ClaimDNSPublicURLWork(t.Context(), "dns-worker", now, time.Minute)
	if err != nil || !found || removal.PublicURLID != route.ID || removal.State != PublicURLDNSRemoving || removal.Attempts != 2 {
		t.Fatalf("DNS removal = %#v, %t, %v", removal, found, err)
	}
	removal.State, removal.AvailableAt = PublicURLDNSRemoved, time.Time{}
	removed, err := database.SaveDNSPublicURLWork(t.Context(), removal, now)
	if err != nil || removed.State != PublicURLDNSRemoved || !removed.AvailableAt.IsZero() {
		t.Fatalf("removed DNS work = %#v, %v", removed, err)
	}
	request.IdempotencyKey, request.RequestDigest, request.Ephemeral = "replacement", sha256.Sum256([]byte("replacement")), true
	ephemeral := createTestPublicURL(t, database, request, now)
	if ephemeral.ExpiresAt == nil {
		t.Fatal("ephemeral replacement has no expiry")
	}
	if count, err := database.DeleteExpiredEphemeralPublicURLs(t.Context(), *ephemeral.ExpiresAt); err != nil || count != 1 {
		t.Fatalf("DNS-managed expiry = %d, %v", count, err)
	}
	var lifecycle, dns string
	if err := database.pool.QueryRow(t.Context(), `SELECT lifecycle_state, dns_state FROM control.public_urls WHERE id = $1`, ephemeral.ID).Scan(&lifecycle, &dns); err != nil || lifecycle != "deleted" || dns != "removing" {
		t.Fatalf("expired DNS route = %s/%s, %v", lifecycle, dns, err)
	}
	removal, found, err = database.ClaimDNSPublicURLWork(t.Context(), "expiry-worker", *ephemeral.ExpiresAt, time.Minute)
	if err != nil || !found || removal.PublicURLID != ephemeral.ID || removal.State != PublicURLDNSRemoving {
		t.Fatalf("expired DNS cleanup = %#v, %t, %v", removal, found, err)
	}
}

func builtinRouteRequest(t *testing.T, database *Database, now time.Time) CreatePublicURLRequest {
	t.Helper()
	session := newBuiltinSession(t, database, now)
	membership := session.Identity.Memberships[0]
	domains, err := database.ListTeamDomains(t.Context(), session.Identity.Identity.ID, membership.TeamID)
	if err != nil || len(domains) != 1 {
		t.Fatalf("managed domain prerequisite: %#v, %v", domains, err)
	}
	return CreatePublicURLRequest{TeamID: membership.TeamID, DomainID: domains[0].ID, MembershipID: membership.ID,
		ActingIdentityID: session.Identity.Identity.ID, IdempotencyKey: "route", RequestDigest: sha256.Sum256([]byte("route")),
		CanonicalHostname: "demo." + membership.ManagedLabel + ".tunnels.example.test", Target: "http://127.0.0.1:3000", PublicURLScope: PublicURLScopeMember, DNSState: PublicURLDNSUnmanaged}
}

func createTestPublicURL(t *testing.T, database *Database, request CreatePublicURLRequest, now time.Time) PublicURL {
	t.Helper()
	route, err := database.CreatePublicURL(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	return route
}
