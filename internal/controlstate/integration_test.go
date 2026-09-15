package controlstate

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/routeusage"
	"github.com/tnldotdev/tnl/internal/testutil"
	"golang.org/x/crypto/acme/autocert"
)

const testStorageKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestIntegrationPostgresMigrationAndOpen(t *testing.T) {
	testURL := newDisposableControlStateDatabaseURL(t, "migration")
	const migrationCallers = 4
	migrationErrors := make(chan error, migrationCallers)
	var migrations sync.WaitGroup
	for range migrationCallers {
		migrations.Add(1)
		go func() {
			defer migrations.Done()
			migrationErrors <- Migrate(t.Context(), testURL)
		}()
	}
	migrations.Wait()
	close(migrationErrors)
	for err := range migrationErrors {
		if err != nil {
			t.Fatalf("concurrent migration: %v", err)
		}
	}
	if err := Migrate(t.Context(), testURL); err != nil {
		t.Fatalf("repeat migration: %v", err)
	}

	database, err := Open(t.Context(), testURL, testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Health(t.Context()); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Readiness(t.Context()); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if database.pool.Config().ConnConfig.DefaultQueryExecMode != pgx.QueryExecModeExec {
		database.Close()
		t.Fatalf("query execution mode = %v, want %v", database.pool.Config().ConnConfig.DefaultQueryExecMode, pgx.QueryExecModeExec)
	}

	for _, table := range []string{
		"identities",
		"oidc_assertion_exchanges",
		"managed_label_reservations",
		"teams",
		"domains",
		"routes",
		"route_sessions",
		"route_session_connections",
		"relay_services",
		"relay_leases",
		"ingress_leases",
		"ingress_routing_table_events",
		"control_tls_cache",
		"relay_certificate_orders",
		"acme_orders",
		"route_usage_buckets",
		"route_recovery_episodes",
		"admin_audit_events",
		"maintenance_controls",
	} {
		var exists bool
		if err := database.pool.QueryRow(t.Context(), `
			SELECT EXISTS (
				SELECT 1
				FROM information_schema.tables
				WHERE table_schema = 'control' AND table_name = $1
			)
		`, table).Scan(&exists); err != nil {
			database.Close()
			t.Fatal(err)
		}
		if !exists {
			database.Close()
			t.Fatalf("control.%s does not exist", table)
		}
	}
	var version int64
	if err := database.pool.QueryRow(t.Context(), `
		SELECT MAX(version_id) FILTER (WHERE is_applied)
		FROM control.goose_db_version
	`).Scan(&version); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if version != schemaVersion {
		database.Close()
		t.Fatalf("schema version = %d, want %d", version, schemaVersion)
	}
	if _, err := database.pool.Exec(t.Context(), `
		INSERT INTO control.goose_db_version (version_id, is_applied)
		VALUES ($1, true)
	`, schemaVersion+1); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Readiness(t.Context()); err == nil {
		database.Close()
		t.Fatal("Readiness succeeded with an incompatible schema version")
	}
	database.Close()

	if incompatible, err := Open(t.Context(), testURL, testStorageKey, ""); err == nil {
		incompatible.Close()
		t.Fatal("Open succeeded with an incompatible schema version")
	}
}

func testDNSAuthorities(t *testing.T, database *Database) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	request := CreateDNSAuthorityRequest{
		TeamID: "team_hosted_dns", DomainID: "domain_hosted_dns", CanonicalDomain: "hosted-dns.example.test",
		IdempotencyKey: "hosted-dns-create", RequestDigest: sha256.Sum256([]byte("hosted-dns-create")),
	}
	authority, err := database.CreateDNSAuthority(t.Context(), request, now)
	if err != nil || authority.State != "pending" || authority.Reference == "" || len(authority.RequiredRecords) != 0 {
		t.Fatalf("created DNS authority = %#v, %v", authority, err)
	}
	repeated, err := database.CreateDNSAuthority(t.Context(), request, now.Add(time.Second))
	if err != nil || !reflect.DeepEqual(repeated, authority) {
		t.Fatalf("repeated DNS authority = %#v, %v", repeated, err)
	}
	changed := request
	changed.RequestDigest = sha256.Sum256([]byte("hosted-dns-create-changed"))
	if _, err := database.CreateDNSAuthority(t.Context(), changed, now.Add(time.Second)); !errors.Is(err, ErrDNSAuthorityIdempotency) {
		t.Fatalf("DNS authority idempotency error = %v", err)
	}
	work, found, err := database.ClaimDNSAuthorityWork(t.Context(), "dns_worker_test", now.Add(2*time.Second), time.Minute)
	if err != nil || !found || work.Reference != authority.Reference || work.WorkEpoch != 1 || work.Attempts != 1 {
		t.Fatalf("claimed DNS authority work = %#v, %v, found %v", work, err, found)
	}
	work.ProviderZoneID = "ZHOSTEDDNS"
	work.Nameservers = []string{"ns-1.example.test", "ns-2.example.test"}
	work.State = "ready"
	work.AvailableAt = now.Add(3 * time.Second)
	staleWork := work
	saved, err := database.SaveDNSAuthorityWork(t.Context(), work, now.Add(3*time.Second))
	if err != nil || saved.State != "ready" || saved.WorkRevision != 2 || len(saved.RequiredRecords) != 2 {
		t.Fatalf("saved DNS authority work = %#v, %v", saved, err)
	}
	if _, err := database.SaveDNSAuthorityWork(t.Context(), staleWork, now.Add(4*time.Second)); !errors.Is(err, ErrDNSAuthorityWorkStale) {
		t.Fatalf("stale DNS authority save error = %v", err)
	}
	released, err := database.ReleaseDNSAuthority(t.Context(), authority.Reference, "hosted-dns-release", now.Add(5*time.Second))
	if err != nil || released.State != "releasing" {
		t.Fatalf("released DNS authority = %#v, %v", released, err)
	}
	repeatedRelease, err := database.ReleaseDNSAuthority(t.Context(), authority.Reference, "hosted-dns-release", now.Add(6*time.Second))
	if err != nil || !reflect.DeepEqual(repeatedRelease, released) {
		t.Fatalf("repeated DNS authority release = %#v, %v", repeatedRelease, err)
	}
	ready, err := database.DNSAuthorityReleaseReady(t.Context(), authority.DomainID, now.Add(7*time.Second))
	if err != nil || !ready {
		t.Fatalf("DNS authority release ready = %v, %v", ready, err)
	}
}

func testAuthorityMutations(t *testing.T, database *Database) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	session, err := database.CreateBuiltinControlSession(
		t.Context(), "tunnels.example.test", 7, time.Hour, 24*time.Hour, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	ownerIdentityID := session.Identity.Identity.ID
	teamRequest := CreateTeamRequest{
		IdentityID: ownerIdentityID, IdempotencyKey: "authority-create-team",
		RequestDigest: sha256.Sum256([]byte("authority-create-team")),
		DisplayName:   "Authority team", MemberSlug: "owner",
	}
	team, err := database.CreateTeam(t.Context(), teamRequest, now)
	if err != nil {
		t.Fatal(err)
	}
	if team.Kind != "organization" || team.PolicyRevision != 1 || team.DefaultDomainID == "" {
		t.Fatalf("created authority team = %#v", team)
	}
	repeatedTeam, err := database.CreateTeam(t.Context(), teamRequest, now.Add(time.Second))
	if err != nil || !reflect.DeepEqual(repeatedTeam, team) {
		t.Fatalf("idempotent authority team = %#v, %v", repeatedTeam, err)
	}
	changedTeam := teamRequest
	changedTeam.RequestDigest = sha256.Sum256([]byte("changed-authority-create-team"))
	if _, err := database.CreateTeam(t.Context(), changedTeam, now.Add(time.Second)); !errors.Is(err, ErrAuthorityIdempotency) {
		t.Fatalf("team idempotency error = %v", err)
	}
	memberships, err := database.ListTeamMemberships(t.Context(), ownerIdentityID, team.ID)
	if err != nil || len(memberships) != 1 || memberships[0].Role != "owner" || memberships[0].MemberSlug != "owner" {
		t.Fatalf("initial authority memberships = %#v, %v", memberships, err)
	}
	ownerMembership := memberships[0]
	if _, err := database.CreateTeamInvitation(t.Context(), CreateInvitationRequest{
		IdentityID: ownerIdentityID, TeamID: session.Identity.PersonalTeamID, IdempotencyKey: "personal-invite",
		RequestDigest: sha256.Sum256([]byte("personal-invite")), MemberSlug: "not-allowed",
		InitialRole: "member", ExpiresAt: now.Add(time.Hour), RetrySecret: bytes.Repeat([]byte{9}, 32),
	}, now); !errors.Is(err, ErrAuthorityAccess) {
		t.Fatalf("personal-team invitation error = %v", err)
	}

	insertAuthorityIdentity(t, database, "identity_authority_member", "member@example.test", true, now)
	insertAuthorityIdentity(t, database, "identity_authority_wrong_email", "other@example.test", true, now)
	invitationRequest := CreateInvitationRequest{
		IdentityID: ownerIdentityID, TeamID: team.ID, IdempotencyKey: "authority-invite-member",
		RequestDigest: sha256.Sum256([]byte("authority-invite-member")), MemberSlug: "member",
		InitialRole: "member", ExpiresAt: now.Add(time.Hour), EmailRestriction: "MEMBER@example.test",
		RetrySecret: bytes.Repeat([]byte{1}, 32),
	}
	firstInvitation, err := database.CreateTeamInvitation(t.Context(), invitationRequest, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	retriedInvitation, err := database.CreateTeamInvitation(t.Context(), invitationRequest, now.Add(3*time.Second))
	if err != nil || retriedInvitation.Invitation.ID != firstInvitation.Invitation.ID ||
		retriedInvitation.Secret != firstInvitation.Secret || retriedInvitation.Invitation.NormalizedEmailRestriction != "member@example.test" {
		t.Fatalf("retried invitation = %#v, %v", retriedInvitation, err)
	}
	if _, err := database.AcceptInvitation(
		t.Context(), "identity_authority_wrong_email", credentials.InvitationToken(retriedInvitation.Secret), now.Add(4*time.Second),
	); !errors.Is(err, ErrAuthorityAccess) {
		t.Fatalf("restricted invitation error = %v", err)
	}
	member, err := database.AcceptInvitation(
		t.Context(), "identity_authority_member", credentials.InvitationToken(retriedInvitation.Secret), now.Add(5*time.Second),
	)
	if err != nil || member.Role != "member" || member.MemberSlug != "member" || member.PolicyRevision != 2 {
		t.Fatalf("accepted membership = %#v, %v", member, err)
	}
	member, err = database.SetMembershipRole(
		t.Context(), ownerIdentityID, team.ID, member.ID, "admin", now.Add(6*time.Second),
	)
	if err != nil || member.Role != "admin" || member.PolicyRevision != 3 {
		t.Fatalf("promoted membership = %#v, %v", member, err)
	}
	if _, err := database.SetMembershipRole(
		t.Context(), member.IdentityID, team.ID, ownerMembership.ID, "member", now.Add(7*time.Second),
	); !errors.Is(err, ErrAuthorityAccess) {
		t.Fatalf("admin owner-demotion error = %v", err)
	}
	if _, err := database.CreateTeamInvitation(t.Context(), CreateInvitationRequest{
		IdentityID: member.IdentityID, TeamID: team.ID, IdempotencyKey: "authority-admin-invite-admin",
		RequestDigest: sha256.Sum256([]byte("authority-admin-invite-admin")), MemberSlug: "another-admin",
		InitialRole: "admin", ExpiresAt: now.Add(time.Hour), RetrySecret: bytes.Repeat([]byte{8}, 32),
	}, now.Add(7*time.Second)); !errors.Is(err, ErrAuthorityAccess) {
		t.Fatalf("admin role-grant invitation error = %v", err)
	}
	if _, err := database.SetMembershipRole(
		t.Context(), ownerIdentityID, team.ID, ownerMembership.ID, "member", now.Add(7*time.Second),
	); !errors.Is(err, ErrAuthorityConflict) {
		t.Fatalf("last-owner demotion error = %v", err)
	}

	insertAuthorityIdentity(t, database, "identity_authority_second", "", false, now)
	secondInvitation, err := database.CreateTeamInvitation(t.Context(), CreateInvitationRequest{
		IdentityID: member.IdentityID, TeamID: team.ID, IdempotencyKey: "authority-invite-second",
		RequestDigest: sha256.Sum256([]byte("authority-invite-second")), MemberSlug: "second",
		InitialRole: "member", ExpiresAt: now.Add(time.Hour), RetrySecret: bytes.Repeat([]byte{2}, 32),
	}, now.Add(8*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	secondMember, err := database.AcceptInvitation(
		t.Context(), "identity_authority_second", credentials.InvitationToken(secondInvitation.Secret), now.Add(9*time.Second),
	)
	if err != nil || secondMember.PolicyRevision != 4 {
		t.Fatalf("second membership = %#v, %v", secondMember, err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		INSERT INTO control.routes (
			id, team_id, domain_id, membership_id, created_by_identity_id, idempotency_key,
			request_digest, canonical_hostname, target, route_scope, policy_revision, ip_policy,
			lifecycle_state, dns_state, created_at, updated_at
		) VALUES (
			'route_authority_member', $1, $2, $3, $4, 'authority-member-route',
			decode(repeat('31', 32), 'hex'), 'second.authority-member.example.test',
			'http://127.0.0.1:3000', 'member', 4, 'allow_all', 'enabled', 'unmanaged', $5, $5
		)
	`, team.ID, team.DefaultDomainID, secondMember.ID, secondMember.IdentityID, now.Add(9*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		INSERT INTO control.route_sessions (
			id, route_id, team_id, membership_id, acting_identity_id, route_version,
			idempotency_key, request_digest, session_token_id, session_token_digest,
			policy_revision, certificate_cache_key, certificate_scope, certificate_identifiers,
			certificate_challenge, state, created_at, last_heartbeat_at, publisher_expires_at
		) VALUES (
			'session_authority_member', 'route_authority_member', $1, $2, $3, 1,
			'authority-member-session', decode(repeat('32', 32), 'hex'), 'authority-member-token',
			decode(repeat('33', 32), 'hex'), 4, 'authority-member-certificate', 'route',
			ARRAY['second.authority-member.example.test'], 'tls-alpn-01', 'starting', $4, $4, $5
		)
	`, team.ID, secondMember.ID, secondMember.IdentityID, now.Add(9*time.Second), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := database.RemoveMembership(
		t.Context(), member.IdentityID, team.ID, secondMember.ID, now.Add(10*time.Second),
	); err != nil {
		t.Fatalf("admin removed ordinary member: %v", err)
	}
	if _, err := database.getMembership(t.Context(), team.ID, secondMember.ID); !errors.Is(err, ErrMembershipNotFound) {
		t.Fatalf("removed membership error = %v", err)
	}
	var routeState, sessionState, closeReason, slugState string
	if err := database.pool.QueryRow(t.Context(), `
		SELECT routes.lifecycle_state, sessions.state, sessions.close_reason, slugs.state
		FROM control.routes AS routes
		JOIN control.route_sessions AS sessions ON sessions.route_id = routes.id
		JOIN control.team_memberships AS memberships ON memberships.id = routes.membership_id
		JOIN control.member_slug_reservations AS slugs ON slugs.id = memberships.slug_reservation_id
		WHERE routes.id = 'route_authority_member'
	`).Scan(&routeState, &sessionState, &closeReason, &slugState); err != nil {
		t.Fatal(err)
	}
	if routeState != "suspended" || sessionState != "closed" || closeReason != "membership_removed" || slugState != "quarantined" {
		t.Fatalf("removed membership runtime state = route %q, session %q/%q, slug %q", routeState, sessionState, closeReason, slugState)
	}
	if _, err := database.CreateTeamInvitation(t.Context(), CreateInvitationRequest{
		IdentityID: ownerIdentityID, TeamID: team.ID, IdempotencyKey: "authority-reuse-accepted-slug",
		RequestDigest: sha256.Sum256([]byte("authority-reuse-accepted-slug")), MemberSlug: "second",
		InitialRole: "member", ExpiresAt: now.Add(time.Hour), RetrySecret: bytes.Repeat([]byte{3}, 32),
	}, now.Add(11*time.Second)); !errors.Is(err, ErrAuthorityConflict) {
		t.Fatalf("accepted slug reuse error = %v", err)
	}

	revoked, err := database.CreateTeamInvitation(t.Context(), CreateInvitationRequest{
		IdentityID: ownerIdentityID, TeamID: team.ID, IdempotencyKey: "authority-revoked-invite",
		RequestDigest: sha256.Sum256([]byte("authority-revoked-invite")), MemberSlug: "reusable",
		InitialRole: "member", ExpiresAt: now.Add(time.Hour), RetrySecret: bytes.Repeat([]byte{4}, 32),
	}, now.Add(12*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := database.RevokeTeamInvitation(
		t.Context(), ownerIdentityID, team.ID, revoked.Invitation.ID, now.Add(13*time.Second),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateTeamInvitation(t.Context(), CreateInvitationRequest{
		IdentityID: ownerIdentityID, TeamID: team.ID, IdempotencyKey: "authority-reused-invite",
		RequestDigest: sha256.Sum256([]byte("authority-reused-invite")), MemberSlug: "reusable",
		InitialRole: "member", ExpiresAt: now.Add(time.Hour), RetrySecret: bytes.Repeat([]byte{5}, 32),
	}, now.Add(14*time.Second)); err != nil {
		t.Fatalf("released pending slug was not reusable: %v", err)
	}

	domainRequest := ClaimDomainRequest{
		IdentityID: ownerIdentityID, TeamID: team.ID, IdempotencyKey: "authority-domain",
		RequestDigest: sha256.Sum256([]byte("authority-domain")), Domain: "authority.example.test", MakeDefault: true,
	}
	domain, err := database.ClaimTeamDomain(t.Context(), domainRequest, now.Add(15*time.Second))
	if err != nil || domain.State != "pending" || domain.DNSAuthorityReference == "" || domain.AuthorityRevision != 6 {
		t.Fatalf("claimed domain = %#v, %v", domain, err)
	}
	repeatedDomain, err := database.ClaimTeamDomain(t.Context(), domainRequest, now.Add(16*time.Second))
	if err != nil || !reflect.DeepEqual(repeatedDomain, domain) {
		t.Fatalf("idempotent domain = %#v, %v", repeatedDomain, err)
	}
	overlap := domainRequest
	overlap.IdempotencyKey = "authority-domain-overlap"
	overlap.RequestDigest = sha256.Sum256([]byte("authority-domain-overlap"))
	overlap.Domain = "child.authority.example.test"
	if _, err := database.ClaimTeamDomain(t.Context(), overlap, now.Add(17*time.Second)); !errors.Is(err, ErrAuthorityConflict) {
		t.Fatalf("overlapping domain error = %v", err)
	}
	if _, err := database.SetTeamDefaultDomain(
		t.Context(), ownerIdentityID, team.ID, domain.ID, now.Add(18*time.Second),
	); !errors.Is(err, ErrAuthorityConflict) {
		t.Fatalf("pending default domain error = %v", err)
	}
	dnsWork, found, err := database.ClaimDNSAuthorityWork(
		t.Context(), "dns_worker_authority", now.Add(19*time.Second), time.Minute,
	)
	if err != nil || !found || dnsWork.Reference != domain.DNSAuthorityReference {
		t.Fatalf("claimed local DNS authority work = %#v, %v, found %v", dnsWork, err, found)
	}
	dnsWork.ProviderZoneID = "ZAUTHORITY"
	dnsWork.Nameservers = []string{"ns-1.example.test", "ns-2.example.test"}
	dnsWork.State = "ready"
	dnsWork.AvailableAt = now.Add(19 * time.Second)
	if _, err := database.SaveDNSAuthorityWork(t.Context(), dnsWork, now.Add(19*time.Second)); err != nil {
		t.Fatalf("save local DNS authority work: %v", err)
	}
	team, err = database.SetTeamDefaultDomain(t.Context(), ownerIdentityID, team.ID, domain.ID, now.Add(20*time.Second))
	if err != nil || team.DefaultDomainID != domain.ID || team.PolicyRevision != 7 {
		t.Fatalf("claimed default domain team = %#v, %v", team, err)
	}
	if err := database.ReleaseTeamDomain(
		t.Context(), ownerIdentityID, team.ID, domain.ID, now.Add(21*time.Second),
	); !errors.Is(err, ErrAuthorityConflict) {
		t.Fatalf("default domain release error = %v", err)
	}
	managedDomains, err := database.ListTeamDomains(t.Context(), ownerIdentityID, team.ID)
	if err != nil || len(managedDomains) != 2 || managedDomains[0].Kind != "managed" {
		t.Fatalf("organization domains before restoring default = %#v, %v", managedDomains, err)
	}
	team, err = database.SetTeamDefaultDomain(
		t.Context(), ownerIdentityID, team.ID, managedDomains[0].ID, now.Add(22*time.Second),
	)
	if err != nil || team.PolicyRevision != 8 {
		t.Fatalf("restored managed default domain team = %#v, %v", team, err)
	}
	if err := database.ReleaseTeamDomain(
		t.Context(), ownerIdentityID, team.ID, domain.ID, now.Add(23*time.Second),
	); err != nil {
		t.Fatal(err)
	}
	if err := database.ReleaseTeamDomain(
		t.Context(), ownerIdentityID, team.ID, domain.ID, now.Add(24*time.Second),
	); err != nil {
		t.Fatalf("idempotent domain release: %v", err)
	}
	domains, err := database.ListTeamDomains(t.Context(), ownerIdentityID, team.ID)
	if err != nil || len(domains) != 2 || domains[1].State != "releasing" || len(domains[1].RequiredRecords) != 2 {
		t.Fatalf("authority domains after release = %#v, %v", domains, err)
	}
}

func insertAuthorityIdentity(
	t *testing.T,
	database *Database,
	identityID, normalizedEmail string,
	emailVerified bool,
	now time.Time,
) {
	t.Helper()
	var email any
	if normalizedEmail != "" {
		email = normalizedEmail
	}
	if _, err := database.pool.Exec(t.Context(), `
		INSERT INTO control.identities (
			id, kind, display_name, normalized_email, email_verified, administrator, created_at, updated_at
		) VALUES ($1, 'oidc', $1, $2, $3, false, $4, $4)
	`, identityID, email, emailVerified, now); err != nil {
		t.Fatal(err)
	}
}

func testControlTLSState(t *testing.T, database *Database) {
	t.Helper()
	cache, err := database.ControlTLSCache("https://acme.example.test/directory")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Get(t.Context(), "control.example.test"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("missing control TLS cache error = %v", err)
	}
	if err := cache.Put(t.Context(), "control.example.test", []byte("certificate state")); err != nil {
		t.Fatal(err)
	}
	var ciphertext []byte
	if err := database.pool.QueryRow(t.Context(), `
		SELECT cache_ciphertext
		FROM control.control_tls_cache
		WHERE directory_url = $1 AND cache_key = $2
	`, "https://acme.example.test/directory", "control.example.test").Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ciphertext, []byte("certificate state")) || bytes.Contains(ciphertext, []byte("certificate state")) {
		t.Fatal("control TLS cache persisted plaintext")
	}
	data, err := cache.Get(t.Context(), "control.example.test")
	if err != nil || string(data) != "certificate state" {
		t.Fatalf("control TLS cache data = %q, %v", data, err)
	}
	if err := cache.Delete(t.Context(), "control.example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Get(t.Context(), "control.example.test"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("deleted control TLS cache error = %v", err)
	}

	firstStarted := make(chan struct{})
	firstRelease := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- database.RunControlTLSLeader(t.Context(), func(context.Context) error {
			close(firstStarted)
			<-firstRelease
			return nil
		})
	}()
	select {
	case <-firstStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("first control TLS leader did not start")
	}
	secondCtx, cancelSecond := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancelSecond()
	secondRan := false
	if err := database.RunControlTLSLeader(secondCtx, func(context.Context) error {
		secondRan = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if secondRan {
		t.Fatal("concurrent control TLS leader ran")
	}
	close(firstRelease)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	thirdRan := false
	if err := database.RunControlTLSLeader(t.Context(), func(context.Context) error {
		thirdRan = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !thirdRan {
		t.Fatal("replacement control TLS leader did not run")
	}

	lostStarted := make(chan struct{})
	lostCanceled := make(chan struct{})
	lostDone := make(chan error, 1)
	go func() {
		lostDone <- database.RunControlTLSLeader(t.Context(), func(ctx context.Context) error {
			close(lostStarted)
			<-ctx.Done()
			close(lostCanceled)
			return nil
		})
	}()
	select {
	case <-lostStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("control TLS leader for connection-loss test did not start")
	}
	if _, err := database.pool.Exec(t.Context(), `
		SELECT pg_terminate_backend(pid)
		FROM pg_locks
		WHERE locktype = 'advisory'
		  AND classid::bigint = $1
		  AND objid::bigint = $2
		  AND objsubid = 1
		  AND granted
		  AND pid <> pg_backend_pid()
	`, controlTLSLeadershipKey>>32, controlTLSLeadershipKey&0xffffffff); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-lostDone:
		if err == nil {
			t.Fatal("control TLS leadership connection loss returned no error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("control TLS leader did not detect connection loss")
	}
	select {
	case <-lostCanceled:
	case <-time.After(time.Second):
		t.Fatal("control TLS callback was not canceled after connection loss")
	}
	afterLossRan := false
	if err := database.RunControlTLSLeader(t.Context(), func(context.Context) error {
		afterLossRan = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !afterLossRan {
		t.Fatal("replacement control TLS leader did not run after connection loss")
	}
}

func testStorageKeyRotation(t *testing.T, database *Database, databaseURL string) {
	t.Helper()
	cache, err := database.ControlTLSCache("https://acme.example.test/rotation")
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Put(t.Context(), "rotation.example.test", []byte("rotation state")); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	relayLease, err := database.RegisterRelay(t.Context(), RelayRegistration{
		RelayServiceID: "relay-rotation", RelayID: "relay-rotation-1", RelayRunID: "relay-run-rotation",
		ProtocolVersion: 1, RelayAddress: "relay-rotation.example.test:443", TLSServerName: "relay-rotation.example.test",
		InternalRelayAddress: "relay-rotation.internal:9445", InternalNetworks: []netip.Prefix{},
		ConnectionCapacity: 10, StreamCapacity: 100,
	}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, privateKeyPEM := testRelayCertificate(t, relayLease.TLSServerName, now)
	if _, err := database.StoreRelayServiceCertificate(
		t.Context(), relayLease.RelayServiceID, relayLease.TLSServerName, certificatePEM, privateKeyPEM, now,
	); err != nil {
		t.Fatal(err)
	}
	var relayPrivateKeyCiphertext []byte
	if err := database.pool.QueryRow(t.Context(), `
		SELECT transport_private_key_ciphertext
		FROM control.relay_services
		WHERE relay_service_id = $1
	`, relayLease.RelayServiceID).Scan(&relayPrivateKeyCiphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(relayPrivateKeyCiphertext, privateKeyPEM) || bytes.Contains(relayPrivateKeyCiphertext, privateKeyPEM) {
		t.Fatal("relay service private key persisted as plaintext")
	}
	var before []byte
	var beforeKeyID string
	if err := database.pool.QueryRow(t.Context(), `
		SELECT cache_ciphertext, cache_storage_key_id
		FROM control.control_tls_cache
		WHERE directory_url = $1 AND cache_key = $2
	`, "https://acme.example.test/rotation", "rotation.example.test").Scan(&before, &beforeKeyID); err != nil {
		t.Fatal(err)
	}
	rotatedKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	rotatedDatabase, err := Open(t.Context(), databaseURL, rotatedKey, testStorageKey)
	if err != nil {
		t.Fatal(err)
	}
	defer rotatedDatabase.Close()
	rotated, err := rotatedDatabase.ReencryptStorageSecrets(t.Context(), 1)
	if err != nil || rotated != 1 {
		t.Fatalf("bounded storage-key rotation = %d, %v", rotated, err)
	}
	if err := rotatedDatabase.CompleteStorageKeyRotation(t.Context()); err != nil {
		t.Fatal(err)
	}
	relayCertificate, err := rotatedDatabase.GetRelayServiceCertificate(t.Context(), relayLease.RelayLeaseIdentity, now)
	if err != nil || relayCertificate.CertificatePEM != string(certificatePEM) || relayCertificate.PrivateKeyPEM != string(privateKeyPEM) {
		t.Fatalf("rotated relay service certificate = %#v, %v", relayCertificate, err)
	}
	staleLease := relayLease.RelayLeaseIdentity
	staleLease.RelayRunID = "relay-run-stale"
	if _, err := rotatedDatabase.GetRelayServiceCertificate(t.Context(), staleLease, now); !errors.Is(err, ErrRelayServiceCertificateLeaseStale) {
		t.Fatalf("stale relay certificate lease error = %v", err)
	}
	rotatedCache, err := rotatedDatabase.ControlTLSCache("https://acme.example.test/rotation")
	if err != nil {
		t.Fatal(err)
	}
	data, err := rotatedCache.Get(t.Context(), "rotation.example.test")
	if err != nil || string(data) != "rotation state" {
		t.Fatalf("rotated control TLS cache data = %q, %v", data, err)
	}
	var after []byte
	var afterKeyID string
	if err := database.pool.QueryRow(t.Context(), `
		SELECT cache_ciphertext, cache_storage_key_id
		FROM control.control_tls_cache
		WHERE directory_url = $1 AND cache_key = $2
	`, "https://acme.example.test/rotation", "rotation.example.test").Scan(&after, &afterKeyID); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("previous-key ciphertext was not re-encrypted")
	}
	if afterKeyID == beforeKeyID {
		t.Fatal("previous storage key ID was not replaced")
	}
	var remaining int
	if err := database.pool.QueryRow(t.Context(), `
		SELECT
			(SELECT count(*) FROM control.control_sessions WHERE retry_secret_storage_key_id = $1) +
			(SELECT count(*) FROM control.acme_accounts WHERE account_key_storage_key_id = $1) +
			(SELECT count(*) FROM control.control_tls_cache WHERE cache_storage_key_id = $1) +
			(SELECT count(*) FROM control.relay_services WHERE transport_private_key_storage_key_id = $1) +
			(SELECT count(*) FROM control.relay_certificate_orders WHERE private_key_storage_key_id = $1) +
			(SELECT count(*) FROM control.runtime_secrets WHERE external_retry_master_key_storage_key_id = $1)
	`, beforeKeyID).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("previous-key rows remaining = %d", remaining)
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.relay_services SET enabled = false WHERE relay_service_id = $1
	`, relayLease.RelayServiceID); err != nil {
		t.Fatal(err)
	}
}

func testRelayCertificateOrderWork(t *testing.T, database *Database) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	account, err := database.EnsureACMEAccount(
		t.Context(), "https://relay-acme.example.test/directory", "relay-operator@example.test", now,
	)
	if err != nil {
		t.Fatal(err)
	}
	account, err = database.UpdateACMEAccountRegistration(
		t.Context(), account.ID, account.ContactEmail, "https://relay-acme.example.test/account/1", "", now,
	)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := database.RegisterRelay(t.Context(), RelayRegistration{
		RelayServiceID: "relay-certificate", RelayID: "relay-certificate-1", RelayRunID: "relay-run-certificate",
		ProtocolVersion: 1, RelayAddress: "relay-certificate.example.test:443", TLSServerName: "relay-certificate.example.test",
		InternalRelayAddress: "relay-certificate.internal:9445", ConnectionCapacity: 10, StreamCapacity: 100,
	}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	created, err := database.PrepareRelayCertificateOrder(t.Context(), account.ID, now, time.Hour)
	if err != nil || !created {
		t.Fatalf("prepare relay certificate order = %v, %v", created, err)
	}
	if created, err := database.PrepareRelayCertificateOrder(t.Context(), account.ID, now, time.Hour); err != nil || created {
		t.Fatalf("duplicate relay certificate order = %v, %v", created, err)
	}
	work, found, err := database.ClaimRelayCertificateOrderWork(t.Context(), "relay-certificate-worker-1", now, 10*time.Millisecond)
	if err != nil || !found || work.State != "pending" || work.Account.AccountURL != account.AccountURL ||
		work.RelayServiceID != lease.RelayServiceID || work.TLSServerName != lease.TLSServerName {
		t.Fatalf("claimed relay certificate order = %#v, %v, %v", work, found, err)
	}
	csr, err := x509.ParseCertificateRequest(work.CSRDER)
	if err != nil || csr.CheckSignature() != nil || !reflect.DeepEqual(csr.DNSNames, []string{lease.TLSServerName}) {
		t.Fatalf("relay certificate CSR = %#v, %v", csr, err)
	}
	var privateKeyCiphertext []byte
	if err := database.pool.QueryRow(t.Context(), `
		SELECT private_key_ciphertext FROM control.relay_certificate_orders WHERE id = $1
	`, work.ID).Scan(&privateKeyCiphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(privateKeyCiphertext, work.PrivateKeyPEM) || bytes.Contains(privateKeyCiphertext, work.PrivateKeyPEM) {
		t.Fatal("relay certificate order persisted its private key as plaintext")
	}
	if other, found, err := database.ClaimRelayCertificateOrderWork(t.Context(), "relay-certificate-worker-2", now, time.Minute); err != nil || found {
		t.Fatalf("concurrent relay certificate claim = %#v, %v, %v", other, found, err)
	}
	recovered, found, err := database.ClaimRelayCertificateOrderWork(
		t.Context(), "relay-certificate-worker-2", now.Add(10*time.Millisecond), time.Minute,
	)
	if err != nil || !found || recovered.ID != work.ID || recovered.WorkEpoch != work.WorkEpoch+1 {
		t.Fatalf("recovered relay certificate order = %#v, %v, %v", recovered, found, err)
	}
	work.AvailableAt = now
	if _, err := database.SaveRelayCertificateOrderWork(t.Context(), work, now.Add(time.Millisecond)); !errors.Is(err, ErrRelayCertificateWorkStale) {
		t.Fatalf("stale relay certificate work error = %v", err)
	}
	recovered.State = "presenting"
	recovered.OrderURL = "https://relay-acme.example.test/order/1"
	recovered.FinalizeURL = "https://relay-acme.example.test/finalize/1"
	recovered.AuthorizationURL = "https://relay-acme.example.test/authorization/1"
	recovered.ChallengeURL = "https://relay-acme.example.test/challenge/1"
	recovered.ChallengeToken = "relay-challenge-token"
	recovered.ChallengeDigest = sha256.Sum256([]byte("relay-challenge"))
	recovered.PresentationReference = "relay_acme_presentation_integration"
	recovered.AvailableAt = now
	saved, err := database.SaveRelayCertificateOrderWork(t.Context(), recovered, now.Add(11*time.Millisecond))
	if err != nil || saved.OrderRevision != recovered.OrderRevision+1 {
		t.Fatalf("saved relay certificate order = %#v, %v", saved, err)
	}
	challenge, err := database.GetRelayDNSChallengeContext(t.Context(), saved.ID)
	if err != nil || challenge.PresentationReference != recovered.PresentationReference || len(challenge.Presentations) != 1 ||
		!challenge.Presentations[0].Active {
		t.Fatalf("relay DNS challenge context = %#v, %v", challenge, err)
	}
	issued, found, err := database.ClaimRelayCertificateOrderWork(t.Context(), "relay-certificate-worker-3", now.Add(12*time.Millisecond), time.Minute)
	if err != nil || !found || issued.ID != work.ID {
		t.Fatalf("claimed relay certificate issuance = %#v, %v, %v", issued, found, err)
	}
	certificatePEM, notBefore, notAfter := issueRelayOrderCertificate(t, issued, now)
	renewAt := notBefore.Add(notAfter.Sub(notBefore) * 2 / 3).UTC()
	issued.State = "cleaning"
	issued.CertificateURL = "https://relay-acme.example.test/certificate/1"
	issued.CertificatePEM = certificatePEM
	issued.NotBefore, issued.NotAfter, issued.RenewAt = &notBefore, &notAfter, &renewAt
	issued.AvailableAt = now
	issued, err = database.SaveRelayCertificateOrderWork(t.Context(), issued, now.Add(13*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	challenge, err = database.GetRelayDNSChallengeContext(t.Context(), issued.ID)
	if err != nil || challenge.Presentations[0].Active {
		t.Fatalf("cleaning relay DNS challenge context = %#v, %v", challenge, err)
	}
	issued, found, err = database.ClaimRelayCertificateOrderWork(t.Context(), "relay-certificate-worker-4", now.Add(14*time.Millisecond), time.Minute)
	if err != nil || !found {
		t.Fatalf("claimed relay certificate cleanup = %#v, %v, %v", issued, found, err)
	}
	issued.State = "complete"
	issued.AvailableAt = renewAt
	completed, err := database.SaveRelayCertificateOrderWork(t.Context(), issued, now.Add(15*time.Millisecond))
	if err != nil || completed.State != "complete" {
		t.Fatalf("completed relay certificate order = %#v, %v", completed, err)
	}
	installed, err := database.GetRelayServiceCertificate(t.Context(), lease.RelayLeaseIdentity, now.Add(16*time.Millisecond))
	if err != nil || installed.CertificatePEM != string(certificatePEM) || installed.PrivateKeyPEM != string(work.PrivateKeyPEM) {
		t.Fatalf("installed relay service certificate = %#v, %v", installed, err)
	}
	if created, err := database.PrepareRelayCertificateOrder(t.Context(), account.ID, now, time.Hour); err != nil || created {
		t.Fatalf("early relay certificate renewal = %v, %v", created, err)
	}
	if created, err := database.PrepareRelayCertificateOrder(t.Context(), account.ID, renewAt, time.Hour); err != nil || !created {
		t.Fatalf("due relay certificate renewal = %v, %v", created, err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.relay_services SET enabled = false WHERE relay_service_id = $1
	`, lease.RelayServiceID); err != nil {
		t.Fatal(err)
	}
}

func issueRelayOrderCertificate(t *testing.T, work RelayCertificateOrderWork, now time.Time) ([]byte, time.Time, time.Time) {
	t.Helper()
	block, remaining := pem.Decode(work.PrivateKeyPEM)
	if block == nil || len(remaining) != 0 || block.Type != "PRIVATE KEY" {
		t.Fatal("relay certificate order private key is invalid PEM")
	}
	value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, ok := value.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("relay certificate order private key is not ECDSA")
	}
	now = now.Truncate(time.Second)
	notBefore, notAfter := now.Add(-time.Minute), now.Add(90*24*time.Hour)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(43), DNSNames: []string{work.TLSServerName}, NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), notBefore, notAfter
}

func testRelayCertificate(t *testing.T, hostname string, now time.Time) ([]byte, []byte) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42), DNSNames: []string{hostname},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
}

func testExternalAuthoritySecret(t *testing.T, database *Database) {
	t.Helper()
	const identityID = "10000000-0000-4000-8000-000000000001"
	first, err := database.EnsureExternalAuthorityPrincipal(t.Context(), identityID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, err := database.EnsureExternalAuthorityPrincipal(t.Context(), identityID, time.Now())
	if err != nil || first != second || first == ([32]byte{}) {
		t.Fatalf("external retry master key = %x, %v", second, err)
	}
	var ciphertext []byte
	if err := database.pool.QueryRow(t.Context(), `
		SELECT external_retry_master_key_ciphertext FROM control.runtime_secrets WHERE singleton = true
	`).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ciphertext, first[:]) || bytes.Contains(ciphertext, first[:]) {
		t.Fatal("external retry master key persisted as plaintext")
	}
}

func testBuiltinAuthentication(t *testing.T, database *Database) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	const callers = 4
	results := make(chan ControlSession, callers)
	exchangeErrors := make(chan error, callers)
	var exchanges sync.WaitGroup
	for range callers {
		exchanges.Add(1)
		go func() {
			defer exchanges.Done()
			result, err := database.CreateBuiltinControlSession(
				t.Context(), "tunnels.example.test", 7, time.Hour, 24*time.Hour, now,
			)
			results <- result
			exchangeErrors <- err
		}()
	}
	exchanges.Wait()
	close(results)
	close(exchangeErrors)
	for err := range exchangeErrors {
		if err != nil {
			t.Fatalf("concurrent builtin authentication: %v", err)
		}
	}
	issued := <-results
	if issued.Identity.Identity.ID == "" || issued.Identity.PersonalTeamID == "" ||
		len(issued.Identity.Memberships) != 1 || issued.Identity.Memberships[0].Role != "owner" {
		t.Fatalf("builtin identity context = %#v", issued.Identity)
	}
	teamRows, err := database.ListTeams(t.Context(), issued.Identity.Identity.ID)
	if err != nil || len(teamRows) != 1 || teamRows[0].ID != issued.Identity.PersonalTeamID || teamRows[0].DefaultDomainID == "" {
		t.Fatalf("builtin teams = %#v, %v", teamRows, err)
	}
	team, err := database.GetTeam(t.Context(), issued.Identity.Identity.ID, issued.Identity.PersonalTeamID)
	if err != nil || team != teamRows[0] {
		t.Fatalf("builtin team = %#v, %v", team, err)
	}
	domainsForTeam, err := database.ListTeamDomains(t.Context(), issued.Identity.Identity.ID, team.ID)
	if err != nil || len(domainsForTeam) != 1 || domainsForTeam[0].CanonicalDomain != "tunnels.example.test" ||
		domainsForTeam[0].ID != team.DefaultDomainID {
		t.Fatalf("builtin team domains = %#v, %v", domainsForTeam, err)
	}
	principal, err := database.AuthenticateAccessToken(t.Context(), issued.AccessToken, 7, now)
	if err != nil || principal.IdentityID != issued.Identity.Identity.ID || !principal.Administrator {
		t.Fatalf("authenticated principal = %#v, %v", principal, err)
	}
	retrySecret := principal.RetrySecret
	var retrySecretCiphertext []byte
	if err := database.pool.QueryRow(t.Context(), `
		SELECT retry_secret_ciphertext FROM control.control_sessions WHERE id = $1
	`, principal.SessionID).Scan(&retrySecretCiphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(retrySecretCiphertext, retrySecret[:]) || bytes.Contains(retrySecretCiphertext, retrySecret[:]) {
		t.Fatal("control-session retry secret persisted as plaintext")
	}
	if _, err := database.AuthenticateAccessToken(t.Context(), issued.AccessToken, 8, now); !errors.Is(err, ErrControlAuthentication) {
		t.Fatalf("stale login source authentication error = %v", err)
	}
	if _, err := database.CreateBuiltinControlSession(
		t.Context(), "other.example.test", 7, time.Hour, 24*time.Hour, now,
	); !errors.Is(err, ErrManagedDomainMismatch) {
		t.Fatalf("managed domain mismatch error = %v", err)
	}

	refreshed, err := database.RefreshControlSession(t.Context(), issued.RefreshToken, 7, time.Hour, now.Add(time.Minute))
	if err != nil || refreshed.SessionID != issued.SessionID || !refreshed.RefreshExpiresAt.Equal(issued.RefreshExpiresAt) {
		t.Fatalf("refreshed control session = %#v, %v", refreshed, err)
	}
	if _, err := database.AuthenticateAccessToken(t.Context(), issued.AccessToken, 7, now.Add(time.Minute)); !errors.Is(err, ErrControlAuthentication) {
		t.Fatalf("rotated access-token error = %v", err)
	}
	if _, err := database.RefreshControlSession(t.Context(), issued.RefreshToken, 7, time.Hour, now.Add(time.Minute)); !errors.Is(err, ErrControlAuthentication) {
		t.Fatalf("rotated refresh-token error = %v", err)
	}
	principal, err = database.AuthenticateAccessToken(t.Context(), refreshed.AccessToken, 7, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if principal.RetrySecret == ([32]byte{}) || principal.RetrySecret != retrySecret {
		t.Fatal("control-session retry secret changed during credential rotation")
	}
	if err := database.RevokeControlSession(t.Context(), principal, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.AuthenticateAccessToken(t.Context(), refreshed.AccessToken, 7, now.Add(2*time.Minute)); !errors.Is(err, ErrControlAuthentication) {
		t.Fatalf("revoked access-token error = %v", err)
	}

	var identities, teams, memberships, domains int
	if err := database.pool.QueryRow(t.Context(), `
		SELECT
			(SELECT count(*) FROM control.identities WHERE kind = 'builtin'),
			(SELECT count(*) FROM control.teams WHERE kind = 'personal'),
			(SELECT count(*) FROM control.team_memberships),
			(SELECT count(*) FROM control.domains WHERE kind = 'managed')
	`).Scan(&identities, &teams, &memberships, &domains); err != nil {
		t.Fatal(err)
	}
	if identities != 1 || teams != 1 || memberships != 1 || domains != 1 {
		t.Fatalf("bootstrap row counts = identities %d, teams %d, memberships %d, domains %d", identities, teams, memberships, domains)
	}
}

func testRouteManagement(t *testing.T, database *Database) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	session, err := database.CreateBuiltinControlSession(
		t.Context(), "tunnels.example.test", 7, time.Hour, 24*time.Hour, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := database.AuthenticateAccessToken(t.Context(), session.AccessToken, 7, now)
	if err != nil {
		t.Fatal(err)
	}
	membership := session.Identity.Memberships[0]
	domains, err := database.ListTeamDomains(t.Context(), principal.IdentityID, membership.TeamID)
	if err != nil || len(domains) != 1 {
		t.Fatalf("route test domains = %#v, %v", domains, err)
	}
	request := CreateRouteRequest{
		TeamID: membership.TeamID, DomainID: domains[0].ID, MembershipID: membership.ID,
		ActingIdentityID: principal.IdentityID, IdempotencyKey: "route-management-create",
		RequestDigest:     sha256.Sum256([]byte("route-management-create")),
		CanonicalHostname: "demo." + membership.ManagedLabel + ".tunnels.example.test",
		Target:            "http://127.0.0.1:3000", RouteScope: "member", DNSState: "unmanaged",
	}
	route, err := database.CreateRoute(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	if route.TeamID != request.TeamID || route.MembershipID != request.MembershipID ||
		route.CanonicalHostname != request.CanonicalHostname || route.PolicyRevision != membership.PolicyRevision ||
		route.NextRouteVersion != 1 || route.LifecycleState != "enabled" {
		t.Fatalf("created route = %#v", route)
	}
	repeated, err := database.CreateRoute(t.Context(), request, now.Add(time.Second))
	if err != nil || !reflect.DeepEqual(repeated, route) {
		t.Fatalf("idempotent route = %#v, %v", repeated, err)
	}
	changed := request
	changed.RequestDigest = sha256.Sum256([]byte("route-management-changed"))
	if _, err := database.CreateRoute(t.Context(), changed, now.Add(2*time.Second)); !errors.Is(err, ErrRouteIdempotency) {
		t.Fatalf("route idempotency error = %v", err)
	}
	conflict := request
	conflict.IdempotencyKey = "route-management-conflict"
	conflict.RequestDigest = sha256.Sum256([]byte("route-management-conflict"))
	if _, err := database.CreateRoute(t.Context(), conflict, now.Add(3*time.Second)); !errors.Is(err, ErrRouteConflict) {
		t.Fatalf("route hostname conflict error = %v", err)
	}
	concurrent := request
	concurrent.IdempotencyKey = "route-management-concurrent"
	concurrent.RequestDigest = sha256.Sum256([]byte("route-management-concurrent"))
	concurrent.CanonicalHostname = "concurrent." + membership.ManagedLabel + ".tunnels.example.test"
	const concurrentCallers = 4
	created := make(chan Route, concurrentCallers)
	creationErrors := make(chan error, concurrentCallers)
	var creations sync.WaitGroup
	for range concurrentCallers {
		creations.Add(1)
		go func() {
			defer creations.Done()
			createdRoute, err := database.CreateRoute(t.Context(), concurrent, now.Add(4*time.Second))
			created <- createdRoute
			creationErrors <- err
		}()
	}
	creations.Wait()
	close(created)
	close(creationErrors)
	for err := range creationErrors {
		if err != nil {
			t.Fatalf("concurrent route creation: %v", err)
		}
	}
	var concurrentRoute Route
	for createdRoute := range created {
		if concurrentRoute.ID == "" {
			concurrentRoute = createdRoute
		} else if !reflect.DeepEqual(createdRoute, concurrentRoute) {
			t.Fatalf("concurrent route = %#v, want %#v", createdRoute, concurrentRoute)
		}
	}
	deeper := request
	deeper.IdempotencyKey = "route-management-deeper"
	deeper.RequestDigest = sha256.Sum256([]byte("route-management-deeper"))
	deeper.CanonicalHostname = "too.deep." + membership.ManagedLabel + ".tunnels.example.test"
	if _, err := database.CreateRoute(t.Context(), deeper, now.Add(5*time.Second)); !errors.Is(err, ErrRouteAccess) {
		t.Fatalf("deep member hostname error = %v", err)
	}
	page, err := database.ListRoutes(t.Context(), principal.IdentityID, membership.TeamID, "")
	if err != nil || len(page.Routes) != 2 || page.NextCursor != "" {
		t.Fatalf("route page = %#v, %v", page, err)
	}
	loaded, err := database.GetRoute(t.Context(), principal.IdentityID, route.ID)
	if err != nil || !reflect.DeepEqual(loaded, route) {
		t.Fatalf("loaded route = %#v, %v", loaded, err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.teams SET policy_revision = 2, updated_at = $2 WHERE id = $1
	`, membership.TeamID, now.Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	updated, err := database.UpdateAuthorizedRoute(t.Context(), AuthorizedRouteUpdateRequest{
		RouteID: route.ID, TeamID: route.TeamID, ActingIdentityID: principal.IdentityID,
		Target: "http://127.0.0.1:4000", AllowedIPPrefixes: []string{"192.0.2.0/24"}, PolicyRevision: 2,
		ExpectedMutationRevision: route.MutationRevision,
	}, now.Add(6*time.Second))
	if err != nil || updated.Target != "http://127.0.0.1:4000" || updated.PolicyRevision != 2 ||
		!reflect.DeepEqual(updated.AllowedIPPrefixes, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}) ||
		updated.TeamID != route.TeamID || updated.DomainID != route.DomainID || updated.MembershipID != route.MembershipID ||
		updated.CanonicalHostname != route.CanonicalHostname || updated.RouteScope != route.RouteScope {
		t.Fatalf("updated route = %#v, %v", updated, err)
	}
	if _, err := database.UpdateAuthorizedRoute(t.Context(), AuthorizedRouteUpdateRequest{
		RouteID: route.ID, TeamID: route.TeamID, ActingIdentityID: principal.IdentityID,
		Target: "http://127.0.0.1:5000", AllowedIPPrefixes: []string{}, PolicyRevision: 2,
		ExpectedMutationRevision: route.MutationRevision,
	}, now.Add(6*time.Second)); !errors.Is(err, ErrRouteMutationStale) {
		t.Fatalf("stale route mutation error = %v", err)
	}
	invalidUpdate := AuthorizedRouteUpdateRequest{
		RouteID: route.ID, TeamID: route.TeamID, ActingIdentityID: principal.IdentityID,
		Target: "http://127.0.0.1:5000", AllowedIPPrefixes: []string{"192.0.2.9/24"}, PolicyRevision: 2,
		ExpectedMutationRevision: updated.MutationRevision,
	}
	if _, err := database.UpdateAuthorizedRoute(t.Context(), invalidUpdate, now.Add(6*time.Second)); !errors.Is(err, ErrRouteInvalid) {
		t.Fatalf("noncanonical route update error = %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		INSERT INTO control.route_sessions (
			id, route_id, team_id, membership_id, acting_identity_id, route_version,
			idempotency_key, request_digest, session_token_id, session_token_digest,
			policy_revision, certificate_cache_key, certificate_scope, certificate_identifiers,
			certificate_challenge, state, created_at, last_heartbeat_at, publisher_expires_at
		) VALUES (
			'session_stale_update', $1, $2, $3, $4, 1,
			'stale-update', decode(repeat('08', 32), 'hex'), 'token_stale_update', decode(repeat('09', 32), 'hex'),
			2, 'stale-update', 'stale-update', ARRAY[$5], 'tls-alpn-01', 'starting', $6, $6, $7
		)
	`, route.ID, route.TeamID, route.MembershipID, principal.IdentityID, route.CanonicalHostname,
		now, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	updated, err = database.UpdateAuthorizedRoute(t.Context(), AuthorizedRouteUpdateRequest{
		RouteID: route.ID, TeamID: route.TeamID, ActingIdentityID: principal.IdentityID,
		Target: "http://127.0.0.1:5000", AllowedIPPrefixes: []string{}, PolicyRevision: 2,
		ExpectedMutationRevision: updated.MutationRevision,
	}, now.Add(2*time.Second))
	if err != nil || updated.Target != "http://127.0.0.1:5000" {
		t.Fatalf("update after stale route session = %#v, %v", updated, err)
	}
	var staleSessionState string
	if err := database.pool.QueryRow(t.Context(), `
		SELECT state FROM control.route_sessions WHERE id = 'session_stale_update'
	`).Scan(&staleSessionState); err != nil || staleSessionState != "expired" {
		t.Fatalf("stale update route session state = %q, %v", staleSessionState, err)
	}
	route = updated
	ephemeralRequest := request
	ephemeralRequest.IdempotencyKey = "route-management-ephemeral"
	ephemeralRequest.RequestDigest = sha256.Sum256([]byte("route-management-ephemeral"))
	ephemeralRequest.CanonicalHostname = "ephemeral." + membership.ManagedLabel + ".tunnels.example.test"
	ephemeralRequest.Ephemeral = true
	ephemeral, err := database.CreateRoute(t.Context(), ephemeralRequest, now.Add(6*time.Second))
	if err != nil || !ephemeral.Ephemeral || ephemeral.ExpiresAt == nil ||
		!ephemeral.ExpiresAt.Equal(now.Add(6*time.Second).Add(ephemeralRouteGracePeriod)) {
		t.Fatalf("ephemeral route = %#v, %v", ephemeral, err)
	}
	if count, err := database.DeleteExpiredEphemeralRoutes(t.Context(), ephemeral.ExpiresAt.Add(-time.Millisecond)); err != nil || count != 0 {
		t.Fatalf("early ephemeral cleanup = %d, %v", count, err)
	}
	if count, err := database.DeleteExpiredEphemeralRoutes(t.Context(), *ephemeral.ExpiresAt); err != nil || count != 1 {
		t.Fatalf("expired ephemeral cleanup = %d, %v", count, err)
	}
	if _, err := database.GetRoute(t.Context(), principal.IdentityID, ephemeral.ID); !errors.Is(err, ErrRouteNotFound) {
		t.Fatalf("expired ephemeral route read error = %v", err)
	}
	contended := ephemeralRequest
	contended.CanonicalHostname = "contended." + membership.ManagedLabel + ".tunnels.example.test"
	const ephemeralContenders = 4
	contentionResults := make(chan Route, ephemeralContenders)
	contentionErrors := make(chan error, ephemeralContenders)
	var contention sync.WaitGroup
	for index := range ephemeralContenders {
		contention.Add(1)
		go func() {
			defer contention.Done()
			candidate := contended
			candidate.IdempotencyKey = fmt.Sprintf("route-management-ephemeral-contention-%d", index)
			candidate.RequestDigest = sha256.Sum256([]byte(candidate.IdempotencyKey))
			createdRoute, err := database.CreateRoute(t.Context(), candidate, now.Add(7*time.Second))
			contentionResults <- createdRoute
			contentionErrors <- err
		}()
	}
	contention.Wait()
	close(contentionResults)
	close(contentionErrors)
	createdCount, conflictCount := 0, 0
	var contendedRoute Route
	for createdRoute := range contentionResults {
		if createdRoute.ID != "" {
			createdCount++
			contendedRoute = createdRoute
		}
	}
	for err := range contentionErrors {
		switch {
		case err == nil:
		case errors.Is(err, ErrRouteConflict):
			conflictCount++
		default:
			t.Fatalf("ephemeral route contention error = %v", err)
		}
	}
	if createdCount != 1 || conflictCount != ephemeralContenders-1 {
		t.Fatalf("ephemeral route contention = %d created, %d conflicts", createdCount, conflictCount)
	}
	if count, err := database.DeleteExpiredEphemeralRoutes(t.Context(), *contendedRoute.ExpiresAt); err != nil || count != 1 {
		t.Fatalf("contended ephemeral route cleanup = %d, %v", count, err)
	}
	if err := database.DeleteRoute(t.Context(), principal.IdentityID, route.ID, now.Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := database.DeleteRoute(t.Context(), principal.IdentityID, concurrentRoute.ID, now.Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.GetRoute(t.Context(), principal.IdentityID, route.ID); !errors.Is(err, ErrRouteNotFound) {
		t.Fatalf("deleted route read error = %v", err)
	}
	if _, err := database.CreateRoute(t.Context(), request, now.Add(7*time.Second)); !errors.Is(err, ErrRouteIdempotency) {
		t.Fatalf("deleted route retry error = %v", err)
	}
}

func testDNSRouteWork(t *testing.T, database *Database) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	session, err := database.CreateBuiltinControlSession(
		t.Context(), "tunnels.example.test", 7, time.Hour, 24*time.Hour, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := database.AuthenticateAccessToken(t.Context(), session.AccessToken, 7, now)
	if err != nil {
		t.Fatal(err)
	}
	membership := session.Identity.Memberships[0]
	domains, err := database.ListTeamDomains(t.Context(), principal.IdentityID, membership.TeamID)
	if err != nil || len(domains) != 1 {
		t.Fatalf("DNS route domains = %#v, %v", domains, err)
	}
	request := CreateRouteRequest{
		TeamID: membership.TeamID, DomainID: domains[0].ID, MembershipID: membership.ID,
		ActingIdentityID: principal.IdentityID, IdempotencyKey: "dns-route-work-create",
		RequestDigest:     sha256.Sum256([]byte("dns-route-work-create")),
		CanonicalHostname: "dns-work." + membership.ManagedLabel + ".tunnels.example.test",
		Target:            "http://127.0.0.1:3000", RouteScope: RouteScopeMember, DNSState: RouteDNSPending,
	}
	route, err := database.CreateRoute(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	if route.DNSState != RouteDNSPending || route.DNSAuthorityReference != "" {
		t.Fatalf("created DNS route = %#v", route)
	}
	work, found, err := database.ClaimDNSRouteWork(t.Context(), "dns_worker_integration", now, time.Minute)
	if err != nil || !found || work.RouteID != route.ID || work.Attempts != 1 || work.WorkEpoch != 1 {
		t.Fatalf("claimed DNS route work = %#v, found %v, error %v", work, found, err)
	}
	if _, found, err := database.ClaimDNSRouteWork(t.Context(), "dns_worker_other", now, time.Minute); err != nil || found {
		t.Fatalf("concurrent DNS route claim = found %v, error %v", found, err)
	}
	stale := work
	work.State = RouteDNSPublished
	work.AvailableAt = time.Time{}
	saved, err := database.SaveDNSRouteWork(t.Context(), work, now.Add(time.Second))
	if err != nil || saved.State != RouteDNSPublished || !saved.AvailableAt.IsZero() || saved.DNSRevision != 2 {
		t.Fatalf("saved published DNS route work = %#v, %v", saved, err)
	}
	if _, err := database.SaveDNSRouteWork(t.Context(), stale, now.Add(2*time.Second)); !errors.Is(err, ErrDNSRouteWorkStale) {
		t.Fatalf("stale DNS route save error = %v", err)
	}
	if err := database.DeleteRoute(t.Context(), principal.IdentityID, route.ID, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	removal, found, err := database.ClaimDNSRouteWork(t.Context(), "dns_worker_integration", now.Add(3*time.Second), time.Minute)
	if err != nil || !found || removal.RouteID != route.ID || removal.State != RouteDNSRemoving || removal.Attempts != 2 {
		t.Fatalf("claimed DNS route removal = %#v, found %v, error %v", removal, found, err)
	}
	removal.State = RouteDNSRemoved
	removal.AvailableAt = time.Time{}
	removed, err := database.SaveDNSRouteWork(t.Context(), removal, now.Add(4*time.Second))
	if err != nil || removed.State != RouteDNSRemoved || !removed.AvailableAt.IsZero() {
		t.Fatalf("saved removed DNS route work = %#v, %v", removed, err)
	}
	replacement := request
	replacement.IdempotencyKey = "dns-route-work-replacement"
	replacement.RequestDigest = sha256.Sum256([]byte("dns-route-work-replacement"))
	replacement.Ephemeral = true
	ephemeral, err := database.CreateRoute(t.Context(), replacement, now.Add(5*time.Second))
	if err != nil {
		t.Fatalf("reuse removed DNS route hostname: %v", err)
	}
	if count, err := database.DeleteExpiredEphemeralRoutes(t.Context(), *ephemeral.ExpiresAt); err != nil || count != 1 {
		t.Fatalf("expired DNS-managed ephemeral route cleanup = %d, %v", count, err)
	}
	var lifecycleState, dnsState string
	if err := database.pool.QueryRow(t.Context(), `
		SELECT lifecycle_state, dns_state FROM control.routes WHERE id = $1
	`, ephemeral.ID).Scan(&lifecycleState, &dnsState); err != nil || lifecycleState != "deleted" || dnsState != "removing" {
		t.Fatalf("expired DNS-managed route state = %q, %q, %v", lifecycleState, dnsState, err)
	}
	removal, found, err = database.ClaimDNSRouteWork(
		t.Context(), "dns_worker_ephemeral", *ephemeral.ExpiresAt, time.Minute,
	)
	if err != nil || !found || removal.RouteID != ephemeral.ID || removal.State != RouteDNSRemoving {
		t.Fatalf("expired ephemeral DNS removal = %#v, found %v, error %v", removal, found, err)
	}
}

func testRouteSessionCreation(t *testing.T, database *Database) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	seedControlRoute(t, database, now, "session")
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.routes SET ephemeral = true, expires_at = $2 WHERE id = $1
	`, "route_session", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	placementLeases := make(map[string]RelayLease, routeSessionConnectionCount)
	for index := range routeSessionConnectionCount {
		name := fmt.Sprintf("placement_%d", index)
		lease, err := database.RegisterRelay(t.Context(), RelayRegistration{
			RelayServiceID: name, RelayID: "relay_" + name, RelayRunID: "run_" + name, ProtocolVersion: 1,
			RelayAddress: name + ".example:443", TLSServerName: name + ".example",
			InternalRelayAddress: name + ".internal:9443", ConnectionCapacity: 10, StreamCapacity: 100,
		}, now, time.Minute)
		if err != nil {
			t.Fatalf("register placement relay %q: %v", name, err)
		}
		placementLeases[name] = lease
	}
	request := RouteSessionRequest{
		RouteID: "route_session", TeamID: "team_session", ActingIdentityID: "identity_session",
		MembershipID: "membership_session", RequireLocalAuthority: true,
		RetrySecret: bytes.Repeat([]byte{7}, 32), IdempotencyKey: "request_session_1",
		RequestDigest: sha256.Sum256([]byte("request-session-1")), PolicyRevision: 1,
		CertificateCacheKey: "certificate_session", CertificateScope: "route",
		CertificateIdentifiers: []string{"route-session.example.test"}, CertificateChallenge: "tls-alpn-01",
		ExpectedMutationRevision: 1,
	}
	setup, err := database.CreateRouteSession(t.Context(), request, now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if setup.RouteID != request.RouteID || setup.RouteVersion != 1 || setup.State != "starting" || setup.RouteSessionToken == "" {
		t.Fatalf("route session setup = %#v", setup)
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.routes SET expires_at = $2 WHERE id = $1
	`, request.RouteID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if count, err := database.DeleteExpiredEphemeralRoutes(t.Context(), now.Add(2*time.Second)); err != nil || count != 0 {
		t.Fatalf("active ephemeral route cleanup = %d, %v", count, err)
	}
	if _, err := database.UpdateAuthorizedRoute(t.Context(), AuthorizedRouteUpdateRequest{
		RouteID: request.RouteID, TeamID: request.TeamID, ActingIdentityID: request.ActingIdentityID,
		Target: "http://127.0.0.1:4000", AllowedIPPrefixes: []string{"192.0.2.0/24"}, PolicyRevision: 1,
		ExpectedMutationRevision: 2,
	}, now.Add(time.Second)); !errors.Is(err, ErrRouteAttached) {
		t.Fatalf("attached route update error = %v", err)
	}
	route, err := database.GetRoute(t.Context(), "identity_session", request.RouteID)
	if err != nil || len(route.AllowedIPPrefixes) != 0 {
		t.Fatalf("route policy = %#v, %v", route.AllowedIPPrefixes, err)
	}
	services := make(map[string]bool)
	for slot, connection := range setup.PublisherConnections {
		if connection.ConnectionSlot != slot || connection.RouteSessionID != setup.RouteSessionID ||
			connection.RouteID != setup.RouteID || connection.RouteVersion != setup.RouteVersion ||
			connection.ConnectionAssignmentRevision != 1 {
			t.Fatalf("publisher connection slot %d = %#v", slot, connection)
		}
		if _, err := credentials.ParsePublisherConnectionCredential(connection.PublisherConnectionCredential); err != nil {
			t.Fatalf("publisher connection slot %d credential: %v", slot, err)
		}
		services[connection.RelayServiceID] = true
	}
	if len(services) != routeSessionConnectionCount {
		t.Fatalf("relay services = %#v", services)
	}
	repeated, err := database.CreateRouteSession(t.Context(), request, now.Add(time.Second), 30*time.Second, time.Minute)
	if err != nil || !reflect.DeepEqual(repeated, setup) {
		t.Fatalf("idempotent route session setup = %#v, %v", repeated, err)
	}
	changed := request
	changed.RequestDigest = sha256.Sum256([]byte("different request"))
	if _, err := database.CreateRouteSession(t.Context(), changed, now.Add(2*time.Second), 30*time.Second, time.Minute); !errors.Is(err, ErrRouteSessionIdempotency) {
		t.Fatalf("idempotency conflict error = %v", err)
	}
	changed = request
	changed.IdempotencyKey = "request_session_2"
	changed.RequestDigest = sha256.Sum256([]byte("request-session-2"))
	changed.ExpectedMutationRevision = 2
	if _, err := database.CreateRouteSession(t.Context(), changed, now.Add(3*time.Second), 30*time.Second, time.Minute); !errors.Is(err, ErrRouteSessionConflict) {
		t.Fatalf("live route session conflict error = %v", err)
	}
	route, err = database.GetRoute(t.Context(), "identity_session", request.RouteID)
	if err != nil || len(route.AllowedIPPrefixes) != 0 {
		t.Fatalf("failed session changed route policy = %#v, %v", route.AllowedIPPrefixes, err)
	}
	staleAuthority := changed
	staleAuthority.PolicyRevision = 2
	if _, err := database.CreateRouteSession(t.Context(), staleAuthority, now.Add(4*time.Second), 30*time.Second, time.Minute); !errors.Is(err, ErrRouteAuthority) {
		t.Fatalf("stale route authority error = %v", err)
	}

	closedAt := now.Add(5 * time.Second)
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.route_sessions SET publisher_expires_at = $2 WHERE id = $1
	`, setup.RouteSessionID, closedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.maintenance_controls
		SET enabled = false, revision = revision + 1, updated_at = $1, updated_by = 'test'
		WHERE control_name = 'route_session_creation'
	`, now.Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	closedSetup := setup
	closedSetup.State = "expired"
	closedSetup.ExpiresAt = closedAt
	for index := range closedSetup.PublisherConnections {
		closedSetup.PublisherConnections[index].State = PublisherConnectionClosed
	}
	retry, err := database.CreateRouteSession(t.Context(), request, now.Add(7*time.Second), 30*time.Second, time.Minute)
	if retry.ClosedAt == nil || !retry.ClosedAt.Equal(closedAt) {
		t.Fatalf("idempotent route session close time = %v, want %v", retry.ClosedAt, closedAt)
	}
	if !retry.ExpiresAt.Equal(closedAt) {
		t.Fatalf("idempotent route session expiry = %v, want %v", retry.ExpiresAt, closedAt)
	}
	retry.ClosedAt = nil
	closedSetup.ExpiresAt = retry.ExpiresAt
	if err != nil || !reflect.DeepEqual(retry, closedSetup) {
		t.Fatalf("gated idempotent retry = %#v, %v", retry, err)
	}
	var closeReason string
	if err := database.pool.QueryRow(t.Context(), `
		SELECT close_reason FROM control.route_sessions WHERE id = $1
	`, setup.RouteSessionID).Scan(&closeReason); err != nil || closeReason != "publisher_expired" {
		t.Fatalf("expired route session close reason = %q, %v", closeReason, err)
	}
	if _, err := database.CreateRouteSession(t.Context(), changed, now.Add(8*time.Second), 30*time.Second, time.Minute); !errors.Is(err, ErrRouteSessionCreationGated) {
		t.Fatalf("gated route session error = %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.maintenance_controls
		SET enabled = true, revision = revision + 1, updated_at = $1, updated_by = 'test'
		WHERE control_name = 'route_session_creation'
	`, now.Add(9*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.relay_leases SET draining = true, drain_deadline = $1
		WHERE relay_service_id LIKE 'placement_%'
	`, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateRouteSession(t.Context(), changed, now.Add(10*time.Second), 30*time.Second, time.Minute); !errors.Is(err, ErrInsufficientRelayServices) {
		t.Fatalf("insufficient placement error = %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.relay_leases SET draining = false, drain_deadline = NULL
		WHERE relay_service_id LIKE 'placement_%'
	`); err != nil {
		t.Fatal(err)
	}
	replacement, err := database.CreateRouteSession(t.Context(), changed, now.Add(11*time.Second), 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.RouteVersion != 2 || replacement.RouteSessionID == setup.RouteSessionID || replacement.RouteSessionToken == setup.RouteSessionToken {
		t.Fatalf("replacement route session = %#v", replacement)
	}
	route, err = database.GetRoute(t.Context(), "identity_session", request.RouteID)
	if err != nil || len(route.AllowedIPPrefixes) != 0 {
		t.Fatalf("replacement route policy = %#v, %v", route.AllowedIPPrefixes, err)
	}
	testRouteSessionReadiness(t, database, request, replacement, placementLeases, now.Add(12*time.Second))
}

func testRouteSessionReadiness(
	t *testing.T,
	database *Database,
	request RouteSessionRequest,
	setup RouteSessionSetup,
	leases map[string]RelayLease,
	now time.Time,
) {
	t.Helper()
	ingressLease, err := database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "ingress_readiness", IngressRunID: "run_readiness", ProtocolVersion: 1,
		ConnectionCapacity: 100,
	}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	authentication := RouteSessionAuthentication{
		RouteSessionID: setup.RouteSessionID, RouteID: setup.RouteID,
		RouteVersion: setup.RouteVersion, RouteSessionToken: setup.RouteSessionToken,
	}
	claims := make([]PublisherConnectionClaimRequest, 0, len(setup.PublisherConnections))
	claimConnection := func(slot int, at time.Time) {
		plan := setup.PublisherConnections[slot]
		digest, err := credentials.ParsePublisherConnectionCredential(plan.PublisherConnectionCredential)
		if err != nil {
			t.Fatal(err)
		}
		lease := leases[plan.RelayServiceID]
		claim := PublisherConnectionClaimRequest{
			ConnectionAssignmentIdentity: plan.ConnectionAssignmentIdentity,
			RelayLeaseIdentity:           lease.RelayLeaseIdentity,
			ClaimID:                      fmt.Sprintf("readiness_claim_%d", slot), CredentialDigest: [32]byte(digest),
		}
		if _, err := database.ClaimPublisherConnection(t.Context(), claim, at); err != nil {
			t.Fatal(err)
		}
		if _, err := database.MarkPublisherConnectionReady(t.Context(), claim, at); err != nil {
			t.Fatal(err)
		}
		claims = append(claims, claim)
	}
	claimConnection(0, now)
	account, err := database.EnsureACMEAccount(
		t.Context(), "https://acme.example.test/directory", "operator@example.test", now,
	)
	if err != nil {
		t.Fatal(err)
	}
	var accountKeyCiphertext []byte
	if err := database.pool.QueryRow(t.Context(), `
		SELECT account_key_ciphertext FROM control.acme_accounts WHERE id = $1
	`, account.ID).Scan(&accountKeyCiphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(accountKeyCiphertext, account.AccountKeyDER) || bytes.Contains(accountKeyCiphertext, account.AccountKeyDER) {
		t.Fatal("ACME account key persisted as plaintext")
	}
	repeatedAccount, err := database.EnsureACMEAccount(
		t.Context(), "https://acme.example.test/directory", "operator@example.test", now.Add(time.Millisecond),
	)
	if err != nil || repeatedAccount.ID != account.ID || !bytes.Equal(repeatedAccount.AccountKeyDER, account.AccountKeyDER) {
		t.Fatalf("idempotent ACME account = %#v, %v", repeatedAccount, err)
	}
	registeredAccount, err := database.UpdateACMEAccountRegistration(
		t.Context(), account.ID, account.ContactEmail, "https://acme.example.test/account/1",
		"https://acme.example.test/terms", now.Add(2*time.Millisecond),
	)
	if err != nil || registeredAccount.AccountURL != "https://acme.example.test/account/1" ||
		registeredAccount.AcceptedTerms != "https://acme.example.test/terms" {
		t.Fatalf("registered ACME account = %#v, %v", registeredAccount, err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(
		rand.Reader, &x509.CertificateRequest{DNSNames: []string{request.CertificateIdentifiers[0]}}, key,
	)
	if err != nil {
		t.Fatal(err)
	}
	issuanceRequest := CreateCertificateIssuanceRequest{
		Authentication: authentication, DirectoryURL: account.DirectoryURL,
		IdempotencyKey: "issuance-readiness", RequestDigest: sha256.Sum256([]byte("issuance-readiness")), CSRDER: csrDER,
	}
	issuance, err := database.CreateCertificateIssuance(t.Context(), issuanceRequest, now)
	if err != nil {
		t.Fatal(err)
	}
	if issuance.State != "pending" || issuance.RouteSessionID != setup.RouteSessionID ||
		issuance.RouteVersion != setup.RouteVersion || !reflect.DeepEqual(issuance.CertificatePlan.Identifiers, request.CertificateIdentifiers) {
		t.Fatalf("certificate issuance = %#v", issuance)
	}
	repeatedIssuance, err := database.CreateCertificateIssuance(t.Context(), issuanceRequest, now.Add(time.Millisecond))
	if err != nil || !reflect.DeepEqual(repeatedIssuance, issuance) {
		t.Fatalf("idempotent certificate issuance = %#v, %v", repeatedIssuance, err)
	}
	changedIssuance := issuanceRequest
	changedIssuance.RequestDigest = sha256.Sum256([]byte("issuance-changed"))
	if _, err := database.CreateCertificateIssuance(t.Context(), changedIssuance, now.Add(2*time.Millisecond)); !errors.Is(err, ErrCertificateIssuanceIdempotency) {
		t.Fatalf("certificate issuance idempotency error = %v", err)
	}
	loadedIssuance, err := database.GetCertificateIssuance(t.Context(), issuance.ID, setup.RouteSessionToken, now)
	if err != nil || !reflect.DeepEqual(loadedIssuance, issuance) {
		t.Fatalf("loaded certificate issuance = %#v, %v", loadedIssuance, err)
	}
	firstWork, found, err := database.ClaimACMEOrderWork(t.Context(), "certificate-worker-1", now.Add(3*time.Millisecond), 10*time.Millisecond)
	if err != nil || !found || firstWork.ID != issuance.ID || firstWork.WorkEpoch != 1 ||
		firstWork.Account.AccountURL != registeredAccount.AccountURL {
		t.Fatalf("first ACME order work = %#v, %v, %v", firstWork, found, err)
	}
	if otherWork, found, err := database.ClaimACMEOrderWork(t.Context(), "certificate-worker-2", now.Add(4*time.Millisecond), time.Minute); err != nil || found {
		t.Fatalf("concurrent ACME order work = %#v, %v, %v", otherWork, found, err)
	}
	recoveredWork, found, err := database.ClaimACMEOrderWork(t.Context(), "certificate-worker-2", now.Add(14*time.Millisecond), time.Minute)
	if err != nil || !found || recoveredWork.ID != issuance.ID || recoveredWork.WorkEpoch != 2 {
		t.Fatalf("recovered ACME order work = %#v, %v, %v", recoveredWork, found, err)
	}
	firstWork.AvailableAt = now
	if _, err := database.SaveACMEOrderWork(t.Context(), firstWork, now.Add(5*time.Millisecond)); !errors.Is(err, ErrACMEWorkStale) {
		t.Fatalf("stale ACME order work error = %v", err)
	}
	recoveredWork.State = "authorizing"
	recoveredWork.AvailableAt = now
	authorizationExpiresAt := now.Add(time.Hour)
	recoveredWork.Authorizations = []ACMEAuthorizationWork{{
		Identifier:       request.CertificateIdentifiers[0],
		AuthorizationURL: "https://acme.example.test/authz/worker",
		ChallengeType:    "tls-alpn-01", ChallengeURL: "https://acme.example.test/challenge/worker",
		ChallengeToken: "challenge-worker", ChallengeDigest: sha256.Sum256([]byte("challenge-worker")),
		State: "presenting", AvailableAt: now, ExpiresAt: &authorizationExpiresAt,
		CreatedAt: now, UpdatedAt: now,
	}}
	savedWork, err := database.SaveACMEOrderWork(t.Context(), recoveredWork, now.Add(15*time.Millisecond))
	if err != nil {
		t.Fatalf("save recovered ACME order work: %v", err)
	}
	if savedWork.OrderRevision != recoveredWork.OrderRevision+1 || len(savedWork.Authorizations) != 1 ||
		!opaqueid.Valid(savedWork.Authorizations[0].ID, "acme_authorization_") || savedWork.Authorizations[0].Revision != 1 {
		t.Fatalf("saved ACME order work = %#v", savedWork)
	}
	if otherWork, found, err := database.ClaimACMEOrderWork(t.Context(), "certificate-worker-3", now.Add(16*time.Millisecond), time.Minute); err != nil || !found {
		t.Fatalf("released ACME order work = %#v, %v, %v", otherWork, found, err)
	} else {
		if _, err := database.pool.Exec(t.Context(), `
			UPDATE control.acme_authorizations
			SET authorization_revision = authorization_revision + 1
			WHERE order_id = $1
		`, issuance.ID); err != nil {
			t.Fatal(err)
		}
		otherWork.AvailableAt = now
		if _, err := database.SaveACMEOrderWork(t.Context(), otherWork, now.Add(17*time.Millisecond)); !errors.Is(err, ErrACMEWorkStale) {
			t.Fatalf("stale ACME authorization work error = %v", err)
		}
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.acme_orders SET work_owner = NULL, work_expires_at = NULL WHERE id = $1
	`, issuance.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		DELETE FROM control.acme_authorizations WHERE order_id = $1
	`, issuance.ID); err != nil {
		t.Fatal(err)
	}
	orderWork, found, err := database.ClaimACMEOrderWork(t.Context(), "certificate-worker-4", now.Add(18*time.Millisecond), time.Minute)
	if err != nil || !found {
		t.Fatalf("order-revision ACME work = %#v, %v, %v", orderWork, found, err)
	}
	expiredLeaseWork := orderWork
	expiredLeaseWork.AvailableAt = now
	if _, err := database.SaveACMEOrderWork(t.Context(), expiredLeaseWork, now.Add(2*time.Minute)); !errors.Is(err, ErrACMEWorkStale) {
		t.Fatalf("expired ACME work lease error = %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.acme_orders SET order_revision = order_revision + 1 WHERE id = $1
	`, issuance.ID); err != nil {
		t.Fatal(err)
	}
	orderWork.AvailableAt = now
	if _, err := database.SaveACMEOrderWork(t.Context(), orderWork, now.Add(19*time.Millisecond)); !errors.Is(err, ErrACMEWorkStale) {
		t.Fatalf("stale ACME order revision error = %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.acme_orders SET work_owner = NULL, work_expires_at = NULL WHERE id = $1
	`, issuance.ID); err != nil {
		t.Fatal(err)
	}
	issuanceID := issuance.ID
	notAfter := now.Add(time.Hour).Truncate(time.Second)
	challengeDigest := sha256.Sum256([]byte("challenge-readiness"))
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.acme_orders SET state = 'authorizing', updated_at = $2 WHERE id = $1
	`, issuanceID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		INSERT INTO control.acme_authorizations (
			id, order_id, identifier, authorization_url, challenge_type,
			challenge_url, challenge_token, challenge_digest, state,
			available_at, expires_at, created_at, updated_at
		) VALUES (
			'authorization_readiness', $1, $2, 'https://acme.example.test/authz/readiness', 'tls-alpn-01',
			'https://acme.example.test/challenge/readiness', 'challenge-readiness', $3, 'presenting',
			$4, $5, $4, $4
		)
	`, issuanceID, request.CertificateIdentifiers[0], challengeDigest[:], now, notAfter); err != nil {
		t.Fatal(err)
	}
	presentedIssuance, err := database.MarkCertificateChallengeReady(t.Context(), issuanceID, setup.RouteSessionToken, now)
	if err != nil || len(presentedIssuance.Challenges) != 1 || presentedIssuance.Challenges[0].Token != "challenge-readiness" {
		t.Fatalf("presented certificate challenge = %#v, %v", presentedIssuance, err)
	}
	if _, err := database.MarkCertificateChallengeReady(t.Context(), issuanceID, setup.RouteSessionToken, now.Add(time.Millisecond)); err != nil {
		t.Fatalf("idempotent certificate challenge ready: %v", err)
	}
	if work, found, err := database.ClaimACMEOrderWork(
		t.Context(), "certificate-worker-before-ingress", now.Add(2*time.Millisecond), time.Minute,
	); err != nil || found {
		t.Fatalf("ACME work before ingress applied challenge = %#v, %v, %v", work, found, err)
	}
	var routingTableRevision int64
	if err := database.pool.QueryRow(t.Context(), `
		SELECT current_revision FROM control.ingress_routing_table_clock WHERE singleton = true
	`).Scan(&routingTableRevision); err != nil {
		t.Fatal(err)
	}
	if _, err := database.RenewIngress(t.Context(), IngressRenewal{
		IngressLeaseIdentity: ingressLease.IngressLeaseIdentity,
		RoutingTableRevision: uint64(routingTableRevision),
	}, now.Add(3*time.Millisecond), time.Minute); err != nil {
		t.Fatal(err)
	}
	work, found, err := database.ClaimACMEOrderWork(
		t.Context(), "certificate-worker-after-ingress", now.Add(4*time.Millisecond), time.Minute,
	)
	if err != nil || !found || work.ID != issuanceID {
		t.Fatalf("ACME work after ingress applied challenge = %#v, %v, %v", work, found, err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.acme_orders SET work_owner = NULL, work_expires_at = NULL WHERE id = $1
	`, issuanceID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.acme_orders SET state = 'failed', last_error = 'terminal failure', updated_at = $2 WHERE id = $1
	`, issuanceID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.acme_authorizations SET state = 'failed', last_error = 'terminal failure', updated_at = $2 WHERE order_id = $1
	`, issuanceID, now); err != nil {
		t.Fatal(err)
	}
	removedIssuance, err := database.MarkCertificateChallengeRemoved(t.Context(), issuanceID, setup.RouteSessionToken, now)
	if err != nil || len(removedIssuance.Challenges) != 0 {
		t.Fatalf("removed failed certificate challenge = %#v, %v", removedIssuance, err)
	}
	if _, err := database.MarkCertificateChallengeRemoved(t.Context(), issuanceID, setup.RouteSessionToken, now.Add(time.Millisecond)); err != nil {
		t.Fatalf("idempotent failed certificate challenge removal: %v", err)
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: request.CertificateIdentifiers,
		NotBefore: now.Truncate(time.Second), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.acme_orders
		SET state = 'waiting_for_install', certificate_pem = $4,
			not_before = $5, not_after = $3, updated_at = $2
		WHERE id = $1
	`, issuanceID, now, notAfter, certificatePEM, certificate.NotBefore); err != nil {
		t.Fatal(err)
	}
	lifecycle, err := database.MarkRouteCertificateInstalled(t.Context(), authentication, issuanceID, notAfter, now)
	if err != nil {
		t.Fatal(err)
	}
	if lifecycle.State != "starting" || lifecycle.CertificateAt == nil || lifecycle.ReadyAt != nil || lifecycle.Routable {
		t.Fatalf("certificate-only lifecycle = %#v", lifecycle)
	}
	if lifecycle.ReadyPublisherConnectionCount != 1 {
		t.Fatalf("certificate lifecycle ready publisher connections = %d, want 1", lifecycle.ReadyPublisherConnectionCount)
	}
	if _, err := database.MarkRouteSessionReady(t.Context(), authentication, now.Add(time.Second)); !errors.Is(err, ErrRouteSessionNotReady) {
		t.Fatalf("early route readiness error = %v", err)
	}
	installedIssuance, err := database.GetCertificateIssuance(t.Context(), issuance.ID, setup.RouteSessionToken, now)
	if err != nil || installedIssuance.State != "installed" {
		t.Fatalf("installed certificate issuance = %#v, %v", installedIssuance, err)
	}
	if _, err := database.MarkRouteCertificateInstalled(
		t.Context(), authentication, "issuance_other", notAfter, now.Add(time.Millisecond),
	); !errors.Is(err, ErrRouteCertificate) {
		t.Fatalf("certificate acknowledgement conflict error = %v", err)
	}

	for slot := 1; slot < len(setup.PublisherConnections); slot++ {
		claimConnection(slot, now.Add(time.Duration(slot)*time.Second))
		lifecycle, err = database.MarkRouteCertificateInstalled(
			t.Context(), authentication, issuanceID, notAfter, now.Add(time.Duration(slot)*time.Second),
		)
		if err != nil {
			t.Fatal(err)
		}
		if slot == 1 {
			lifecycle, err = database.MarkRouteSessionReady(t.Context(), authentication, now.Add(2*time.Second))
			if err != nil {
				t.Fatal(err)
			}
		}
		if slot >= 1 && (lifecycle.ReadyAt == nil || !lifecycle.Routable || lifecycle.ReadyPublisherConnectionCount != slot+1) {
			t.Fatalf("ready lifecycle after slot %d = %#v", slot, lifecycle)
		}
	}

	heartbeatAt := now.Add(3 * time.Second)
	bucketStart := heartbeatAt.Truncate(time.Minute)
	if err := database.ReportIngressUsage(t.Context(), ingressLease.IngressLeaseIdentity, IngressUsageBatch{Reports: []IngressUsageReport{{
		RouteID: setup.RouteID, RouteVersion: setup.RouteVersion, BucketStart: bucketStart,
		BucketEnd: bucketStart.Add(time.Minute), ObservedThrough: heartbeatAt, ReportRevision: 1,
		ConnectionAttempts: 3, PolicyDenials: 3, HistogramData: (routeusage.Checkpoint{}).MarshalBinary(),
	}}}, heartbeatAt); err != nil {
		t.Fatalf("report route policy denials: %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.route_session_connections
		SET publisher_connection_credential_expires_at = $2
		WHERE route_session_id = $1
	`, setup.RouteSessionID, heartbeatAt.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	heartbeat, err := database.HeartbeatRouteSession(t.Context(), authentication, heartbeatAt, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !heartbeat.ExpiresAt.Equal(heartbeatAt.Add(30*time.Second)) || heartbeat.RouteVersion != setup.RouteVersion ||
		heartbeat.PolicyDenials != 3 {
		t.Fatalf("heartbeat setup = %#v", heartbeat)
	}
	renewedRoute, err := database.GetRoute(t.Context(), request.ActingIdentityID, request.RouteID)
	if err != nil || renewedRoute.ExpiresAt == nil ||
		!renewedRoute.ExpiresAt.Equal(heartbeatAt.Add(ephemeralRouteGracePeriod)) {
		t.Fatalf("renewed ephemeral route = %#v, %v", renewedRoute, err)
	}
	earlierHeartbeat, err := database.HeartbeatRouteSession(
		t.Context(), authentication, heartbeatAt.Add(-time.Second), 10*time.Second, time.Minute,
	)
	if err != nil || !earlierHeartbeat.ExpiresAt.Equal(heartbeat.ExpiresAt) {
		t.Fatalf("monotonic route-session heartbeat = %#v, %v", earlierHeartbeat, err)
	}
	monotonicRoute, err := database.GetRoute(t.Context(), request.ActingIdentityID, request.RouteID)
	if err != nil || monotonicRoute.ExpiresAt == nil || !monotonicRoute.ExpiresAt.Equal(*renewedRoute.ExpiresAt) {
		t.Fatalf("monotonic ephemeral expiry = %#v, %v", monotonicRoute, err)
	}
	for slot, connection := range heartbeat.PublisherConnections {
		if connection.PublisherConnectionID != setup.PublisherConnections[slot].PublisherConnectionID ||
			connection.ConnectionAssignmentRevision != setup.PublisherConnections[slot].ConnectionAssignmentRevision ||
			connection.State != PublisherConnectionReady {
			t.Fatalf("established publisher connection slot %d was replaced after credential expiry: %#v", slot, connection)
		}
	}
	snapshot, err := database.ReadIngressRoutingTableSnapshot(
		t.Context(), ingressLease.IngressLeaseIdentity, heartbeatAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.RoutingTableRevision != 4 || len(snapshot.Routes) != 1 ||
		len(snapshot.Routes[0].Projection.PublisherConnections) != routeSessionConnectionCount {
		t.Fatalf("ingress routing-table snapshot = %#v", snapshot)
	}
	firstPage, err := database.ReadIngressRoutingTableEvents(
		t.Context(), ingressLease.IngressLeaseIdentity, 0, 3, heartbeatAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstPage.Events) != 3 || firstPage.NextRevision != 3 || !firstPage.More || firstPage.ResnapshotRequired {
		t.Fatalf("first ingress routing-table page = %#v", firstPage)
	}
	if firstPage.Events[0].Kind != "challenge_upsert" || firstPage.Events[1].Kind != "challenge_tombstone" ||
		firstPage.Events[2].Kind != "route_upsert" {
		t.Fatalf("initial ingress routing-table event kinds = %#v", firstPage.Events)
	}
	secondPage, err := database.ReadIngressRoutingTableEvents(
		t.Context(), ingressLease.IngressLeaseIdentity, firstPage.NextRevision, 3, heartbeatAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(secondPage.Events) != 1 || secondPage.NextRevision != 4 || secondPage.More || secondPage.ResnapshotRequired {
		t.Fatalf("second ingress routing-table page = %#v", secondPage)
	}
	for index := len(claims) - 1; index >= 0; index-- {
		if _, err := database.DisconnectPublisherConnection(
			t.Context(), claims[index], heartbeatAt.Add(time.Duration(len(claims)-index)*time.Second), true,
		); err != nil {
			t.Fatal(err)
		}
	}

	rows, err := database.pool.Query(t.Context(), `
		SELECT event_kind, entry_revision, projection
		FROM control.ingress_routing_table_events
		WHERE route_id = $1 AND route_version = $2
		ORDER BY routing_table_revision
	`, setup.RouteID, setup.RouteVersion)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var events int
	for rows.Next() {
		var eventKind string
		var revision int64
		var payload []byte
		if err := rows.Scan(&eventKind, &revision, &payload); err != nil {
			t.Fatal(err)
		}
		events++
		if revision != int64(events) {
			t.Fatalf("routing-table entry revision = %d, want %d", revision, events)
		}
		var projection IngressRoutingTableProjection
		if err := json.Unmarshal(payload, &projection); err != nil {
			t.Fatal(err)
		}
		if projection.RouteID != setup.RouteID || projection.RouteVersion != setup.RouteVersion ||
			projection.CanonicalHostname != request.CertificateIdentifiers[0] {
			t.Fatalf("ingress routing-table projection = %#v", projection)
		}
		if events == 6 && (eventKind != "route_tombstone" || len(projection.PublisherConnections) != 0) {
			t.Fatalf("final ingress routing-table event = %q, %#v", eventKind, projection)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if events != 6 {
		t.Fatalf("ingress routing-table events = %d, want 6", events)
	}
	emptySnapshot, err := database.ReadIngressRoutingTableSnapshot(
		t.Context(), ingressLease.IngressLeaseIdentity, heartbeatAt.Add(4*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if emptySnapshot.RoutingTableRevision != 6 || len(emptySnapshot.Routes) != 0 {
		t.Fatalf("tombstoned ingress routing-table snapshot = %#v", emptySnapshot)
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.ingress_routing_table_clock
		SET retained_after_revision = 3, updated_at = $1
		WHERE singleton = true
	`, heartbeatAt.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	resnapshot, err := database.ReadIngressRoutingTableEvents(
		t.Context(), ingressLease.IngressLeaseIdentity, 2, 10, heartbeatAt.Add(5*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !resnapshot.ResnapshotRequired || len(resnapshot.Events) != 0 || resnapshot.RetainedAfterRevision != 3 {
		t.Fatalf("retained ingress routing-table page = %#v", resnapshot)
	}
	var episodeID int64
	var episodeOpenedAt time.Time
	if err := database.pool.QueryRow(t.Context(), `
		SELECT episode_id, opened_at FROM control.route_recovery_episodes
		WHERE route_id = $1 AND route_version = $2 AND state = 'open'
	`, setup.RouteID, setup.RouteVersion).Scan(&episodeID, &episodeOpenedAt); err != nil {
		t.Fatal(err)
	}
	replenishAt := heartbeatAt.Add(6 * time.Second)
	replenished, err := database.HeartbeatRouteSession(
		t.Context(), authentication, replenishAt, 30*time.Second, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	for slot, connection := range replenished.PublisherConnections {
		if connection.State != "assigned" ||
			connection.ConnectionAssignmentRevision != setup.PublisherConnections[slot].ConnectionAssignmentRevision+1 ||
			connection.PublisherConnectionID == setup.PublisherConnections[slot].PublisherConnectionID {
			t.Fatalf("replenished publisher connection slot %d = %#v", slot, connection)
		}
	}
	recoveredPlan := replenished.PublisherConnections[0]
	recoveredDigest, err := credentials.ParsePublisherConnectionCredential(recoveredPlan.PublisherConnectionCredential)
	if err != nil {
		t.Fatal(err)
	}
	recoveredClaim := PublisherConnectionClaimRequest{
		ConnectionAssignmentIdentity: recoveredPlan.ConnectionAssignmentIdentity,
		RelayLeaseIdentity:           leases[recoveredPlan.RelayServiceID].RelayLeaseIdentity,
		ClaimID:                      "recovered_claim", CredentialDigest: [32]byte(recoveredDigest),
	}
	if _, err := database.ClaimPublisherConnection(t.Context(), recoveredClaim, replenishAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	recoveredAt := replenishAt.Add(2 * time.Second)
	if _, err := database.MarkPublisherConnectionReady(t.Context(), recoveredClaim, recoveredAt); err != nil {
		t.Fatal(err)
	}
	var recoveredPayload []byte
	if err := database.pool.QueryRow(t.Context(), `
		SELECT projection
		FROM control.ingress_routing_table_events
		WHERE route_id = $1 AND route_version = $2
		ORDER BY routing_table_revision DESC
		LIMIT 1
	`, setup.RouteID, setup.RouteVersion).Scan(&recoveredPayload); err != nil {
		t.Fatal(err)
	}
	var recoveredProjection IngressRoutingTableProjection
	if err := json.Unmarshal(recoveredPayload, &recoveredProjection); err != nil {
		t.Fatal(err)
	}
	if recoveredProjection.RecoveryEpisodeID == nil || *recoveredProjection.RecoveryEpisodeID != uint64(episodeID) ||
		len(recoveredProjection.PublisherConnections) != 1 || recoveredProjection.RouteVersion != setup.RouteVersion {
		t.Fatalf("recovered ingress routing-table projection = %#v", recoveredProjection)
	}
	observedAt := recoveredAt.Add(750 * time.Millisecond)
	wantObservedSeconds := observedAt.Sub(episodeOpenedAt).Seconds()
	observation, err := database.ObserveRouteRecovery(
		t.Context(), ingressLease.IngressLeaseIdentity, setup.RouteID, setup.RouteVersion, uint64(episodeID), observedAt,
	)
	if err != nil || observation.ObservedSeconds != wantObservedSeconds {
		t.Fatalf("recovery observation = %#v, %v", observation, err)
	}
	repeatedObservation, err := database.ObserveRouteRecovery(
		t.Context(), ingressLease.IngressLeaseIdentity, setup.RouteID, setup.RouteVersion,
		uint64(episodeID), observedAt.Add(time.Second),
	)
	if err != nil || !reflect.DeepEqual(repeatedObservation, observation) {
		t.Fatalf("repeated recovery observation = %#v, %v", repeatedObservation, err)
	}
	var count, bucketHalf, bucketOne, bucketTen, bucketInfinite int64
	var sum float64
	if err := database.pool.QueryRow(t.Context(), `
		SELECT observation_count, observation_sum_seconds,
			bucket_le_0_5, bucket_le_1, bucket_le_10, bucket_le_120
		FROM control.route_recovery_histogram
		WHERE singleton = true
	`).Scan(&count, &sum, &bucketHalf, &bucketOne, &bucketTen, &bucketInfinite); err != nil {
		t.Fatal(err)
	}
	if count != 1 || sum != wantObservedSeconds || bucketHalf != 0 || bucketOne != 0 || bucketTen != 1 || bucketInfinite != 1 {
		t.Fatalf("recovery histogram = count %d, sum %f, buckets %d/%d/%d/%d", count, sum, bucketHalf, bucketOne, bucketTen, bucketInfinite)
	}
	dnsOrderID := "issuance_dns_cleanup"
	dnsWorkAt := observedAt.Add(time.Second)
	dnsRequestDigest := sha256.Sum256([]byte("dns-cleanup-request"))
	dnsCSRDigest := sha256.Sum256([]byte("dns-cleanup-csr"))
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.domains SET canonical_domain = $2, updated_at = $3 WHERE id = $1
	`, "domain_session", request.CertificateIdentifiers[0], dnsWorkAt); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		INSERT INTO control.acme_orders (
			id, account_id, route_session_id, route_id, route_version, idempotency_key, request_digest,
			certificate_cache_key, certificate_scope, certificate_identifiers, challenge_method,
			csr_der, csr_digest, state, available_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, 'dns-cleanup', $6, $7, $8, $9, 'dns-01', $10, $11, 'pending', $12, $12, $12)
	`, dnsOrderID, registeredAccount.ID, setup.RouteSessionID, setup.RouteID, setup.RouteVersion,
		dnsRequestDigest[:], request.CertificateCacheKey, request.CertificateScope, request.CertificateIdentifiers,
		csrDER, dnsCSRDigest[:], dnsWorkAt); err != nil {
		t.Fatal(err)
	}
	dnsWork, found, err := database.ClaimACMEOrderWork(t.Context(), "certificate-worker-dns", dnsWorkAt, time.Minute)
	if err != nil || !found || dnsWork.ID != dnsOrderID {
		t.Fatalf("claimed DNS certificate work = %#v, found %v, error %v", dnsWork, found, err)
	}
	dnsWork.State = "authorizing"
	dnsWork.AvailableAt = dnsWorkAt
	dnsAuthorizationExpiresAt := dnsWorkAt.Add(time.Hour)
	dnsWork.Authorizations = []ACMEAuthorizationWork{{
		Identifier: request.CertificateIdentifiers[0], AuthorizationURL: "https://acme.example.test/authz/dns-cleanup",
		ChallengeType: "dns-01", ChallengeURL: "https://acme.example.test/challenge/dns-cleanup",
		ChallengeToken: "dns-cleanup", ChallengeDigest: sha256.Sum256([]byte("dns-cleanup")),
		State: "presenting", AvailableAt: dnsWorkAt, ExpiresAt: &dnsAuthorizationExpiresAt,
		CreatedAt: dnsWorkAt, UpdatedAt: dnsWorkAt,
	}}
	dnsWork, err = database.SaveACMEOrderWork(t.Context(), dnsWork, dnsWorkAt.Add(time.Millisecond))
	if err != nil || len(dnsWork.Authorizations) != 1 ||
		!opaqueid.Valid(dnsWork.Authorizations[0].PresentationReference, "acme_presentation_") {
		t.Fatalf("saved DNS certificate work = %#v, %v", dnsWork, err)
	}
	dnsContext, err := database.GetDNSChallengeContext(t.Context(), setup.RouteID, dnsWork.Authorizations[0].ID)
	if err != nil || len(dnsContext.Presentations) != 1 || !dnsContext.Presentations[0].Active ||
		dnsContext.PresentationReference != dnsWork.Authorizations[0].PresentationReference {
		t.Fatalf("DNS challenge context = %#v, %v", dnsContext, err)
	}
	wrongToken, _, _, err := credentials.NewRouteSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := database.CloseRouteSession(t.Context(), setup.RouteSessionID, wrongToken, observedAt.Add(2*time.Second)); !errors.Is(err, ErrRouteSessionCredential) {
		t.Fatalf("wrong close credential error = %v", err)
	}
	if err := database.CloseRouteSession(t.Context(), setup.RouteSessionID, setup.RouteSessionToken, observedAt.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	dnsCleanupWork, found, err := database.ClaimACMEOrderWork(
		t.Context(), "certificate-worker-dns-cleanup", observedAt.Add(3*time.Second), time.Minute,
	)
	if err != nil || !found || dnsCleanupWork.ID != dnsOrderID || dnsCleanupWork.State != "canceled" ||
		len(dnsCleanupWork.Authorizations) != 1 || dnsCleanupWork.Authorizations[0].State != "cleaning" {
		t.Fatalf("claimed canceled DNS cleanup = %#v, found %v, error %v", dnsCleanupWork, found, err)
	}
	dnsContext, err = database.GetDNSChallengeContext(t.Context(), setup.RouteID, dnsCleanupWork.Authorizations[0].ID)
	if err != nil || dnsContext.Presentations[0].Active {
		t.Fatalf("cleaning DNS challenge context = %#v, %v", dnsContext, err)
	}
	dnsCleanupWork.Authorizations[0].State = "complete"
	dnsCleanupCompletedAt := observedAt.Add(3500 * time.Millisecond)
	dnsCleanupWork.Authorizations[0].CleanupCompletedAt = &dnsCleanupCompletedAt
	dnsCleanupWork.Authorizations[0].AvailableAt = dnsCleanupCompletedAt
	dnsCleanupWork.AvailableAt = dnsCleanupCompletedAt
	if _, err := database.SaveACMEOrderWork(t.Context(), dnsCleanupWork, dnsCleanupCompletedAt); err != nil {
		t.Fatalf("complete canceled DNS cleanup: %v", err)
	}
	if err := database.CloseRouteSession(t.Context(), setup.RouteSessionID, setup.RouteSessionToken, observedAt.Add(4*time.Second)); err != nil {
		t.Fatalf("idempotent route session close: %v", err)
	}
	if remaining, found, err := database.ClaimACMEOrderWork(
		t.Context(), "certificate-worker-dns-complete", observedAt.Add(4500*time.Millisecond), time.Minute,
	); err != nil || found {
		t.Fatalf("completed canceled DNS cleanup = %#v, found %v, error %v", remaining, found, err)
	}
	usageCompleteAt := observedAt.Add(4 * time.Second)
	if err := database.ReportIngressUsage(t.Context(), ingressLease.IngressLeaseIdentity, IngressUsageBatch{
		ObservedThrough: &usageCompleteAt, Complete: true,
	}, usageCompleteAt); err != nil {
		t.Fatalf("complete readiness ingress usage: %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		DELETE FROM control.route_usage_buckets
		WHERE route_id = $1 AND route_version = $2
	`, setup.RouteID, setup.RouteVersion); err != nil {
		t.Fatalf("clean readiness usage bucket: %v", err)
	}
}

func seedControlRoute(
	t *testing.T,
	database *Database,
	now time.Time,
	suffix string,
) {
	t.Helper()
	identityID := "identity_" + suffix
	teamID := "team_" + suffix
	reservationID := "reservation_" + suffix
	membershipID := "membership_" + suffix
	domainID := "domain_" + suffix
	routeID := "route_" + suffix
	hostname := "route-" + suffix + ".example.test"
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO control.identities (
			id, kind, display_name, administrator, created_at, updated_at
		) VALUES ($2, 'authority', 'Test identity', true, $1, $1)`, []any{now, identityID}},
		{`INSERT INTO control.managed_label_reservations (label, created_at)
		VALUES ($2, $1), ($3, $1)`, []any{now, "team-" + suffix, "member-" + suffix}},
		{`INSERT INTO control.teams (
			id, kind, display_name, managed_label, created_by_identity_id, created_at, updated_at
		) VALUES ($2, 'personal', 'Team', $3, $4, $1, $1)`, []any{now, teamID, "team-" + suffix, identityID}},
		{`INSERT INTO control.member_slug_reservations (
			id, team_id, member_slug, state, reserved_by_identity_id, created_at, activated_at
		) VALUES ($2, $3, $4, 'active', $5, $1, $1)`, []any{now, reservationID, teamID, "member-" + suffix, identityID}},
		{`INSERT INTO control.team_memberships (
			id, team_id, identity_id, slug_reservation_id, managed_label, role, authority_revision, created_at, updated_at
		) VALUES ($2, $3, $4, $5, $6, 'owner', 1, $1, $1)`, []any{now, membershipID, teamID, identityID, reservationID, "member-" + suffix}},
		{`INSERT INTO control.domains (
			id, kind, team_id, canonical_domain, state, authority_revision,
			created_by_identity_id, created_at, verified_at, updated_at
		) VALUES ($2, 'claimed', $3, $4, 'ready', 1, $5, $1, $1, $1)`,
			[]any{now, domainID, teamID, suffix + ".example.test", identityID}},
		{`UPDATE control.teams SET default_domain_id = $1 WHERE id = $2`, []any{domainID, teamID}},
		{`INSERT INTO control.routes (
			id, team_id, domain_id, created_by_identity_id, idempotency_key, request_digest, canonical_hostname,
			target, route_scope, policy_revision,
			ip_policy, lifecycle_state, dns_state, created_at, updated_at
		) VALUES (
			$2, $3, $4, $5, 'seed', decode(repeat('00', 32), 'hex'), $6,
			'http://127.0.0.1:3000', 'shared', 1,
			'allow_all', 'enabled', 'published', $1, $1
		)`, []any{now, routeID, teamID, domainID, identityID, hostname}},
	} {
		if _, err := database.pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
}

func testIngressUsage(t *testing.T, database *Database) {
	t.Helper()
	base := time.Now().UTC().Truncate(time.Minute)
	seedControlRoute(t, database, base, "usage")
	if _, err := database.pool.Exec(t.Context(), `
		INSERT INTO control.route_sessions (
			id, route_id, team_id, acting_identity_id, route_version,
			idempotency_key, request_digest, session_token_id, session_token_digest,
			policy_revision, certificate_cache_key, certificate_scope,
			certificate_identifiers, certificate_challenge, state,
			created_at, last_heartbeat_at, publisher_expires_at
		) VALUES (
			'session_usage', 'route_usage', 'team_usage', 'identity_usage', 1,
			'usage', decode(repeat('01', 32), 'hex'), 'token_usage', decode(repeat('02', 32), 'hex'),
			1, 'usage', 'usage', ARRAY['route-usage.example.test'], 'dns-01', 'starting',
			$1, $1, $2
		)
	`, base, base.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	lease, err := database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "ingress_usage", IngressRunID: "run_usage", ProtocolVersion: 1, ConnectionCapacity: 10,
	}, base, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	assertUsageRun := func(ingressID, runID string, wantObserved, wantExpiry time.Time, wantComplete bool) {
		t.Helper()
		var observedThrough, leaseExpiresAt time.Time
		var complete bool
		if err := database.pool.QueryRow(t.Context(), `
			SELECT observed_through, lease_expires_at, coverage_complete
			FROM control.ingress_usage_runs
			WHERE ingress_id = $1 AND ingress_run_id = $2
		`, ingressID, runID).Scan(&observedThrough, &leaseExpiresAt, &complete); err != nil {
			t.Fatal(err)
		}
		if !observedThrough.Equal(wantObserved) || !leaseExpiresAt.Equal(wantExpiry) || complete != wantComplete {
			t.Fatalf("usage run = observed %v, expiry %v, complete %v", observedThrough, leaseExpiresAt, complete)
		}
	}
	assertUsageRun("ingress_usage", "run_usage", base, base.Add(time.Minute), false)

	observedThrough := base.Add(20 * time.Second)
	report := IngressUsageReport{
		RouteID: "route_usage", RouteVersion: 1, BucketStart: base, BucketEnd: base.Add(time.Minute),
		ObservedThrough: observedThrough, ReportRevision: 1, ConnectionAttempts: 2,
		PolicyDenials: 1, HistogramData: (routeusage.Checkpoint{}).MarshalBinary(),
	}
	batch := IngressUsageBatch{Reports: []IngressUsageReport{report}, ObservedThrough: &observedThrough}
	if err := database.ReportIngressUsage(t.Context(), lease.IngressLeaseIdentity, batch, base.Add(21*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := database.ReportIngressUsage(t.Context(), lease.IngressLeaseIdentity, batch, base.Add(22*time.Second)); err != nil {
		t.Fatalf("exact usage replay: %v", err)
	}
	assertUsageRun("ingress_usage", "run_usage", observedThrough, base.Add(time.Minute), false)

	report.ReportRevision = 2
	report.Final = true
	report.ConnectionAttempts = 3
	report.PolicyDenials = 3
	completeAt := base.Add(30 * time.Second)
	report.ObservedThrough = completeAt
	complete := IngressUsageBatch{
		Reports: []IngressUsageReport{report}, ObservedThrough: &completeAt, Complete: true,
	}
	if err := database.ReportIngressUsage(t.Context(), lease.IngressLeaseIdentity, complete, base.Add(31*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := database.ReportIngressUsage(t.Context(), lease.IngressLeaseIdentity, complete, base.Add(32*time.Second)); err != nil {
		t.Fatalf("exact completed usage replay: %v", err)
	}
	assertUsageRun("ingress_usage", "run_usage", completeAt, base.Add(time.Minute), true)
	var policyDenials int64
	if err := database.pool.QueryRow(t.Context(), `
		SELECT policy_denials FROM control.route_sessions WHERE id = 'session_usage'
	`).Scan(&policyDenials); err != nil || policyDenials != 3 {
		t.Fatalf("route-session policy denials = %d, %v", policyDenials, err)
	}
	if err := database.ReportIngressUsage(t.Context(), lease.IngressLeaseIdentity, IngressUsageBatch{
		ObservedThrough: &completeAt,
	}, base.Add(33*time.Second)); !errors.Is(err, ErrIngressUsageReportStale) {
		t.Fatalf("post-completion usage error = %v", err)
	}

	var attempts int64
	var bucketObserved time.Time
	if err := database.pool.QueryRow(t.Context(), `
		SELECT connection_attempts, observed_through
		FROM control.route_usage_buckets
		WHERE route_id = 'route_usage' AND route_version = 1 AND bucket_start = $1
	`, base).Scan(&attempts, &bucketObserved); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 || !bucketObserved.Equal(completeAt) {
		t.Fatalf("usage bucket = attempts %d, observed %v", attempts, bucketObserved)
	}

	idleLease, err := database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "ingress_usage_idle", IngressRunID: "run_usage_idle", ProtocolVersion: 1, ConnectionCapacity: 10,
	}, base, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	idleLease, err = database.RenewIngress(t.Context(), IngressRenewal{
		IngressLeaseIdentity: idleLease.IngressLeaseIdentity,
	}, base.Add(10*time.Second), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	assertUsageRun("ingress_usage_idle", "run_usage_idle", base, base.Add(40*time.Second), false)
	if finalized, err := database.FinalizeRouteUsageBuckets(t.Context(), base.Add(time.Minute), base.Add(time.Minute)); err != nil || finalized != 0 {
		t.Fatalf("premature usage finalization = %#v, %v", finalized, err)
	}
	if count, err := database.MarkExpiredIngressUsageRunsIncomplete(t.Context(), base.Add(61*time.Second)); err != nil || count < 1 {
		t.Fatalf("expired usage runs = %d, %v", count, err)
	}
	var incompleteFrom, incompleteUntil time.Time
	if err := database.pool.QueryRow(t.Context(), `
		SELECT incomplete_from, incomplete_until
		FROM control.ingress_usage_runs
		WHERE ingress_id = 'ingress_usage_idle' AND ingress_run_id = 'run_usage_idle'
	`).Scan(&incompleteFrom, &incompleteUntil); err != nil {
		t.Fatal(err)
	}
	if !incompleteFrom.Equal(base) || !incompleteUntil.Equal(base.Add(40*time.Second)) {
		t.Fatalf("incomplete usage interval = %v through %v", incompleteFrom, incompleteUntil)
	}
	finalized, err := database.FinalizeRouteUsageBuckets(t.Context(), base.Add(time.Minute), base.Add(62*time.Second))
	if err != nil || finalized != 1 {
		t.Fatalf("usage finalization = %#v, %v", finalized, err)
	}
	claimedAt := base.Add(63 * time.Second)
	firstClaim, err := database.ClaimRouteUsageDeliveries(
		t.Context(), "usage_worker_first", 32, claimedAt, 10*time.Second,
	)
	if err != nil || len(firstClaim) != 1 {
		t.Fatalf("first usage delivery claim = %#v, %v", firstClaim, err)
	}
	firstWork := firstClaim[0]
	if firstWork.DeliveryKey == "" || firstWork.Attempts != 1 || firstWork.WorkEpoch != 1 ||
		firstWork.TeamID != "team_usage" || firstWork.ActingIdentityID != "identity_usage" ||
		firstWork.ConnectionAttempts != 3 || firstWork.Complete || firstWork.Checkpoint.VisitorNetworks.Estimate() != 0 {
		t.Fatalf("first usage delivery work = %#v", firstWork)
	}
	if concurrent, err := database.ClaimRouteUsageDeliveries(
		t.Context(), "usage_worker_concurrent", 32, claimedAt.Add(time.Second), time.Minute,
	); err != nil || len(concurrent) != 0 {
		t.Fatalf("concurrent usage delivery claim = %#v, %v", concurrent, err)
	}
	reclaimedAt := claimedAt.Add(11 * time.Second)
	reclaimed, err := database.ClaimRouteUsageDeliveries(
		t.Context(), "usage_worker_reclaimed", 32, reclaimedAt, 10*time.Second,
	)
	if err != nil || len(reclaimed) != 1 || reclaimed[0].WorkEpoch != 2 || reclaimed[0].Attempts != 2 {
		t.Fatalf("reclaimed usage delivery = %#v, %v", reclaimed, err)
	}
	if err := database.CompleteRouteUsageDelivery(t.Context(), firstWork, reclaimedAt); !errors.Is(err, ErrRouteUsageDeliveryWorkStale) {
		t.Fatalf("stale usage delivery completion error = %v", err)
	}
	retryAt := reclaimedAt.Add(5 * time.Second)
	if err := database.RetryRouteUsageDelivery(
		t.Context(), reclaimed[0], retryAt, "receiver unavailable", reclaimedAt.Add(time.Second),
	); err != nil {
		t.Fatalf("retry usage delivery: %v", err)
	}
	if unavailable, err := database.ClaimRouteUsageDeliveries(
		t.Context(), "usage_worker_early", 32, retryAt.Add(-time.Millisecond), time.Minute,
	); err != nil || len(unavailable) != 0 {
		t.Fatalf("early usage delivery claim = %#v, %v", unavailable, err)
	}
	replayed, err := database.ClaimRouteUsageDeliveries(
		t.Context(), "usage_worker_replay", 32, retryAt, time.Minute,
	)
	if err != nil || len(replayed) != 1 || replayed[0].WorkEpoch != 3 || replayed[0].Attempts != 3 {
		t.Fatalf("replayed usage delivery = %#v, %v", replayed, err)
	}
	replayedWork := replayed[0]
	if replayedWork.DeliveryKey != firstWork.DeliveryKey || replayedWork.SourceRevision != firstWork.SourceRevision ||
		replayedWork.RouteID != firstWork.RouteID || replayedWork.RouteVersion != firstWork.RouteVersion ||
		replayedWork.TeamID != firstWork.TeamID || replayedWork.ActingIdentityID != firstWork.ActingIdentityID ||
		!replayedWork.BucketStart.Equal(firstWork.BucketStart) || !replayedWork.BucketEnd.Equal(firstWork.BucketEnd) ||
		!replayedWork.ObservedThrough.Equal(firstWork.ObservedThrough) ||
		replayedWork.ConnectionAttempts != firstWork.ConnectionAttempts ||
		!bytes.Equal(replayedWork.Checkpoint.MarshalBinary(), firstWork.Checkpoint.MarshalBinary()) {
		t.Fatalf("usage delivery payload changed: first %#v, replay %#v", firstWork, replayedWork)
	}
	completedAt := retryAt.Add(time.Second)
	if err := database.CompleteRouteUsageDelivery(t.Context(), replayedWork, completedAt); err != nil {
		t.Fatalf("complete usage delivery: %v", err)
	}
	if remaining, err := database.ClaimRouteUsageDeliveries(
		t.Context(), "usage_worker_done", 32, completedAt.Add(time.Hour), time.Minute,
	); err != nil || len(remaining) != 0 {
		t.Fatalf("completed usage delivery claim = %#v, %v", remaining, err)
	}
}

func testRelayControlState(t *testing.T, database *Database) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	leaseDuration := 30 * time.Second
	registration := RelayRegistration{
		RelayServiceID: "relay_service_a", RelayID: "relay_a", RelayRunID: "run_a", ProtocolVersion: 1,
		RelayAddress: "relay-a.example:443", TLSServerName: "relay-a.example",
		InternalRelayAddress: "relay-a.internal:9443", ConnectionCapacity: 2, StreamCapacity: 100,
	}
	lease, err := database.RegisterRelay(t.Context(), registration, now, leaseDuration)
	if err != nil {
		t.Fatal(err)
	}
	if lease.RelayLeaseRevision != 1 || lease.RelayID != registration.RelayID ||
		!lease.LeaseExpiresAt.Equal(now.Add(leaseDuration)) {
		t.Fatalf("first relay lease = %#v", lease)
	}
	repeated, err := database.RegisterRelay(t.Context(), registration, now.Add(time.Second), leaseDuration)
	if err != nil {
		t.Fatal(err)
	}
	if repeated.RelayLeaseRevision != lease.RelayLeaseRevision || !repeated.RegisteredAt.Equal(now) {
		t.Fatalf("repeated relay lease = %#v", repeated)
	}
	conflict := registration
	conflict.RelayRunID = "run_conflict"
	if _, err := database.RegisterRelay(t.Context(), conflict, now.Add(2*time.Second), leaseDuration); !errors.Is(err, ErrRelayRegistrationConflict) {
		t.Fatalf("live relay process conflict error = %v", err)
	}

	renewed, err := database.RenewRelay(t.Context(), RelayRenewal{
		RelayLeaseIdentity: lease.RelayLeaseIdentity, ReportedConnections: 1, ReportedStreams: 2,
	}, now.Add(3*time.Second), leaseDuration)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.ReportedConnections != 1 || renewed.ReportedStreams != 2 {
		t.Fatalf("renewed relay lease = %#v", renewed)
	}
	staleIdentity := lease.RelayLeaseIdentity
	staleIdentity.RelayLeaseRevision++
	if _, err := database.RenewRelay(t.Context(), RelayRenewal{
		RelayLeaseIdentity: staleIdentity,
	}, now.Add(4*time.Second), leaseDuration); !errors.Is(err, ErrRelayLeaseStale) {
		t.Fatalf("stale renewal error = %v", err)
	}

	digests := [routeSessionConnectionCount][32]byte{
		sha256.Sum256([]byte("credential-zero")),
		sha256.Sum256([]byte("credential-one")),
	}
	registrationB := registration
	registrationB.RelayServiceID = "relay_service_b"
	registrationB.RelayID = "relay_b"
	registrationB.RelayRunID = "run_b"
	registrationB.RelayAddress = "relay-b.example:443"
	registrationB.TLSServerName = "relay-b.example"
	registrationB.InternalRelayAddress = "relay-b.internal:9443"
	leaseB, err := database.RegisterRelay(t.Context(), registrationB, now.Add(5*time.Second), leaseDuration)
	if err != nil {
		t.Fatal(err)
	}
	seedRelayRouteSession(t, database, now, digests)
	baseClaim := PublisherConnectionClaimRequest{
		ConnectionAssignmentIdentity: ConnectionAssignmentIdentity{
			RouteSessionID: "session_a", RouteID: "route_a", RouteVersion: 1,
			ConnectionSlot: 0, PublisherConnectionID: "connection_0", ConnectionAssignmentRevision: 1,
			RelayServiceID: registration.RelayServiceID,
		},
		RelayLeaseIdentity: renewed.RelayLeaseIdentity,
		CredentialDigest:   digests[0],
	}
	badCredential := baseClaim
	badCredential.ClaimID = "claim_bad"
	badCredential.CredentialDigest = sha256.Sum256([]byte("wrong"))
	if _, err := database.ClaimPublisherConnection(t.Context(), badCredential, now.Add(6*time.Second)); !errors.Is(err, ErrPublisherConnectionCredential) {
		t.Fatalf("bad publisher connection credential error = %v", err)
	}

	claims := []PublisherConnectionClaimRequest{baseClaim, baseClaim}
	claims[0].ClaimID = "claim_quic"
	claims[1].ClaimID = "claim_tcp"
	type claimResult struct {
		request    PublisherConnectionClaimRequest
		connection ClaimedPublisherConnection
		err        error
	}
	results := make(chan claimResult, len(claims))
	for _, request := range claims {
		go func() {
			connection, err := database.ClaimPublisherConnection(t.Context(), request, now.Add(7*time.Second))
			results <- claimResult{request: request, connection: connection, err: err}
		}()
	}
	var winner PublisherConnectionClaimRequest
	for range claims {
		result := <-results
		switch {
		case result.err == nil:
			if winner.ClaimID != "" {
				t.Fatal("both transport candidates claimed one publisher connection")
			}
			winner = result.request
			if result.connection.State != "connected" || result.connection.ClaimID != result.request.ClaimID {
				t.Fatalf("claimed publisher connection = %#v", result.connection)
			}
		case !errors.Is(result.err, ErrPublisherConnectionAlreadyClaimed):
			t.Fatalf("losing transport claim error = %v", result.err)
		}
	}
	if winner.ClaimID == "" {
		t.Fatal("neither transport candidate claimed the publisher connection")
	}
	if _, err := database.ClaimPublisherConnection(t.Context(), winner, now.Add(8*time.Second)); err != nil {
		t.Fatalf("idempotent publisher connection claim: %v", err)
	}
	ready, err := database.MarkPublisherConnectionReady(t.Context(), winner, now.Add(9*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if ready.State != "ready" || ready.ReadyAt == nil {
		t.Fatalf("ready publisher connection = %#v", ready)
	}
	if repeated, err := database.ClaimPublisherConnection(t.Context(), winner, now.Add(10*time.Second)); err != nil || repeated.State != "ready" {
		t.Fatalf("idempotent ready claim = %#v, %v", repeated, err)
	}

	wrongService := winner
	wrongService.ConnectionSlot = 1
	wrongService.PublisherConnectionID = "connection_1"
	wrongService.ConnectionAssignmentIdentity.RelayServiceID = registrationB.RelayServiceID
	wrongService.CredentialDigest = digests[1]
	wrongService.ClaimID = "claim_wrong_service"
	if _, err := database.ClaimPublisherConnection(t.Context(), wrongService, now.Add(11*time.Second)); !errors.Is(err, ErrPublisherConnectionRelayService) {
		t.Fatalf("wrong relay service claim error = %v", err)
	}

	drainingB, err := database.BeginRelayDrain(t.Context(), leaseB.RelayLeaseIdentity, now.Add(12*time.Second), now.Add(20*time.Second))
	if err != nil || !drainingB.Draining {
		t.Fatalf("draining relay lease = %#v, %v", drainingB, err)
	}
	claimWhileDraining := wrongService
	claimWhileDraining.RelayLeaseIdentity = leaseB.RelayLeaseIdentity
	claimWhileDraining.ClaimID = "claim_while_draining"
	if _, err := database.ClaimPublisherConnection(t.Context(), claimWhileDraining, now.Add(13*time.Second)); !errors.Is(err, ErrRelayDraining) {
		t.Fatalf("draining relay claim error = %v", err)
	}

	closed, err := database.DisconnectPublisherConnection(t.Context(), winner, now.Add(14*time.Second), true)
	if err != nil || closed.State != "closed" {
		t.Fatalf("closed publisher connection = %#v, %v", closed, err)
	}
	if _, err := database.DisconnectPublisherConnection(t.Context(), winner, now.Add(15*time.Second), true); !errors.Is(err, ErrConnectionAssignmentStale) {
		t.Fatalf("repeated disconnect error = %v", err)
	}

	replacement := registration
	replacement.RelayRunID = "run_replacement"
	replacementLease, err := database.RegisterRelay(t.Context(), replacement, renewed.LeaseExpiresAt, leaseDuration)
	if err != nil {
		t.Fatal(err)
	}
	if replacementLease.RelayLeaseRevision != renewed.RelayLeaseRevision+1 {
		t.Fatalf("replacement relay lease revision = %d, want %d", replacementLease.RelayLeaseRevision, renewed.RelayLeaseRevision+1)
	}
}

func testHostedPolicyRevocation(t *testing.T, database *Database) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO control.identities (id, kind, display_name, administrator, created_at, updated_at)
		 VALUES ('identity_revocation', 'authority', 'Revocation identity', false, $1, $1)`, []any{now}},
		{`INSERT INTO control.managed_label_reservations (label, created_at)
		 VALUES ('revocation', $1)`, []any{now}},
		{`INSERT INTO control.teams (id, kind, display_name, managed_label, created_by_identity_id, created_at, updated_at)
		 VALUES ('team_revocation', 'organization', 'Revocation team', 'revocation', 'identity_revocation', $1, $1)`, []any{now}},
		{`INSERT INTO control.domains (
			id, kind, team_id, canonical_domain, state, authority_revision, created_by_identity_id,
			created_at, verified_at, updated_at
		 ) VALUES
		 (
			'domain_revocation', 'claimed', 'team_revocation', 'revocation.example.test', 'ready', 1,
			'identity_revocation', $1, $1, $1
		 ),
		 (
			'domain_revocation_other', 'claimed', 'team_revocation', 'other.example.test', 'ready', 1,
			'identity_revocation', $1, $1, $1
		 )`, []any{now}},
		{`INSERT INTO control.routes (
			id, team_id, domain_id, created_by_identity_id, idempotency_key, request_digest,
			canonical_hostname, target, route_scope, policy_revision, ip_policy, lifecycle_state,
			dns_state, created_at, updated_at
		 ) VALUES
			('route_revocation_a', 'team_revocation', 'domain_revocation', 'identity_revocation', 'route-a', decode(repeat('01', 32), 'hex'), 'a.revocation.example.test', 'http://127.0.0.1:3000', 'shared', 5, 'allow_all', 'enabled', 'published', $1, $1),
			('route_revocation_b', 'team_revocation', 'domain_revocation', 'identity_revocation', 'route-b', decode(repeat('02', 32), 'hex'), 'b.revocation.example.test', 'http://127.0.0.1:3000', 'shared', 5, 'allow_all', 'enabled', 'published', $1, $1),
			('route_revocation_c', 'team_revocation', 'domain_revocation_other', 'identity_revocation', 'route-c', decode(repeat('07', 32), 'hex'), 'c.other.example.test', 'http://127.0.0.1:3000', 'shared', 5, 'allow_all', 'enabled', 'published', $1, $1),
			('route_revocation_d', 'team_revocation', 'domain_revocation_other', 'identity_revocation', 'route-d', decode(repeat('08', 32), 'hex'), 'd.other.example.test', 'http://127.0.0.1:3000', 'shared', 5, 'allow_all', 'enabled', 'published', $1, $1)`, []any{now}},
		{`INSERT INTO control.route_sessions (
			id, route_id, team_id, membership_id, acting_identity_id, route_version, idempotency_key,
			request_digest, session_token_id, session_token_digest, policy_revision, certificate_cache_key,
			certificate_scope, certificate_identifiers, certificate_challenge, state, created_at,
			last_heartbeat_at, publisher_expires_at
		 ) VALUES
			('session_revocation_a', 'route_revocation_a', 'team_revocation', 'membership_revocation_a', 'identity_revocation', 1, 'session-a', decode(repeat('03', 32), 'hex'), 'token_revocation_a', decode(repeat('04', 32), 'hex'), 5, 'certificate-a', 'route', ARRAY['a.revocation.example.test'], 'dns-01', 'starting', $1, $1, $2),
			('session_revocation_b', 'route_revocation_b', 'team_revocation', 'membership_revocation_b', 'identity_revocation', 1, 'session-b', decode(repeat('05', 32), 'hex'), 'token_revocation_b', decode(repeat('06', 32), 'hex'), 5, 'certificate-b', 'route', ARRAY['b.revocation.example.test'], 'dns-01', 'starting', $1, $1, $2),
			('session_revocation_d', 'route_revocation_d', 'team_revocation', 'membership_revocation_d', 'identity_revocation', 1, 'session-d', decode(repeat('09', 32), 'hex'), 'token_revocation_d', decode(repeat('0a', 32), 'hex'), 5, 'certificate-d', 'route', ARRAY['d.other.example.test'], 'dns-01', 'starting', $1, $1, $2)`, []any{now, now.Add(time.Hour)}},
	} {
		if _, err := database.pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	routeC, err := database.GetRouteForAuthorization(t.Context(), "route_revocation_c")
	if err != nil {
		t.Fatal(err)
	}
	routeC, err = database.UpdateAuthorizedRoute(t.Context(), AuthorizedRouteUpdateRequest{
		RouteID: routeC.ID, TeamID: routeC.TeamID, ActingIdentityID: "identity_revocation",
		Target: routeC.Target, AllowedIPPrefixes: []string{}, AuthorityIssuer: "https://authority.example.test",
		PolicyRevision: 6, ExpectedMutationRevision: routeC.MutationRevision,
	}, now.Add(time.Second))
	if err != nil {
		t.Fatalf("observe hosted policy revision: %v", err)
	}
	var observedRevision, appliedRevision int64
	if err := database.pool.QueryRow(t.Context(), `
		SELECT observed_policy_revision, applied_policy_revision
		FROM control.authority_revision_state
		WHERE issuer = 'https://authority.example.test' AND team_id = 'team_revocation'
	`).Scan(&observedRevision, &appliedRevision); err != nil || observedRevision != 6 || appliedRevision != 0 {
		t.Fatalf("authority revision state = observed %d, applied %d, %v", observedRevision, appliedRevision, err)
	}
	if _, err := database.CreateRoute(t.Context(), CreateRouteRequest{
		TeamID: "team_revocation", DomainID: "domain_revocation", ActingIdentityID: "identity_revocation",
		IdempotencyKey: "stale-authority-route", RequestDigest: sha256.Sum256([]byte("stale-authority-route")),
		CanonicalHostname: "stale.revocation.example.test", Target: "http://127.0.0.1:3000",
		RouteScope: RouteScopeShared, DNSState: RouteDNSUnmanaged,
		AuthorityIssuer: "https://authority.example.test", PolicyRevision: 5,
	}, now.Add(time.Second)); !errors.Is(err, ErrRouteAuthority) {
		t.Fatalf("stale observed authority decision error = %v", err)
	}

	applied, closed, err := database.ApplyHostedPolicyRevocation(
		t.Context(), "https://authority.example.test", "team_revocation", 6, false,
		[]string{"membership_revocation_a"}, nil, now.Add(time.Second),
	)
	if err != nil || !applied || closed != 1 {
		t.Fatalf("membership revocation = %t, %d, %v", applied, closed, err)
	}
	if err := database.pool.QueryRow(t.Context(), `
		SELECT observed_policy_revision, applied_policy_revision
		FROM control.authority_revision_state
		WHERE issuer = 'https://authority.example.test' AND team_id = 'team_revocation'
	`).Scan(&observedRevision, &appliedRevision); err != nil || observedRevision != 6 || appliedRevision != 6 {
		t.Fatalf("applied authority revision state = observed %d, applied %d, %v", observedRevision, appliedRevision, err)
	}
	var stateA, stateB string
	if err := database.pool.QueryRow(t.Context(), `
		SELECT
			(SELECT state FROM control.route_sessions WHERE id = 'session_revocation_a'),
			(SELECT state FROM control.route_sessions WHERE id = 'session_revocation_b')
	`).Scan(&stateA, &stateB); err != nil {
		t.Fatal(err)
	}
	if stateA != "closed" || stateB != "starting" {
		t.Fatalf("selective revocation states = %q, %q", stateA, stateB)
	}
	if applied, closed, err := database.ApplyHostedPolicyRevocation(
		t.Context(), "https://authority.example.test", "team_revocation", 6, true, nil, nil, now.Add(2*time.Second),
	); err != nil || applied || closed != 0 {
		t.Fatalf("revocation replay = %t, %d, %v", applied, closed, err)
	}
	if applied, closed, err := database.ApplyHostedPolicyRevocation(
		t.Context(), "https://authority.example.test", "team_revocation", 7, false, nil,
		[]string{"domain_revocation"}, now.Add(3*time.Second),
	); err != nil || !applied || closed != 1 {
		t.Fatalf("domain revocation = %t, %d, %v", applied, closed, err)
	}
	var stateD, lifecycleA, lifecycleB, lifecycleD string
	if err := database.pool.QueryRow(t.Context(), `
		SELECT
			(SELECT state FROM control.route_sessions WHERE id = 'session_revocation_b'),
			(SELECT state FROM control.route_sessions WHERE id = 'session_revocation_d'),
			(SELECT lifecycle_state FROM control.routes WHERE id = 'route_revocation_a'),
			(SELECT lifecycle_state FROM control.routes WHERE id = 'route_revocation_b'),
			(SELECT lifecycle_state FROM control.routes WHERE id = 'route_revocation_d')
	`).Scan(&stateB, &stateD, &lifecycleA, &lifecycleB, &lifecycleD); err != nil {
		t.Fatal(err)
	}
	if stateB != "closed" || stateD != "starting" || lifecycleA != "suspended" ||
		lifecycleB != "suspended" || lifecycleD != "enabled" {
		t.Fatalf("domain revocation state = %q, %q; lifecycle = %q, %q, %q", stateB, stateD, lifecycleA, lifecycleB, lifecycleD)
	}
	updateResult := make(chan error, 1)
	revocationResult := make(chan error, 1)
	go func() {
		_, updateErr := database.UpdateAuthorizedRoute(t.Context(), AuthorizedRouteUpdateRequest{
			RouteID: routeC.ID, TeamID: routeC.TeamID, ActingIdentityID: "identity_revocation",
			Target: "http://127.0.0.1:4000", AllowedIPPrefixes: []string{},
			AuthorityIssuer: "https://authority.example.test", PolicyRevision: 8,
			ExpectedMutationRevision: routeC.MutationRevision,
		}, now.Add(4*time.Second))
		updateResult <- updateErr
	}()
	go func() {
		applied, _, applyErr := database.ApplyHostedPolicyRevocation(
			t.Context(), "https://authority.example.test", "team_revocation", 8, true, nil, nil, now.Add(4*time.Second),
		)
		if applyErr == nil && !applied {
			applyErr = errors.New("revision 8 was not applied")
		}
		revocationResult <- applyErr
	}()
	if err := <-updateResult; err != nil {
		t.Fatalf("authorization/revocation update race: %v", err)
	}
	if err := <-revocationResult; err != nil {
		t.Fatalf("authorization/revocation apply race: %v", err)
	}
	if err := database.pool.QueryRow(t.Context(), `
		SELECT state FROM control.route_sessions WHERE id = 'session_revocation_d'
	`).Scan(&stateD); err != nil || stateD != "closed" {
		t.Fatalf("team revocation state = %q, %v", stateD, err)
	}
}

func seedRelayRouteSession(
	t *testing.T,
	database *Database,
	now time.Time,
	digests [routeSessionConnectionCount][32]byte,
) {
	t.Helper()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO control.identities (
			id, kind, display_name, administrator, created_at, updated_at
		) VALUES ('identity_a', 'authority', 'Test identity', true, $1, $1)`, []any{now}},
		{`INSERT INTO control.managed_label_reservations (label, created_at)
		 VALUES ('team-a', $1)`, []any{now}},
		{`INSERT INTO control.teams (
			id, kind, display_name, managed_label, created_by_identity_id, created_at, updated_at
		) VALUES ('team_a', 'personal', 'Team A', 'team-a', 'identity_a', $1, $1)`, []any{now}},
		{`INSERT INTO control.domains (
			id, kind, team_id, canonical_domain, state, authority_revision,
			created_by_identity_id, created_at, verified_at, updated_at
		) VALUES ('domain_a', 'claimed', 'team_a', 'example.test', 'ready', 1,
			'identity_a', $1, $1, $1)`, []any{now}},
		{`UPDATE control.teams SET default_domain_id = 'domain_a' WHERE id = 'team_a'`, nil},
		{`INSERT INTO control.routes (
			id, team_id, domain_id, created_by_identity_id, idempotency_key, request_digest, canonical_hostname,
			target, route_scope, policy_revision, ip_policy, lifecycle_state,
			dns_state, created_at, updated_at
		) VALUES (
			'route_a', 'team_a', 'domain_a', 'identity_a', 'seed', decode(repeat('00', 32), 'hex'), 'route.example.test',
			'http://127.0.0.1:3000', 'shared', 1, 'allow_all', 'enabled',
			'published', $1, $1
		)`, []any{now}},
		{`INSERT INTO control.route_sessions (
			id, route_id, team_id, acting_identity_id, route_version, idempotency_key,
			request_digest, session_token_id, session_token_digest, policy_revision,
			certificate_cache_key, certificate_scope, certificate_identifiers,
			certificate_challenge, state, created_at, last_heartbeat_at,
			publisher_expires_at, certificate_installed_at, certificate_issuance_id,
			certificate_not_after
		) VALUES (
			'session_a', 'route_a', 'team_a', 'identity_a', 1, 'request_a',
			$2, 'session_token_a', $3, 1,
			'certificate_a', 'route', ARRAY['route.example.test'],
			'tls-alpn-01', 'starting', $1, $1, $4, $1, 'issuance_a', $4
		)`, []any{now, digests[0][:], digests[1][:], now.Add(time.Hour)}},
	} {
		if _, err := database.pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	for slot := range routeSessionConnectionCount {
		relayServiceID := fmt.Sprintf("relay_service_%c", 'a'+slot)
		if _, err := database.pool.Exec(t.Context(), `
			INSERT INTO control.route_session_connections (
				route_session_id, route_id, route_version, connection_slot, publisher_connection_id,
				connection_assignment_revision, relay_service_id, relay_address, tls_server_name,
				publisher_connection_credential_digest, publisher_connection_credential_expires_at,
				state, assigned_at
			) VALUES (
				'session_a', 'route_a', 1, $1, $2,
				1, $3, $4, $5, $6, $7, 'assigned', $8
			)
		`, slot, fmt.Sprintf("connection_%d", slot), relayServiceID,
			relayServiceID+".example:443", relayServiceID+".example", digests[slot][:], now.Add(time.Hour), now); err != nil {
			t.Fatal(err)
		}
	}
}

func newDisposableControlStateDatabaseURL(t *testing.T, suffix string) string {
	t.Helper()
	return testutil.NewDisposablePostgresDatabaseURL(t, "controlstate_"+suffix)
}
