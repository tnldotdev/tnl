package controlstate

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationTeamCreation(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "team_creation")
	session := newBuiltinSession(t, database, now)
	personal, err := database.GetTeam(t.Context(), session.Identity.Identity.ID, session.Identity.PersonalTeamID)
	if err != nil || personal.DisplayName != "local-administrator" || personal.ManagedLabel == "" {
		t.Fatalf("personal team name = %#v, %v", personal, err)
	}
	request := authorityTeamRequest(session.Identity.Identity.ID)
	request.DisplayName, request.MemberSlug = "studio", ""
	team, err := database.CreateTeam(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	if team.Kind != "organization" || team.PolicyRevision != 1 || team.DefaultDomainID == "" || team.DisplayName != "studio" {
		t.Fatalf("created team = %#v", team)
	}
	repeated, err := database.CreateTeam(t.Context(), request, now.Add(time.Second))
	if err != nil || !reflect.DeepEqual(repeated, team) {
		t.Fatalf("idempotent team = %#v, %v", repeated, err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.identities SET display_name = '李 小龙' WHERE id = $1`, session.Identity.Identity.ID); err != nil {
		t.Fatal(err)
	}
	repeated, err = database.CreateTeam(t.Context(), request, now.Add(2*time.Second))
	if err != nil || !reflect.DeepEqual(repeated, team) {
		t.Fatalf("idempotent team after identity rename = %#v, %v", repeated, err)
	}
	requiresSlug := authorityTeamRequest(session.Identity.Identity.ID)
	requiresSlug.DisplayName, requiresSlug.MemberSlug, requiresSlug.IdempotencyKey = "new-team", "", "no-usable-identity-name"
	if _, err := database.CreateTeam(t.Context(), requiresSlug, now); !errors.Is(err, ErrMemberSlugRequired) {
		t.Fatalf("missing member slug for non-ASCII identity name: %v", err)
	}
	request.RequestDigest = sha256.Sum256([]byte("changed"))
	if _, err := database.CreateTeam(t.Context(), request, now); !errors.Is(err, ErrAuthorityIdempotency) {
		t.Fatalf("team idempotency: %v", err)
	}
	invalid := authorityTeamRequest(session.Identity.Identity.ID)
	invalid.DisplayName, invalid.IdempotencyKey = "a\x00b", "invalid-display-name"
	if _, err := database.CreateTeam(t.Context(), invalid, now); !errors.Is(err, ErrAuthorityInvalid) {
		t.Fatalf("NUL display name was not rejected at validation: %v", err)
	}
	memberships, err := database.ListTeamMemberships(t.Context(), session.Identity.Identity.ID, team.ID)
	if err != nil || len(memberships) != 1 || memberships[0].Role != "owner" || memberships[0].MemberSlug != "local-administrator" || memberships[0].TeamDisplayName != team.DisplayName {
		t.Fatalf("initial memberships = %#v, %v", memberships, err)
	}
	duplicate := authorityTeamRequest(session.Identity.Identity.ID)
	duplicate.IdempotencyKey = "duplicate-name"
	duplicate.DisplayName = team.DisplayName
	if _, err := database.CreateTeam(t.Context(), duplicate, now); !errors.Is(err, ErrTeamNameUnavailable) {
		t.Fatalf("duplicate team name: %v", err)
	}
	invitation := authorityInvitationRequest(session.Identity.Identity.ID, session.Identity.PersonalTeamID, "member", now)
	if _, err := database.CreateTeamInvitation(t.Context(), invitation, now); !errors.Is(err, ErrAuthorityAccess) {
		t.Fatalf("personal-team invitation: %v", err)
	}
}

func TestIntegrationSimpleModeOnlyReservesReadableLabels(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "simple_labels")
	database.managedURLMode = naming.ManagedURLModeSimple
	admin := newBuiltinSession(t, database, now)
	if member := admin.Identity.Memberships[0]; member.ManagedLabel != "local-administrator" {
		t.Fatalf("builtin label = %q", member.ManagedLabel)
	}
	owner := admin.Identity.Identity.ID
	teamRequest := authorityTeamRequest(owner)
	teamRequest.DisplayName = "studio"
	team, err := database.CreateTeam(t.Context(), teamRequest, now)
	if err != nil || team.ManagedLabel != "studio" {
		t.Fatalf("team label = %#v, %v", team, err)
	}
	creator, err := database.ListTeamMemberships(t.Context(), owner, team.ID)
	if err != nil || len(creator) != 1 || creator[0].ManagedLabel != "studio" {
		t.Fatalf("creator label = %#v, %v", creator, err)
	}
	member := addAuthorityMember(t, database, now, owner, team.ID, "alex", TeamRoleMember)
	if member.ManagedLabel != "alex-studio" {
		t.Fatalf("invited member label = %q", member.ManagedLabel)
	}
	identity := OIDCIdentity{Issuer: "https://issuer.example", Subject: "alex", DisplayName: "Alex",
		AssertionDigest: sha256.Sum256([]byte("alex assertion")), AssertionExpiry: now.Add(time.Hour)}
	personal, err := database.CreateOIDCControlSession(t.Context(), "tunnels.example.test", identity, time.Hour, 24*time.Hour, now)
	if err != nil || len(personal.Identity.Memberships) != 1 || personal.Identity.Memberships[0].ManagedLabel != "alex" {
		t.Fatalf("personal label = %#v, %v", personal.Identity, err)
	}
	var count int
	if err := database.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.managed_label_reservations`).Scan(&count); err != nil || count != 4 {
		t.Fatalf("reserved labels = %d, want four readable names: %v", count, err)
	}
}

func TestIntegrationInvitationAcceptanceAndRoles(t *testing.T) {
	database, now, owner, team := newAuthorityTeam(t)
	owners, err := database.ListTeamMemberships(t.Context(), owner, team.ID)
	if err != nil || len(owners) != 1 {
		t.Fatalf("owner prerequisite: %#v, %v", owners, err)
	}
	insertAuthorityIdentity(t, database, "identity_member", "member@example.test", true, now)
	insertAuthorityIdentity(t, database, "identity_wrong_email", "other@example.test", true, now)
	request := authorityInvitationRequest(owner, team.ID, "member", now)
	request.EmailRestriction = "MEMBER@example.test"
	first, err := database.CreateTeamInvitation(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	retried, err := database.CreateTeamInvitation(t.Context(), request, now.Add(time.Second))
	if err != nil || retried.Invitation.ID != first.Invitation.ID || retried.Secret != first.Secret || retried.Invitation.NormalizedEmailRestriction != "member@example.test" {
		t.Fatalf("invitation retry changed its identity, secret or email: %v", err)
	}
	if _, err := database.AcceptInvitation(t.Context(), "identity_wrong_email", credentials.InvitationToken(first.Secret), now); !errors.Is(err, ErrAuthorityAccess) {
		t.Fatalf("restricted invitation: %v", err)
	}
	member, err := database.AcceptInvitation(t.Context(), "identity_member", credentials.InvitationToken(first.Secret), now)
	if err != nil || member.Role != "member" || member.MemberSlug != "member" || member.PolicyRevision != 2 {
		t.Fatalf("accepted membership = %#v, %v", member, err)
	}
	member, err = database.SetMembershipRole(t.Context(), owner, team.ID, member.ID, "admin", now)
	if err != nil || member.Role != "admin" || member.PolicyRevision != 3 {
		t.Fatalf("promoted membership = %#v, %v", member, err)
	}
	if _, err := database.SetMembershipRole(t.Context(), owner, team.ID, member.ID, TeamRole("unknown"), now); !errors.Is(err, ErrAuthorityInvalid) {
		t.Fatalf("unknown team role: %v", err)
	}
	invalidInvite := authorityInvitationRequest(owner, team.ID, "invalid-role", now)
	invalidInvite.InitialRole = TeamRole("unknown")
	if _, err := database.CreateTeamInvitation(t.Context(), invalidInvite, now); !errors.Is(err, ErrAuthorityInvalid) {
		t.Fatalf("unknown invitation role: %v", err)
	}
	if _, err := database.SetMembershipRole(t.Context(), member.IdentityID, team.ID, owners[0].ID, "member", now); !errors.Is(err, ErrAuthorityAccess) {
		t.Fatalf("admin demoting owner: %v", err)
	}
	adminInvite := authorityInvitationRequest(member.IdentityID, team.ID, "another-admin", now)
	adminInvite.InitialRole = "admin"
	if _, err := database.CreateTeamInvitation(t.Context(), adminInvite, now); !errors.Is(err, ErrAuthorityAccess) {
		t.Fatalf("admin granting admin: %v", err)
	}
	if _, err := database.SetMembershipRole(t.Context(), owner, team.ID, owners[0].ID, "member", now); !errors.Is(err, ErrAuthorityConflict) {
		t.Fatalf("last owner demotion: %v", err)
	}
}

func TestIntegrationMembershipListDoesNotOutliveActorMembership(t *testing.T) {
	database, now, owner, team := newAuthorityTeam(t)
	reader := addAuthorityMember(t, database, now, owner, team.ID, "reader", "member")
	queries := controlstatedb.New(database.pool)
	// reproduce revocation between the actor lookup and the membership list.
	if _, err := queries.GetTeamActorContext(t.Context(), controlstatedb.GetTeamActorContextParams{
		IdentityID: reader.IdentityID, TeamID: team.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.RemoveMembership(t.Context(), owner, team.ID, reader.ID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	rows, err := queries.ListTeamMembershipContexts(t.Context(), controlstatedb.ListTeamMembershipContextsParams{
		TeamID: team.ID, IdentityID: reader.IdentityID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("revoked actor received %d team memberships", len(rows))
	}
}

func TestIntegrationMembershipRemovalClosesRoutesAndQuarantinesSlug(t *testing.T) {
	database, now, owner, team := newAuthorityTeam(t)
	admin := addAuthorityMember(t, database, now, owner, team.ID, "admin", "admin")
	member := addAuthorityMember(t, database, now, admin.IdentityID, team.ID, "second", "member")
	sealedDigest, err := database.sealSecret(publicURLRequestDigestContext("public_url_member"), bytes.Repeat([]byte{'1'}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `INSERT INTO control.public_urls (
		id, team_id, domain_id, membership_id, created_by_identity_id, idempotency_key,
		request_digest_ciphertext, request_digest_storage_key_id, canonical_hostname, target,
		public_url_scope, purpose, policy_revision, ip_policy,
		lifecycle_state, dns_state, created_at, updated_at
	) VALUES ('public_url_member', $1, $2, $3, $4, 'member-route', $5, $6,
		'second.example.test', 'http://127.0.0.1:3000', 'member', 'app', $7, 'allow_all', 'enabled', 'unmanaged', $8, $8)`,
		team.ID, team.DefaultDomainID, member.ID, member.IdentityID,
		sealedDigest, database.storageKey.CurrentID(), member.PolicyRevision, now); err != nil {
		t.Fatal(err)
	}
	insertTestPublishRun(t, database, testPublishRun{
		ID: "session_member", PublicURLID: "public_url_member", TeamID: team.ID,
		MembershipID: member.ID, ActingIdentityID: member.IdentityID, PolicyRevision: int64(member.PolicyRevision),
		CertificateCacheKey: "member-cert", CertificateScope: "route", CertificateIdentifiers: []string{"second.example.test"},
		ChallengeMethod: "tls-alpn-01", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	if err := database.RemoveMembership(t.Context(), admin.IdentityID, team.ID, member.ID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.getMembership(t.Context(), team.ID, member.ID); !errors.Is(err, ErrMembershipNotFound) {
		t.Fatalf("removed membership: %v", err)
	}
	var publicURLState, sessionState, reason, slugState string
	if err := database.pool.QueryRow(t.Context(), `SELECT routes.lifecycle_state, sessions.state, sessions.close_reason, slugs.state
		FROM control.public_urls AS routes JOIN control.publish_runs AS sessions ON sessions.public_url_id = routes.id
		JOIN control.team_memberships AS memberships ON memberships.id = routes.membership_id
		JOIN control.member_slug_reservations AS slugs ON slugs.id = memberships.slug_reservation_id
		WHERE routes.id = 'public_url_member'`).Scan(&publicURLState, &sessionState, &reason, &slugState); err != nil {
		t.Fatal(err)
	}
	if publicURLState != "suspended" || sessionState != "closed" || reason != "membership_removed" || slugState != "quarantined" {
		t.Fatalf("removed member runtime = %s/%s/%s/%s", publicURLState, sessionState, reason, slugState)
	}
	request := authorityInvitationRequest(owner, team.ID, "second", now)
	request.IdempotencyKey = "reuse-accepted-slug"
	request.RequestDigest = sha256.Sum256([]byte(request.IdempotencyKey))
	if _, err := database.CreateTeamInvitation(t.Context(), request, now); !errors.Is(err, ErrAuthorityConflict) {
		t.Fatalf("accepted slug reuse: %v", err)
	}
}

func TestIntegrationRevokedInvitationReleasesPendingSlug(t *testing.T) {
	database, now, owner, team := newAuthorityTeam(t)
	request := authorityInvitationRequest(owner, team.ID, "reusable", now)
	invitation, err := database.CreateTeamInvitation(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.RevokeTeamInvitation(t.Context(), owner, team.ID, invitation.Invitation.ID, now); err != nil {
		t.Fatal(err)
	}
	request.IdempotencyKey = "reused"
	request.RequestDigest = sha256.Sum256([]byte("reused"))
	if _, err := database.CreateTeamInvitation(t.Context(), request, now); err != nil {
		t.Fatalf("released pending slug not reusable: %v", err)
	}
}

func TestIntegrationCustomDomainLifecycle(t *testing.T) {
	database, now, owner, team := newAuthorityTeam(t)
	managedDomainID := team.DefaultDomainID
	request := ClaimDomainRequest{IdentityID: owner, TeamID: team.ID, IdempotencyKey: "domain",
		RequestDigest: sha256.Sum256([]byte("domain")), Domain: "authority.example.test", MakeDefault: true}
	domain, err := database.ClaimTeamDomain(t.Context(), request, now)
	if err != nil || domain.State != "pending" || domain.DNSAuthorityReference == "" || domain.AuthorityRevision != 2 {
		t.Fatalf("custom domain = %#v, %v", domain, err)
	}
	repeated, err := database.ClaimTeamDomain(t.Context(), request, now.Add(time.Second))
	if err != nil || !reflect.DeepEqual(repeated, domain) {
		t.Fatalf("domain replay = %#v, %v", repeated, err)
	}
	overlap := request
	overlap.IdempotencyKey, overlap.Domain = "overlap", "child.authority.example.test"
	overlap.RequestDigest = sha256.Sum256([]byte("overlap"))
	if _, err := database.ClaimTeamDomain(t.Context(), overlap, now); !errors.Is(err, ErrAuthorityConflict) {
		t.Fatalf("overlapping domain: %v", err)
	}
	if _, err := database.SetTeamDefaultDomain(t.Context(), owner, team.ID, domain.ID, now); !errors.Is(err, ErrAuthorityConflict) {
		t.Fatalf("pending default domain: %v", err)
	}
	work, found, err := database.ClaimDNSAuthorityWork(t.Context(), "dns-worker", now, time.Minute)
	if err != nil || !found || work.Reference != domain.DNSAuthorityReference {
		t.Fatalf("claim authority work = %#v, %t, %v", work, found, err)
	}
	work.State, work.ProviderZoneID, work.Nameservers, work.AvailableAt = "ready", "ZAUTHORITY", []string{"ns-1.example.test", "ns-2.example.test"}, now
	if _, err := database.SaveDNSAuthorityWork(t.Context(), work, now); err != nil {
		t.Fatal(err)
	}
	team, err = database.SetTeamDefaultDomain(t.Context(), owner, team.ID, domain.ID, now)
	if err != nil || team.DefaultDomainID != domain.ID || team.PolicyRevision != 3 {
		t.Fatalf("claimed default = %#v, %v", team, err)
	}
	if err := database.ReleaseTeamDomain(t.Context(), owner, team.ID, domain.ID, now); !errors.Is(err, ErrAuthorityConflict) {
		t.Fatalf("release default: %v", err)
	}
	domains, err := database.ListTeamDomains(t.Context(), owner, team.ID)
	if err != nil || len(domains) != 2 || domains[0].Kind != "managed" {
		t.Fatalf("organization domains = %#v, %v", domains, err)
	}
	team, err = database.SetTeamDefaultDomain(t.Context(), owner, team.ID, managedDomainID, now)
	if err != nil || team.PolicyRevision != 4 {
		t.Fatalf("restored default = %#v, %v", team, err)
	}
	for range 2 {
		if err := database.ReleaseTeamDomain(t.Context(), owner, team.ID, domain.ID, now); err != nil {
			t.Fatalf("release/replay: %v", err)
		}
	}
	domains, err = database.ListTeamDomains(t.Context(), owner, team.ID)
	if err != nil || len(domains) != 2 || domains[1].State != "releasing" || len(domains[1].RequiredRecords) != 2 {
		t.Fatalf("released domains = %#v, %v", domains, err)
	}
}

func TestIntegrationDNSAuthorities(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "dns_authorities")
	request := CreateDNSAuthorityRequest{TeamID: "team_hosted_dns", DomainID: "domain_hosted_dns", CanonicalDomain: "hosted-dns.example.test",
		IdempotencyKey: "create", RequestDigest: sha256.Sum256([]byte("create"))}
	authority, err := database.CreateDNSAuthority(t.Context(), request, now)
	if err != nil || authority.State != "pending" || authority.Reference == "" || len(authority.RequiredRecords) != 0 {
		t.Fatalf("created authority = %#v, %v", authority, err)
	}
	repeated, err := database.CreateDNSAuthority(t.Context(), request, now)
	if err != nil || !reflect.DeepEqual(repeated, authority) {
		t.Fatalf("authority replay = %#v, %v", repeated, err)
	}
	request.RequestDigest = sha256.Sum256([]byte("changed"))
	if _, err := database.CreateDNSAuthority(t.Context(), request, now); !errors.Is(err, ErrDNSAuthorityIdempotency) {
		t.Fatalf("authority idempotency: %v", err)
	}
	work, found, err := database.ClaimDNSAuthorityWork(t.Context(), "dns-worker", now, time.Minute)
	if err != nil || !found || work.Reference != authority.Reference || work.WorkEpoch != 1 || work.Attempts != 1 {
		t.Fatalf("claimed authority = %#v, %t, %v", work, found, err)
	}
	work.ProviderZoneID, work.Nameservers, work.State, work.AvailableAt = "ZHOSTEDDNS", []string{"ns-1.example.test", "ns-2.example.test"}, "ready", now
	saved, err := database.SaveDNSAuthorityWork(t.Context(), work, now)
	if err != nil || saved.State != "ready" || saved.WorkRevision != 2 || len(saved.RequiredRecords) != 2 {
		t.Fatalf("saved authority = %#v, %v", saved, err)
	}
	if _, err := database.SaveDNSAuthorityWork(t.Context(), work, now); !errors.Is(err, ErrDNSAuthorityWorkStale) {
		t.Fatalf("stale authority work: %v", err)
	}
	released, err := database.ReleaseDNSAuthority(t.Context(), authority.Reference, "release", now)
	if err != nil || released.State != "releasing" {
		t.Fatalf("released authority = %#v, %v", released, err)
	}
	replay, err := database.ReleaseDNSAuthority(t.Context(), authority.Reference, "release", now)
	if err != nil || !reflect.DeepEqual(replay, released) {
		t.Fatalf("release replay = %#v, %v", replay, err)
	}
	ready, err := database.DNSAuthorityReleaseReady(t.Context(), authority.DomainID, now)
	if err != nil || !ready {
		t.Fatalf("release readiness = %t, %v", ready, err)
	}
}

func newBuiltinSession(t *testing.T, database *Database, now time.Time) ControlSession {
	t.Helper()
	session, err := database.CreateBuiltinControlSession(t.Context(), "tunnels.example.test", 7, time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func authorityTeamRequest(owner string) CreateTeamRequest {
	return CreateTeamRequest{IdentityID: owner, IdempotencyKey: "team", RequestDigest: sha256.Sum256([]byte("team")), DisplayName: "authority-team", MemberSlug: "owner"}
}

func newAuthorityTeam(t *testing.T) (*Database, time.Time, string, Team) {
	t.Helper()
	database, now := newControlStateIntegrationDatabase(t, "authority")
	owner := newBuiltinSession(t, database, now).Identity.Identity.ID
	team, err := database.CreateTeam(t.Context(), authorityTeamRequest(owner), now)
	if err != nil {
		t.Fatal(err)
	}
	return database, now, owner, team
}

func authorityInvitationRequest(owner, team, slug string, now time.Time) CreateInvitationRequest {
	return CreateInvitationRequest{IdentityID: owner, TeamID: team, IdempotencyKey: "invite-" + slug,
		RequestDigest: sha256.Sum256([]byte("invite-" + slug)), MemberSlug: slug, InitialRole: "member", ExpiresAt: now.Add(time.Hour), RetrySecret: bytes.Repeat([]byte{1}, 32)}
}

func addAuthorityMember(t *testing.T, database *Database, now time.Time, inviter, team, slug string, role TeamRole) Membership {
	t.Helper()
	identity := "identity_" + slug
	insertAuthorityIdentity(t, database, identity, "", false, now)
	request := authorityInvitationRequest(inviter, team, slug, now)
	request.InitialRole = role
	invitation, err := database.CreateTeamInvitation(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	member, err := database.AcceptInvitation(t.Context(), identity, credentials.InvitationToken(invitation.Secret), now)
	if err != nil {
		t.Fatal(err)
	}
	return member
}

func insertAuthorityIdentity(t *testing.T, database *Database, identityID, normalizedEmail string, emailVerified bool, now time.Time) {
	t.Helper()
	var email any
	if normalizedEmail != "" {
		email = normalizedEmail
	}
	if _, err := database.pool.Exec(t.Context(), `INSERT INTO control.identities (
		id, kind, display_name, normalized_email, email_verified, administrator, created_at, updated_at
	) VALUES ($1, 'oidc', $1, $2, $3, false, $4, $4)`, identityID, email, emailVerified, now); err != nil {
		t.Fatal(err)
	}
}
