package controlstate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/oidcauth"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
)

func companyTestPrincipal(t *testing.T, d *Database, s ControlSession, now time.Time) ControlPrincipal {
	t.Helper()
	p, err := d.AuthenticateAccessToken(t.Context(), s.AccessToken, now)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func companyTestConnection(t *testing.T, d *Database, team string, owner ControlPrincipal, admission string, now time.Time) IdentityConnectionSecret {
	t.Helper()
	// attach the baseline authority fixture to an exact OIDC subject; activation
	// requires actual source authentication, including in non-auth boundary tests.
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.identities SET kind='oidc',issuer='https://company.example',subject=id WHERE id=$1`, owner.IdentityID); err != nil {
		t.Fatal(err)
	}
	c, err := d.BeginIdentityConnectionSetup(t.Context(), owner, CreateIdentityConnectionRequest{TeamID: team, Issuer: "https://company.example", SourceID: "test-source", Admission: admission}, now)
	if err != nil {
		t.Fatal(err)
	}
	return companyActivateTestSetup(t, d, c, owner, now, companyTestProvisioningToken(t))
}

func companyTestProvisioningToken(t *testing.T) string {
	t.Helper()
	token, err := companyRandom()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func companyActivateTestSetup(t *testing.T, d *Database, c IdentityConnectionSetup, owner ControlPrincipal, now time.Time, provisioningToken string) IdentityConnectionSecret {
	t.Helper()
	if err := d.ProvisionCompanyEligibility(t.Context(), c.SetupToken, ProvisionCompanyEligibilityRequest{TeamID: c.TeamID, IdentityConnectionID: c.ID, ConnectionRevision: c.Revision, IdentityID: owner.IdentityID, Subject: "directory/" + owner.IdentityID, Revision: 1, Eligible: true, ValidUntil: now.Add(4 * time.Hour), MemberSlug: "owner"}, now); err != nil {
		t.Fatal(err)
	}
	source := OIDCIdentity{Issuer: c.Issuer, Subject: owner.IdentityID, AssertionDigest: sha256.Sum256([]byte("activate/" + c.ID)), AssertionExpiry: now.Add(5 * time.Minute), TeamContexts: []oidcauth.TeamContext{{TeamID: c.TeamID, IdentityConnectionID: c.ID, ConnectionRevision: c.Revision, SourceID: c.SourceID, Subject: "directory/" + owner.IdentityID, AuthenticatedAt: now.Unix()}}}
	active, err := d.ActivateIdentityConnection(t.Context(), owner, c.TeamID, c.ID, c.SetupToken, c.Revision, source, now, provisioningToken)
	if err != nil {
		t.Fatal(err)
	}
	return active
}

func TestIntegrationCompanyActivationRetryKeepsPrecommittedCredential(t *testing.T) {
	d, now, _, team := newAuthorityTeam(t)
	p := companyTestPrincipal(t, d, newOIDCSession(t, d, now), now)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.identities SET kind='oidc',issuer='https://company.example',subject=id WHERE id=$1`, p.IdentityID); err != nil {
		t.Fatal(err)
	}
	setup, err := d.BeginIdentityConnectionSetup(t.Context(), p, CreateIdentityConnectionRequest{TeamID: team.ID, Issuer: "https://company.example", SourceID: "retry-source", Admission: "approval"}, now)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("a", 42) + "A"
	for _, invalid := range []string{"", "short", strings.Repeat("a", 43)} {
		if _, err := d.ActivateIdentityConnection(t.Context(), p, team.ID, setup.ID, setup.SetupToken, setup.Revision, OIDCIdentity{}, now, invalid); !errors.Is(err, ErrAuthorityInvalid) {
			t.Fatal("invalid precommitted credential accepted", err)
		}
	}
	active := companyActivateTestSetup(t, d, setup, p, now, token)
	if active.ProvisioningToken != token {
		t.Fatal("activation changed precommitted token")
	}
	for attempt := range 2 {
		source := OIDCIdentity{Issuer: setup.Issuer, Subject: p.IdentityID, AssertionDigest: sha256.Sum256([]byte(fmt.Sprint("retry", attempt))), AssertionExpiry: now.Add(5 * time.Minute), TeamContexts: []oidcauth.TeamContext{{TeamID: team.ID, IdentityConnectionID: setup.ID, ConnectionRevision: active.Revision, SourceID: setup.SourceID, Subject: "directory/" + p.IdentityID, AuthenticatedAt: now.Unix()}}}
		source.Nonce, source.IssuedAt = "retry-nonce", now
		retry, err := d.ActivateIdentityConnection(WithCompanyActorProof(t.Context(), source, source.Nonce), p, team.ID, setup.ID, setup.SetupToken, setup.Revision, source, now, token)
		if err != nil || retry.ProvisioningToken != token || retry.Revision != active.Revision {
			t.Fatalf("retry changed operation: %+v %v", retry, err)
		}
	}
	proof := OIDCIdentity{Issuer: setup.Issuer, Subject: p.IdentityID, Nonce: "rotate", IssuedAt: now, AssertionDigest: sha256.Sum256([]byte("rotate")), AssertionExpiry: now.Add(time.Minute), TeamContexts: []oidcauth.TeamContext{{TeamID: team.ID, IdentityConnectionID: setup.ID, ConnectionRevision: active.Revision, SourceID: setup.SourceID, Subject: "directory/" + p.IdentityID, AuthenticatedAt: now.Unix()}}}
	rotated, err := d.RotateCompanyProvisioningToken(WithCompanyActorProof(t.Context(), proof, proof.Nonce), p, team.ID, setup.ID, active.Revision, now)
	if err != nil || rotated.ProvisioningToken == token {
		t.Fatal("rotation", err)
	}
	proof.Nonce, proof.AssertionDigest = "late-retry", sha256.Sum256([]byte("late-retry"))
	if _, err = d.ActivateIdentityConnection(WithCompanyActorProof(t.Context(), proof, proof.Nonce), p, team.ID, setup.ID, setup.SetupToken, setup.Revision, proof, now, token); !errors.Is(err, ErrAuthorityConflict) {
		t.Fatal("late retry restored revoked credential", err)
	}
}

func TestIntegrationCompanyDisabledIdentityAcceptsOnlyNegativeEligibility(t *testing.T) {
	d, now, _, team := newAuthorityTeam(t)
	owner := companyTestPrincipal(t, d, newOIDCSession(t, d, now), now)
	c := companyTestConnection(t, d, team.ID, owner, "approval", now)
	person := companyTestPrincipal(t, d, newOIDCSession(t, d, now.Add(time.Second)), now)
	r := companyTestEligibility(t, d, c, person.IdentityID, 1, true, now)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, person.IdentityID, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	r.Revision, r.Eligible = 2, false
	if err := d.ProvisionCompanyEligibility(t.Context(), c.ProvisioningToken, r, now); err != nil {
		t.Fatal("offboarding disabled identity", err)
	}
	if err := d.ProvisionCompanyEligibility(t.Context(), c.ProvisioningToken, r, now); err != nil {
		t.Fatal("negative retry", err)
	}
	r.Revision, r.Eligible = 3, true
	if err := d.ProvisionCompanyEligibility(t.Context(), c.ProvisioningToken, r, now); !errors.Is(err, ErrAuthorityAccess) {
		t.Fatal("disabled identity reactivated", err)
	}
}

func companyBindTestIntent(t *testing.T, d *Database, i OIDCIdentity, now time.Time) (OIDCIdentity, error) {
	t.Helper()
	if len(i.TeamContexts) == 0 {
		return i, nil
	}
	intent, err := d.CreateCompanyLoginIntent(t.Context(), i.TeamContexts[0].TeamID, "https://company.example", "tnl-cli", "https://control.example/v1/auth/device/callback", now)
	if err != nil {
		return i, ErrControlAuthentication
	}
	i.Nonce, i.ClientID = intent.Nonce, intent.ClientID
	i.CompanyIntent = &CompanyIntentBinding{ID: intent.ID, BindingToken: intent.BindingToken, RedirectURI: intent.RedirectURI}
	return i, nil
}

func companyTestEligibility(t *testing.T, d *Database, c IdentityConnectionSecret, identity string, revision int64, eligible bool, now time.Time) ProvisionCompanyEligibilityRequest {
	t.Helper()
	r := ProvisionCompanyEligibilityRequest{TeamID: c.TeamID, IdentityConnectionID: c.ID, ConnectionRevision: c.Revision, IdentityID: identity, Subject: "directory/" + identity, Revision: revision, Eligible: eligible, ValidUntil: now.Add(4 * time.Hour), MemberSlug: "managed-member"}
	if err := d.ProvisionCompanyEligibility(t.Context(), c.ProvisioningToken, r, now); err != nil {
		t.Fatal(err)
	}
	return r
}

func companyTestActive(t *testing.T, d *Database, member string, now time.Time) bool {
	t.Helper()
	active, err := controlstatedb.New(d.pool).ActiveCompanyMembership(t.Context(), controlstatedb.ActiveCompanyMembershipParams{MembershipID: member, Now: timestamptz(now)})
	if err != nil {
		t.Fatal(err)
	}
	return active
}

func TestIntegrationCompanyApprovalSubjectNeedsCurrentCompanySignIn(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	p := companyTestPrincipal(t, d, newOIDCSession(t, d, now), now)
	identity := OIDCIdentity{Issuer: "https://company.example", Subject: "approval-visitor", DisplayName: "Approval visitor", AssertionDigest: sha256.Sum256([]byte("approval-personal")), AssertionExpiry: now.Add(time.Hour)}
	personal, err := d.CreateOIDCControlSession(t.Context(), "tunnels.example.test", identity, time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	person := personal.Identity.Identity.ID
	service, err := d.CreatePrivateService(t.Context(), team.ID, owner, "approval-private", "approval-private", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.CreatePrivateServiceGrant(t.Context(), service.ID, owner, "approval-grant", "identity", person, nil, now); err != nil {
		t.Fatal(err)
	}
	c := companyTestConnection(t, d, team.ID, p, "approval", now)
	companyTestEligibility(t, d, c, person, 1, true, now)
	personalCtx := WithControlPrincipal(t.Context(), companyTestPrincipal(t, d, personal, now))
	check := func(ctx context.Context, want bool) {
		t.Helper()
		tx, err := d.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		_, _, err = privateVisitorAccess(ctx, tx, service.ID, person, now)
		if want && err != nil || !want && !errors.Is(err, ErrPrivateServiceAccess) {
			t.Fatal("approval subject authorization", want, err)
		}
	}
	check(personalCtx, false)
	identity.TeamContexts = []oidcauth.TeamContext{{TeamID: team.ID, IdentityConnectionID: c.ID, ConnectionRevision: c.Revision, SourceID: c.SourceID, Subject: "directory/" + person, AuthenticatedAt: now.Unix()}}
	identity, err = companyBindTestIntent(t, d, identity, now)
	if err != nil {
		t.Fatal(err)
	}
	identity.AssertionDigest = sha256.Sum256([]byte("approval-company"))
	company, err := d.CreateOIDCControlSession(t.Context(), "tunnels.example.test", identity, time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	companyCtx := WithControlPrincipal(t.Context(), companyTestPrincipal(t, d, company, now))
	check(companyCtx, true)
	if err = d.AuthorizeTeamSession(t.Context(), companyTestPrincipal(t, d, company, now), team.ID, now); !errors.Is(err, ErrAuthorityAccess) {
		t.Fatal("company proof implicitly admitted membership", err)
	}
	companyTestEligibility(t, d, c, person, 2, false, now)
	check(companyCtx, false)
}

func TestIntegrationCompanyManagedMembershipPreservesManualAuthority(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	s := newOIDCSession(t, d, now)
	p := companyTestPrincipal(t, d, s, now)
	admin := addAuthorityMember(t, d, now, owner, team.ID, "admin", TeamRoleAdmin)
	contractorRequest := authorityInvitationRequest(admin.IdentityID, team.ID, "contractor", now)
	contractorRequest.PersonalAccountException = true
	if _, err := d.CreateTeamInvitation(t.Context(), contractorRequest, now); !errors.Is(err, ErrAuthorityAccess) {
		t.Fatal("admin granted contractor exception", err)
	}
	contractorRequest.IdentityID = owner
	contractorInvitation, err := d.CreateTeamInvitation(t.Context(), contractorRequest, now)
	if err != nil {
		t.Fatal(err)
	}
	insertAuthorityIdentity(t, d, "identity_contractor", "", false, now)
	// an asserted administrator flag is not an owner membership.
	if _, err := d.BeginIdentityConnectionSetup(t.Context(), ControlPrincipal{IdentityID: admin.IdentityID, Administrator: true}, CreateIdentityConnectionRequest{TeamID: team.ID, Issuer: "https://company.example", SourceID: "test-source", Admission: "managed"}, now); !errors.Is(err, ErrAuthorityAccess) {
		t.Fatal("non-owner configured company connection", err)
	}
	c := companyTestConnection(t, d, team.ID, p, "managed", now)
	contractor, err := d.AcceptInvitation(t.Context(), "identity_contractor", credentials.InvitationToken(contractorInvitation.Secret), now)
	if err != nil || !contractor.PersonalAccountException || !companyTestActive(t, d, contractor.ID, now) {
		t.Fatal("owner contractor invitation lost exception", contractor, err)
	}
	var personalMembership string
	for _, m := range s.Identity.Memberships {
		if m.TeamID == s.Identity.PersonalTeamID {
			personalMembership = m.ID
		}
	}
	if companyTestActive(t, d, personalMembership, now) == false {
		t.Fatal("organization policy affected personal team")
	}
	var ownerMember string
	if err := d.pool.QueryRow(t.Context(), `SELECT id FROM control.team_memberships WHERE team_id=$1 AND identity_id=$2`, team.ID, owner).Scan(&ownerMember); err != nil {
		t.Fatal(err)
	}
	companyTestEligibility(t, d, c, owner, 2, false, now)
	if companyTestActive(t, d, ownerMember, now) {
		t.Fatal("last owner silently bypassed eligibility")
	}
	if err := d.SetCompanyMembershipDecision(t.Context(), p, team.ID, ownerMember, false, true, true, now); err != nil {
		t.Fatal("explicit owner recovery", err)
	}
	if err := d.AuthorizeTeamSession(t.Context(), p, team.ID, now); err != nil {
		t.Fatal(err)
	}
	companyTestEligibility(t, d, c, admin.IdentityID, 1, true, now)
	if !companyTestActive(t, d, admin.ID, now) {
		t.Fatal("approved admin not eligible")
	}
	companyTestEligibility(t, d, c, admin.IdentityID, 2, false, now)
	if companyTestActive(t, d, admin.ID, now) {
		t.Fatal("suspended admin retained access")
	}
	companyTestEligibility(t, d, c, admin.IdentityID, 3, true, now)
	after, err := d.getMembership(t.Context(), team.ID, admin.ID)
	if err != nil || after.Role != TeamRoleAdmin || after.ID != admin.ID || after.ManagedLabel != admin.ManagedLabel || after.MemberSlug != admin.MemberSlug {
		t.Fatalf("resume lost authority or namespace: %+v %v", after, err)
	}
	if err = d.SetCompanyMembershipDecision(t.Context(), p, team.ID, admin.ID, true, false, false, now); err != nil {
		t.Fatal(err)
	}
	companyTestEligibility(t, d, c, admin.IdentityID, 4, true, now)
	if companyTestActive(t, d, admin.ID, now) {
		t.Fatal("sync cleared manual suspension")
	}
	if err = d.SetCompanyMembershipDecision(t.Context(), p, team.ID, admin.ID, false, false, false, now); err != nil {
		t.Fatal(err)
	}
	if err = d.RemoveMembership(WithControlPrincipal(t.Context(), p), owner, team.ID, admin.ID, now); err != nil {
		t.Fatal(err)
	}
	companyTestEligibility(t, d, c, admin.IdentityID, 5, true, now)
	if companyTestActive(t, d, admin.ID, now) {
		t.Fatal("sync resurrected manual removal")
	}
	var count int
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.team_memberships WHERE team_id=$1 AND identity_id=$2`, team.ID, admin.IdentityID).Scan(&count); err != nil || count != 1 {
		t.Fatal("sync recreated removed membership", count, err)
	}
	insertAuthorityIdentity(t, d, "identity_managed", "", false, now)
	r := companyTestEligibility(t, d, c, "identity_managed", 1, true, now)
	var member, role, slug, state string
	if err = d.pool.QueryRow(t.Context(), `SELECT m.id,m.role,s.member_slug,s.state FROM control.team_memberships m JOIN control.member_slug_reservations s ON s.id=m.slug_reservation_id WHERE m.team_id=$1 AND m.identity_id=$2 AND m.identity_connection_id=$3`, team.ID, r.IdentityID, c.ID).Scan(&member, &role, &slug, &state); err != nil || role != "member" || state != "active" {
		t.Fatal("managed admission", role, state, err)
	}
	if err = d.ProvisionCompanyEligibility(t.Context(), c.ProvisioningToken, r, now); err != nil {
		t.Fatal("idempotent delta", err)
	}
	r.Eligible = false
	if err = d.ProvisionCompanyEligibility(t.Context(), c.ProvisioningToken, r, now); !errors.Is(err, ErrAuthorityIdempotency) {
		t.Fatal("changed retry", err)
	}
	r.Revision = 2
	if err = d.ProvisionCompanyEligibility(t.Context(), c.ProvisioningToken, r, now); err != nil {
		t.Fatal(err)
	}
	r.Revision = 1
	r.Eligible = true
	if err = d.ProvisionCompanyEligibility(t.Context(), c.ProvisioningToken, r, now); !errors.Is(err, ErrAuthorityConflict) {
		t.Fatal("stale sync restored access", err)
	}
	if companyTestActive(t, d, member, now) {
		t.Fatal("stale sync active")
	}
	other := authorityTeamRequest(owner)
	other.IdempotencyKey = "other"
	other.DisplayName = "other-team"
	otherTeam, err := d.CreateTeam(t.Context(), other, now)
	if err != nil {
		t.Fatal(err)
	}
	r.TeamID = otherTeam.ID
	r.Revision = 3
	if err = d.ProvisionCompanyEligibility(t.Context(), c.ProvisioningToken, r, now); !errors.Is(err, ErrAuthorityAccess) {
		t.Fatal("cross-team provisioning", err)
	}
	r.TeamID = team.ID
	if err = d.ProvisionCompanyEligibility(t.Context(), "wrong-token", r, now); !errors.Is(err, ErrAuthorityAccess) {
		t.Fatal("unscoped provisioning", err)
	}
	// replacing a source fences its credential and cannot re-admit its managed
	// members. the owner must make a new explicit membership decision.
	setup, err := d.BeginIdentityConnectionSetup(t.Context(), p, CreateIdentityConnectionRequest{TeamID: team.ID, Issuer: c.Issuer, SourceID: "replacement-source", Admission: "managed", ReplaceID: c.ID, ExpectedRevision: c.Revision}, now)
	if err != nil {
		t.Fatal(err)
	}
	replacement := companyActivateTestSetup(t, d, setup, p, now, companyTestProvisioningToken(t))
	if err = d.ProvisionCompanyEligibility(t.Context(), c.ProvisioningToken, r, now); !errors.Is(err, ErrAuthorityAccess) {
		t.Fatal("retired source accepted", err)
	}
	r.IdentityConnectionID = replacement.ID
	r.ConnectionRevision = replacement.Revision
	if err = d.ProvisionCompanyEligibility(t.Context(), replacement.ProvisioningToken, r, now); err != nil {
		t.Fatal("replacement could not record independent eligibility", err)
	}
	var binding string
	if err = d.pool.QueryRow(t.Context(), `SELECT identity_connection_id FROM control.team_memberships WHERE id=$1`, member).Scan(&binding); err != nil || binding != c.ID || companyTestActive(t, d, member, now) {
		t.Fatal("replacement eligibility silently rebound membership", binding, err)
	}
	eligibility, err := controlstatedb.New(d.pool).GetCompanyEligibility(t.Context(), controlstatedb.GetCompanyEligibilityParams{IdentityConnectionID: replacement.ID, IdentityID: r.IdentityID})
	if err != nil || !eligibility.Eligible || eligibility.Revision != r.Revision {
		t.Fatal("replacement eligibility was not retained", eligibility, err)
	}
	var audits int
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.company_access_audit WHERE team_id=$1`, team.ID).Scan(&audits); err != nil || audits < 8 {
		t.Fatal("missing company audit", audits, err)
	}
}

func TestIntegrationCompanyAuthenticationProofScopeAndContractor(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	p := companyTestPrincipal(t, d, newOIDCSession(t, d, now), now)
	identity := OIDCIdentity{Issuer: "https://company.example", Subject: "broker-subject", DisplayName: "Company user"}
	person, err := d.EnsureServiceIdentity(t.Context(), "tunnels.example.test", identity, now)
	if err != nil {
		t.Fatal(err)
	}
	c := companyTestConnection(t, d, team.ID, p, "approval", now)
	companyTestEligibility(t, d, c, person.Identity.ID, 1, true, now)
	var count int
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.team_memberships WHERE team_id=$1 AND identity_id=$2`, team.ID, person.Identity.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("approval mode admitted membership", count, err)
	}
	var ownerMember string
	if err = d.pool.QueryRow(t.Context(), `SELECT id FROM control.team_memberships WHERE team_id=$1 AND identity_id=$2`, team.ID, owner).Scan(&ownerMember); err != nil {
		t.Fatal(err)
	}
	if err = d.SetCompanyMembershipDecision(t.Context(), p, team.ID, ownerMember, false, true, true, now); err != nil {
		t.Fatal(err)
	}
	invitation, err := d.CreateTeamInvitation(WithControlPrincipal(t.Context(), p), authorityInvitationRequest(owner, team.ID, "company-user", now), now)
	if err != nil {
		t.Fatal(err)
	}
	member, err := d.AcceptInvitation(t.Context(), person.Identity.ID, credentials.InvitationToken(invitation.Secret), now)
	if err != nil {
		t.Fatal(err)
	}
	exchange := func(v OIDCIdentity, nonce string, at time.Time) (ControlSession, error) {
		v.AssertionDigest = sha256.Sum256([]byte(nonce))
		v.AssertionExpiry = at.Add(2 * time.Hour)
		v, err = companyBindTestIntent(t, d, v, at)
		if err != nil {
			return ControlSession{}, err
		}
		return d.CreateOIDCControlSession(t.Context(), "tunnels.example.test", v, time.Hour, 24*time.Hour, at)
	}
	personal, err := exchange(identity, "personal", now)
	if err != nil {
		t.Fatal(err)
	}
	personalPrincipal := companyTestPrincipal(t, d, personal, now)
	if err = d.AuthorizeTeamSession(t.Context(), personalPrincipal, team.ID, now); !errors.Is(err, ErrAuthorityAccess) {
		t.Fatal("linked account metadata authorized personal sign-in", err)
	}
	proof := oidcauth.TeamContext{TeamID: team.ID, IdentityConnectionID: c.ID, ConnectionRevision: c.Revision, SourceID: c.SourceID, Subject: "directory/" + person.Identity.ID, AuthenticatedAt: now.Unix()}
	identity.TeamContexts = []oidcauth.TeamContext{proof}
	company, err := exchange(identity, "company", now)
	if err != nil {
		t.Fatal(err)
	}
	companyPrincipal := companyTestPrincipal(t, d, company, now)
	if err = d.AuthorizeTeamSession(t.Context(), companyPrincipal, team.ID, now); err != nil {
		t.Fatal("company sign-in denied", err)
	}
	for _, change := range []string{"issuer", "identity"} {
		other := identity
		if change == "issuer" {
			other.Issuer = "https://other-issuer.example"
		} else {
			other.Subject = "other-identity"
		}
		if _, err = exchange(other, "wrong-"+change, now); !errors.Is(err, ErrControlAuthentication) {
			t.Fatal("company proof escaped identity or issuer", change, err)
		}
	}
	if _, err = exchange(identity, "company", now); !errors.Is(err, ErrOIDCAssertionReplay) {
		t.Fatal("proof token replay", err)
	}
	for i, mutate := range []func(*oidcauth.TeamContext){func(p *oidcauth.TeamContext) { p.TeamID = personal.Identity.PersonalTeamID }, func(p *oidcauth.TeamContext) { p.IdentityConnectionID = "icn_other" }, func(p *oidcauth.TeamContext) { p.ConnectionRevision++ }, func(p *oidcauth.TeamContext) { p.SourceID = "wrong-source" }, func(p *oidcauth.TeamContext) { p.Subject = "another-directory-subject" }, func(p *oidcauth.TeamContext) { p.AuthenticatedAt = now.Add(time.Second).Unix() }, func(p *oidcauth.TeamContext) { p.AuthenticatedAt = now.Add(-2 * time.Hour).Unix() }} {
		bad := proof
		mutate(&bad)
		identity.TeamContexts = []oidcauth.TeamContext{bad}
		if _, err = exchange(identity, fmt.Sprint("bad-", i), now); err == nil {
			t.Fatal("accepted proof scope", i)
		}
	}
	if err = d.AuthorizeTeamSession(t.Context(), companyPrincipal, team.ID, now.Add(CompanyAuthenticationLifetime)); !errors.Is(err, ErrAuthorityAccess) {
		t.Fatal("authentication freshness extended", err)
	}
	// the same active subject rule covers identity visitor grants, private
	// services and service-client certificate issuance, not just team API calls.
	ownerCtx := WithControlPrincipal(t.Context(), p)
	companyCtx, personalCtx := WithControlPrincipal(t.Context(), companyPrincipal), WithControlPrincipal(t.Context(), personalPrincipal)
	domains, err := d.ListTeamDomains(ownerCtx, owner, team.ID)
	if err != nil {
		t.Fatal(err)
	}
	namespace, _ := naming.PublicURLNamespace(naming.NamespaceFacts{Domain: domains[0].CanonicalDomain, Managed: true, Mode: d.managedURLMode, TeamName: team.DisplayName, MemberSlug: member.MemberSlug, ManagedLabel: member.ManagedLabel})
	public, err := d.CreatePublicURL(companyCtx, CreatePublicURLRequest{TeamID: team.ID, DomainID: domains[0].ID, MembershipID: member.ID, ActingIdentityID: person.Identity.ID, IdempotencyKey: "company-visitor", CanonicalHostname: "app." + namespace, Target: "http://127.0.0.1:3000", PublicURLScope: PublicURLScopeMember, Purpose: PublicURLPurposeApp, DNSState: PublicURLDNSUnmanaged}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.CreateIdentityVisitorGrant(companyCtx, public.ID, person.Identity.ID, "company-member", person.Identity.ID, nil, now); err != nil {
		t.Fatal(err)
	}
	q := controlstatedb.New(d.pool)
	if _, err = identityPermission(personalCtx, q, public.ID, person.Identity.ID, "", now); !errors.Is(err, ErrVisitorSignIn) {
		t.Fatal("personal browser provenance bypass", err)
	}
	if permission, err := identityPermission(companyCtx, q, public.ID, person.Identity.ID, "", now); err != nil || !permission.VisitAllowed || permission.ExpiresAt == nil || permission.ExpiresAt.After(now.Add(CompanyAuthenticationLifetime)) {
		t.Fatal("company browser permission", permission, err)
	}
	service, err := d.CreatePrivateService(ownerCtx, team.ID, owner, "company-private", "company-private", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.CreatePrivateServiceGrant(ownerCtx, service.ID, owner, "company-grant", "identity", person.Identity.ID, nil, now); err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := d.EnrollVisitorDevice(personalCtx, person.Identity.ID, pub, now)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.IssueServiceClientCertificate(personalCtx, service.ID, person.Identity.ID, device.ID, csr, now); !errors.Is(err, ErrPrivateServiceAccess) {
		t.Fatal("personal mTLS issuance bypass", err)
	}
	issued, err := d.IssueServiceClientCertificate(companyCtx, service.ID, person.Identity.ID, device.ID, csr, now)
	if err != nil || issued.CertificatePEM == "" {
		t.Fatal("company mTLS issuance", err)
	}
	var boundSession string
	if err = d.pool.QueryRow(t.Context(), `SELECT control_session_id FROM control.service_client_certificates WHERE private_service_id=$1 AND identity_id=$2`, service.ID, person.Identity.ID).Scan(&boundSession); err != nil || boundSession != companyPrincipal.SessionID {
		t.Fatal("mTLS identity lost exact session provenance", boundSession, err)
	}
	// expire the company proof while the leaf remains valid, then reauthenticate
	// and replay the immutable issuance CSR to rebind without another certificate.
	if _, err := d.IssueServiceClientCertificate(companyCtx, service.ID, person.Identity.ID, device.ID, csr, now.Add(CompanyAuthenticationLifetime)); !errors.Is(err, ErrPrivateServiceAccess) {
		t.Fatal("cached certificate extended expired company proof", err)
	}
	proof.AuthenticatedAt = now.Add(time.Minute).Unix()
	identity.TeamContexts = []oidcauth.TeamContext{proof}
	fresh, err := exchange(identity, "fresh-company", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	freshPrincipal := companyTestPrincipal(t, d, fresh, now.Add(time.Minute))
	freshCtx := WithControlPrincipal(t.Context(), freshPrincipal)
	rebound, err := d.IssueServiceClientCertificate(freshCtx, service.ID, person.Identity.ID, device.ID, csr, now.Add(time.Minute))
	if err != nil || rebound != issued {
		t.Fatal("fresh company sign-in did not reuse issued certificate", err)
	}
	if err = d.pool.QueryRow(t.Context(), `SELECT control_session_id FROM control.service_client_certificates WHERE private_service_id=$1 AND identity_id=$2`, service.ID, person.Identity.ID).Scan(&boundSession); err != nil || boundSession != freshPrincipal.SessionID {
		t.Fatal("certificate was not rebound to current company proof", boundSession, err)
	}
	companyTestEligibility(t, d, c, person.Identity.ID, 2, false, now)
	if _, err = d.IssueServiceClientCertificate(companyCtx, service.ID, person.Identity.ID, device.ID, csr, now); !errors.Is(err, ErrPrivateServiceAccess) {
		t.Fatal("offboarded mTLS CSR retry authorized", err)
	}
	if permission, err := identityPermission(companyCtx, q, public.ID, person.Identity.ID, "", now); err != nil || permission.VisitAllowed {
		t.Fatal("explicit public identity grant bypassed suspension", permission, err)
	}
	companyTestEligibility(t, d, c, person.Identity.ID, 3, true, now)
	if err = d.SetCompanyMembershipDecision(t.Context(), p, team.ID, member.ID, false, true, false, now); err != nil {
		t.Fatal(err)
	}
	companyTestEligibility(t, d, c, person.Identity.ID, 4, false, now)
	if err = d.AuthorizeTeamSession(t.Context(), personalPrincipal, team.ID, now); err != nil {
		t.Fatal("explicit contractor exception denied personal account", err)
	}
	if err = d.SetCompanyMembershipDecision(t.Context(), p, team.ID, member.ID, true, true, false, now); err != nil {
		t.Fatal(err)
	}
	if err = d.AuthorizeTeamSession(t.Context(), personalPrincipal, team.ID, now); !errors.Is(err, ErrAuthorityAccess) {
		t.Fatal("contractor exception bypassed manual suspension", err)
	}
}

func TestIntegrationCompanyOffboardingClosesMemberPublicAndPrivateRuns(t *testing.T) {
	f := newTransactionAuthorityFixture(t)
	d, now := f.database, f.now
	team := f.member.TeamID
	shared := reviewSharedURL(t, f)
	registerCertificatePlanRelays(t, d, now)
	memberPublic, memberKey := reviewPublisher(t, d, f.route, f.member.IdentityID, now)
	teamPublic, teamKey := reviewPublisher(t, d, shared, f.member.IdentityID, now)
	if memberPublic.Ownership != "member" || teamPublic.Ownership != "team" {
		t.Fatal("implicit publisher ownership", memberPublic, teamPublic)
	}
	service, err := d.CreatePrivateService(t.Context(), team, f.member.IdentityID, "offboarding", "create", now, PrivateServiceMetadata{Protocol: "tcp", PublisherPool: true})
	if err != nil {
		t.Fatal(err)
	}
	privatePublisher := func(ownership string) (PublisherIdentity, ed25519.PrivateKey) {
		t.Helper()
		m, err := controlstatedb.New(d.pool).GetActivePublishRunMembership(t.Context(), controlstatedb.GetActivePublishRunMembershipParams{TeamID: team, IdentityID: f.member.IdentityID})
		if err != nil {
			t.Fatal(err)
		}
		e, err := d.IssuePublisherEnrollment(t.Context(), CreatePublisherEnrollmentRequest{Ownership: ownership, Scope: PublisherScope{TeamID: team, Kind: "private_service", PrivateServiceID: service.ID}, Name: ownership, Kind: "installed", EditorID: f.member.IdentityID, EditorMembershipID: m.ID, PolicyRevision: uint64(m.PolicyRevision), Now: now})
		if err != nil {
			t.Fatal(err)
		}
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		p, err := d.RedeemPublisherEnrollment(t.Context(), e.Key, pub, now)
		if err != nil {
			t.Fatal(err)
		}
		return p, key
	}
	memberPrivate, memberPrivateKey := privatePublisher("member")
	teamPrivate, teamPrivateKey := privatePublisher("team")
	groupRequest := ApplyProjectConfigurationRequest{TeamID: team, ActorID: f.member.IdentityID, ProjectKey: "company-publishers", SourceFingerprint: strings.Repeat("a", 64), Configuration: ProjectConfiguration{Publishers: map[string]ProjectPublisherGroup{"production": {}}, Services: map[string]ProjectServiceConfiguration{"group-database": {Publisher: "production", Protocol: "postgres", Target: "localhost:5432"}}}, Now: now}
	if _, err = d.ApplyProjectConfiguration(t.Context(), groupRequest); err != nil {
		t.Fatal(err)
	}
	groupEnrollment, err := d.IssuePublisherGroupEnrollment(t.Context(), team, groupRequest.ProjectKey, "production", f.member.IdentityID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	ownerSession, err := createTestControlSession(t.Context(), d, "managed.example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	ownerPrincipal, err := d.AuthenticateAccessToken(t.Context(), ownerSession.AccessToken, now)
	if err != nil {
		t.Fatal(err)
	}
	c := companyTestConnection(t, d, team, ownerPrincipal, "managed", now)
	companyTestEligibility(t, d, c, f.member.IdentityID, 1, true, now)
	memberRun, err := d.CreatePublishRun(t.Context(), reviewRunRequest(t, d, memberPublic, memberKey, f.route, "member"), now, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	teamRun, err := d.CreatePublishRun(t.Context(), reviewRunRequest(t, d, teamPublic, teamKey, shared, "team"), now, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leases := map[string]RelayLease{}
	for i := range 2 {
		name := fmt.Sprintf("plan-relay-%d", i)
		leases[name] = RelayLease{RelayLeaseIdentity: RelayLeaseIdentity{RelayServiceID: name, RelayID: name, RelayRunID: name + "-run", RelayLeaseRevision: 1}}
	}
	privateRun := readyAppliedPrivateRun(t, d, PublisherAccess{PublisherIdentity: memberPrivate}, memberPrivateKey, service, leases, now)
	teamPrivateRun := readyAppliedPrivateRun(t, d, PublisherAccess{PublisherIdentity: teamPrivate}, teamPrivateKey, service, leases, now)
	var beforeRefresh int64
	if err = d.pool.QueryRow(t.Context(), `SELECT policy_revision FROM control.teams WHERE id=$1`, team).Scan(&beforeRefresh); err != nil {
		t.Fatal(err)
	}
	companyTestEligibility(t, d, c, f.member.IdentityID, 2, true, now)
	var afterRefresh int64
	if err = d.pool.QueryRow(t.Context(), `SELECT policy_revision FROM control.teams WHERE id=$1`, team).Scan(&afterRefresh); err != nil || beforeRefresh != afterRefresh {
		t.Fatal("healthy directory refresh disconnected visitors", beforeRefresh, afterRefresh, err)
	}
	companyTestEligibility(t, d, c, f.member.IdentityID, 3, false, now)
	for _, id := range []string{memberRun.PublishRunID, privateRun.RunID} {
		var closed bool
		if err = d.pool.QueryRow(t.Context(), `SELECT closed_at IS NOT NULL FROM control.publish_runs WHERE id=$1 UNION ALL SELECT closed_at IS NOT NULL FROM control.private_service_runs WHERE id=$1`, id).Scan(&closed); err != nil || !closed {
			t.Fatal("member run remained open", id, closed, err)
		}
	}
	assertion, err := publisheridentity.Sign(memberPublic.ID, memberPublic.KeyID, memberPublic.GrantID, publisherTestAudience, memberKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.ExchangePublisherAssertion(t.Context(), memberPublic.ID, memberPublic.GrantID, publisherTestAudience, assertion, "", now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("member credential survived", err)
	}
	if _, err = d.HeartbeatPrivateServiceRun(t.Context(), service.ID, privateRun.RunID, privateRun.Token, now, PrivateRunHealth{Healthy: true, StreamCapacity: 64}); !errors.Is(err, ErrPrivateServiceAccess) {
		t.Fatal("offboarded member private run renewed", err)
	}
	replica := enrollAppliedGroup(t, d, groupRequest, groupEnrollment, now)
	var groupOwnership string
	if err = d.pool.QueryRow(t.Context(), `SELECT ownership FROM control.publisher_identities WHERE id=$1`, replica.member.PublisherIdentityID).Scan(&groupOwnership); err != nil || groupOwnership != "team" {
		t.Fatal("group creator remained runtime owner", groupOwnership, err)
	}
	auth := PublishRunAuthentication{PublishRunID: teamRun.PublishRunID, PublicURLID: shared.ID, PublishRunNumber: teamRun.PublishRunNumber, PublishRunToken: teamRun.PublishRunToken}
	if _, err = d.HeartbeatPublishRun(t.Context(), auth, now, time.Hour, time.Hour); err != nil {
		t.Fatal("team-owned public publisher depended on creator", err)
	}
	if _, err = d.HeartbeatPrivateServiceRun(t.Context(), service.ID, teamPrivateRun.RunID, teamPrivateRun.Token, now, PrivateRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal("team-owned private publisher depended on creator", err)
	}
	url, err := d.GetPublicURLForAuthorization(t.Context(), f.route.ID)
	if err != nil || url.LifecycleState != PublicURLLifecycleEnabled {
		t.Fatal("offboarding destructively suspended saved URL", url, err)
	}
	companyTestEligibility(t, d, c, f.member.IdentityID, 4, true, now)
	if !companyTestActive(t, d, f.member.ID, now) {
		t.Fatal("resumption lost membership")
	}
	if _, err = d.CreatePublishRun(t.Context(), reviewRunRequest(t, d, memberPublic, memberKey, url, "resumed"), now, time.Hour, time.Hour); err != nil {
		t.Fatal("resumption could not republish saved URL", err)
	}
	// explicit identity visitor grants cannot bypass company suspension.
	companyTestEligibility(t, d, c, f.member.IdentityID, 5, false, now)
	tx, err := d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, _, err = privateVisitorAccess(context.Background(), tx, service.ID, f.member.IdentityID, now); !errors.Is(err, ErrPrivateServiceAccess) {
		t.Fatal("private identity grant bypassed offboarding", err)
	}
	if err = tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	fresh := companyTestEligibility(t, d, c, f.member.IdentityID, 6, true, now)
	fresh.Revision = 7
	fresh.ValidUntil = now.Add(time.Second)
	if err = d.ProvisionCompanyEligibility(t.Context(), c.ProvisioningToken, fresh, now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.ExpireSavedPublishRuns(t.Context(), now.Add(2*time.Second)); err != nil {
		t.Fatal("expire company eligibility", err)
	}
	if companyTestActive(t, d, f.member.ID, now.Add(2*time.Second)) {
		t.Fatal("expired company eligibility retained authority")
	}
	var revision int64
	if err = d.pool.QueryRow(t.Context(), `SELECT policy_revision FROM control.teams WHERE id=$1`, team).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if _, err = d.ExpireSavedPublishRuns(t.Context(), now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	var repeated int64
	if err = d.pool.QueryRow(t.Context(), `SELECT policy_revision FROM control.teams WHERE id=$1`, team).Scan(&repeated); err != nil || repeated != revision {
		t.Fatal("expiration repeatedly invalidated policy", revision, repeated, err)
	}
}
