package public

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/testutil/managedcert"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

type companyMembershipSnapshot struct {
	ID, TeamID, IdentityID, SourceID, Role, Slug, ManagedLabel string
	Exception                                                  bool
	SuspendedAt, RemovedAt                                     pgtype.Timestamptz
}

func (f *companyHTTPFixture) membership(identity, team string) companyMembershipSnapshot {
	f.t.Helper()
	var m companyMembershipSnapshot
	err := f.sql.QueryRow(f.t.Context(), `SELECT m.id,m.team_id,m.identity_id,COALESCE(m.identity_connection_id,''),m.role,s.member_slug,m.managed_label,m.personal_account_exception,m.manual_suspended_at,m.removed_at FROM control.team_memberships m JOIN control.member_slug_reservations s ON s.id=m.slug_reservation_id WHERE m.identity_id=$1 AND m.team_id=$2 ORDER BY (m.removed_at IS NULL) DESC,m.created_at DESC,m.id DESC LIMIT 1`, identity, team).Scan(&m.ID, &m.TeamID, &m.IdentityID, &m.SourceID, &m.Role, &m.Slug, &m.ManagedLabel, &m.Exception, &m.SuspendedAt, &m.RemovedAt)
	if err != nil {
		f.t.Fatal(err)
	}
	return m
}

func (f *companyHTTPFixture) active(m companyMembershipSnapshot) bool {
	f.t.Helper()
	var active bool
	if err := f.sql.QueryRow(f.t.Context(), `SELECT control.active_membership($1,$2)`, m.ID, time.Now().UTC()).Scan(&active); err != nil {
		f.t.Fatal(err)
	}
	return active
}

func TestIntegrationCompanySuccessfulSourceReplacementAndExplicitRebind(t *testing.T) {
	f := newCompanyHTTPFixture(t, "company_successful_replacement")
	ctx := t.Context()
	d := f.d
	type person struct {
		sub, dir, slug    string
		personal, company authorityv1.ControlSessionResponse
		before            companyMembershipSnapshot
	}
	newPerson := func(label string, n int) *person {
		t.Helper()
		p := &person{sub: fmt.Sprintf("00000000-0000-4000-8000-%012d", n), dir: "a/" + label, slug: label}
		p.personal = f.basic(p.sub)
		return p
	}
	founder := newPerson("founder", 1)
	team, err := d.CreateTeam(ctx, controlstate.CreateTeamRequest{IdentityID: founder.personal.Identity.Identity.Id, DisplayName: "company-replacement", MemberSlug: "founder", IdempotencyKey: "team", RequestDigest: sha256.Sum256([]byte("company-replacement"))}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	base := "/v1/service/teams/" + team.ID + "/identity-connections"
	var aSetup controlstate.IdentityConnectionSetup
	f.decode(f.ownerCall("POST", base, founder.sub, nil, authorityv1.CreateIdentityConnectionRequest{SourceId: "source-a", Admission: authorityv1.CreateConnectionManaged}), 201, &aSetup)
	f.decode(f.provision(aSetup.IdentityConnection, aSetup.SetupToken, founder.sub, founder.dir, 1, true, founder.slug), 204, nil)
	var a controlstate.IdentityConnectionSecret
	f.decode(f.ownerCall("POST", base+"/"+aSetup.ID+"/activate", founder.sub, f.proof(aSetup.IdentityConnection, founder.dir), f.activationRequest(aSetup)), 200, &a)
	founder.company = f.login(a.IdentityConnection, founder.sub, founder.dir)
	owner := newPerson("consenting-owner", 2)
	admin := newPerson("admin", 3)
	formerAdmin := newPerson("former-admin", 4)
	employee := newPerson("employee", 5)
	suspended := newPerson("suspended", 6)
	removed := newPerson("removed", 7)
	contractor := newPerson("contractor", 8)
	stagedNew := newPerson("staged-new", 9)
	people := []*person{owner, admin, formerAdmin, employee, suspended, removed, contractor}
	for _, p := range people {
		f.decode(f.provision(a.IdentityConnection, a.ProvisioningToken, p.sub, p.dir, 1, true, p.slug), 204, nil)
		p.company = f.login(a.IdentityConnection, p.sub, p.dir)
		p.before = f.membership(p.personal.Identity.Identity.Id, team.ID)
		if p.before.SourceID != a.ID || p.before.Role != "member" || !f.active(p.before) {
			t.Fatal("source A did not perform real managed admission", p.before)
		}
	}
	founderPrincipal := f.principal(founder.company)
	founderCtx := controlstate.WithControlPrincipal(ctx, founderPrincipal)
	for _, change := range []struct {
		p    *person
		role controlstate.TeamRole
	}{{owner, controlstate.TeamRoleOwner}, {admin, controlstate.TeamRoleAdmin}, {formerAdmin, controlstate.TeamRoleAdmin}, {formerAdmin, controlstate.TeamRoleMember}} {
		if _, err = d.SetMembershipRole(founderCtx, founderPrincipal.IdentityID, team.ID, change.p.before.ID, change.role, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	ownerPrincipal := f.principal(owner.company)
	ownerCtx := controlstate.WithControlPrincipal(ctx, ownerPrincipal)
	if err = d.UpdateCompanyMembershipDecision(ownerCtx, ownerPrincipal, team.ID, suspended.before.ID, controlstate.CompanyMembershipDecision{Suspended: true}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err = d.UpdateCompanyMembershipDecision(ownerCtx, ownerPrincipal, team.ID, contractor.before.ID, controlstate.CompanyMembershipDecision{PersonalAccountException: true}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err = d.RemoveMembership(ownerCtx, ownerPrincipal.IdentityID, team.ID, removed.before.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	for _, p := range people {
		p.before = f.membership(p.personal.Identity.Identity.Id, team.ID)
	}
	founder.before = f.membership(founder.personal.Identity.Identity.Id, team.ID)
	// the unattended publishers belong to the team; their admin creator will
	// remain bound to A and lose membership access until explicitly rebound.
	publicTeam, publicMember, privateTeam, privateMember := replacementPublications(t, f, team, founder.company, admin.company, admin.before)
	client, err := clientauthority.New(f.server.URL, f.server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	oldIntent, err := client.CreateCompanyLoginIntent(ctx, team.ID)
	if err != nil || oldIntent.BindingToken == nil {
		t.Fatal("prepare old-source login intent", err)
	}
	replacementBody := authorityv1.CreateIdentityConnectionRequest{SourceId: "source-b", Admission: authorityv1.CreateConnectionManaged, ReplaceId: &a.ID, ExpectedRevision: &a.Revision}
	var bSetup controlstate.IdentityConnectionSetup
	f.decode(f.ownerCall("POST", base, owner.sub, f.proof(a.IdentityConnection, owner.dir), replacementBody), 201, &bSetup)
	// pending sync records B's directory facts without mutating A's memberships,
	// creating staged accounts, or changing any manual decision.
	staged := []*person{founder, owner, formerAdmin, employee, suspended, removed, contractor, stagedNew}
	for _, p := range staged {
		f.decode(f.provision(bSetup.IdentityConnection, bSetup.SetupToken, p.sub, "b/"+p.slug, 1, p != contractor, p.slug), 204, nil)
	}
	for _, p := range people {
		if got := f.membership(p.personal.Identity.Identity.Id, team.ID); got != p.before {
			t.Fatal("pending sync changed membership", p.slug, p.before, got)
		}
	}
	if !f.active(admin.before) || !f.active(employee.before) {
		t.Fatal("pending replacement suspended current source")
	}
	var stagedMemberships int
	if err = f.sql.QueryRow(ctx, `SELECT count(*) FROM control.team_memberships WHERE identity_id=$1 AND team_id=$2`, stagedNew.personal.Identity.Identity.Id, team.ID).Scan(&stagedMemberships); err != nil || stagedMemberships != 0 {
		t.Fatal("pending sync admitted a new member", stagedMemberships, err)
	}
	activation := base + "/" + bSetup.ID + "/activate"
	activationBody := f.activationRequest(bSetup)
	ownerProof := append(f.proof(a.IdentityConnection, owner.dir), f.proof(bSetup.IdentityConnection, "b/"+owner.slug)...)
	// neither a different current owner nor staged eligibility can replace the
	// consenting identity or bypass a current-source eligibility suspension.
	f.decode(f.ownerCall("POST", activation, founder.sub, append(f.proof(a.IdentityConnection, founder.dir), f.proof(bSetup.IdentityConnection, "b/"+founder.slug)...), activationBody), 409, nil)
	f.decode(f.provision(a.IdentityConnection, a.ProvisioningToken, owner.sub, owner.dir, 2, false, owner.slug), 204, nil)
	f.decode(f.ownerCall("POST", activation, owner.sub, ownerProof, activationBody), 403, nil)
	f.decode(f.provision(a.IdentityConnection, a.ProvisioningToken, owner.sub, owner.dir, 3, true, owner.slug), 204, nil)
	activationBytes := f.encode(activationBody)
	activationToken := f.token(owner.sub, controlstate.CompanyActorNonce("POST", activation, activationBytes), ownerProof)
	var b controlstate.IdentityConnectionSecret
	f.decode(f.call("POST", activation, companyWebsiteSecret, activationToken, activationBytes), 200, &b)
	if b.ID == a.ID || b.Revision != bSetup.Revision+1 {
		t.Fatal("replacement did not advance a distinct source")
	}
	// bootstrap is only the consenting owner's explicit source transition, with
	// the same membership and identity. no other membership is automatically moved.
	expectedOwner := owner.before
	expectedOwner.SourceID = b.ID
	if got := f.membership(owner.personal.Identity.Identity.Id, team.ID); got != expectedOwner || !f.active(got) {
		t.Fatal("owner bootstrap lost identity, policy or access", expectedOwner, got)
	}
	for _, p := range []*person{admin, formerAdmin, employee, suspended, removed, contractor} {
		if got := f.membership(p.personal.Identity.Identity.Id, team.ID); got != p.before {
			t.Fatal("activation silently rebound another membership", p.slug, p.before, got)
		}
	}
	var bootstraps int
	if err = f.sql.QueryRow(ctx, `SELECT count(*) FROM control.company_access_audit WHERE identity_connection_id=$1 AND operation='connection.activate' AND actor_identity_id=$2 AND target_identity_id=$2 AND details->>'bootstrap_membership_id'=$3 AND details->>'previous_connection_id'=$4`, b.ID, owner.personal.Identity.Identity.Id, owner.before.ID, a.ID).Scan(&bootstraps); err != nil || bootstraps != 1 {
		t.Fatal("owner bootstrap was not explicitly audited", bootstraps, err)
	}
	newOwnerSession := f.login(b.IdentityConnection, owner.sub, "b/"+owner.slug)
	if newOwnerSession.Identity.Identity.Id != owner.personal.Identity.Identity.Id || newOwnerSession.Identity.PersonalTeamId != owner.personal.Identity.PersonalTeamId {
		t.Fatal("replacement changed the consenting owner's account")
	}
	f.decode(f.call("GET", "/v1/teams/"+team.ID, newOwnerSession.AccessToken, "", nil), 200, nil)
	f.decode(f.ownerCall("GET", base, owner.sub, f.proof(b.IdentityConnection, "b/"+owner.slug), nil), 200, nil)
	newOwnerPrincipal := f.principal(newOwnerSession)
	newOwnerCtx := controlstate.WithControlPrincipal(ctx, newOwnerPrincipal)
	if _, err = d.SetMembershipRole(newOwnerCtx, newOwnerPrincipal.IdentityID, team.ID, founder.before.ID, controlstate.TeamRoleAdmin, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	founder.before = f.membership(founder.personal.Identity.Identity.Id, team.ID)
	if founder.before.Role != "admin" {
		t.Fatal("former owner fixture was not demoted")
	}
	// A's sessions, pending intents, actor proofs and high-revision sync are all
	// obsolete; none may restore access or mutate B after the replacement.
	f.decode(f.call("GET", "/v1/teams/"+team.ID, owner.company.AccessToken, "", nil), 403, nil)
	if _, err = d.RefreshControlSession(ctx, credentials.RefreshToken(owner.company.RefreshToken), time.Hour, time.Now().UTC()); !errors.Is(err, controlstate.ErrControlAuthentication) {
		t.Fatal("old-source session refreshed", err)
	}
	if _, err = client.ResolveCompanyLoginIntent(ctx, oldIntent.IntentId, *oldIntent.BindingToken); err == nil {
		t.Fatal("old-source intent resolved after replacement")
	}
	if _, err = f.exchangeIntent(ctx, oldIntent.IntentId, *oldIntent.BindingToken, f.token(owner.sub, oldIntent.Nonce, f.proof(a.IdentityConnection, owner.dir))); err == nil {
		t.Fatal("old source proof created a company session")
	}
	f.decode(f.ownerCall("GET", base, owner.sub, f.proof(a.IdentityConnection, owner.dir), nil), 403, nil)
	f.decode(f.provision(a.IdentityConnection, a.ProvisioningToken, employee.sub, employee.dir, 1000, true, employee.slug), 403, nil)
	f.decode(f.provision(bSetup.IdentityConnection, bSetup.SetupToken, employee.sub, "b/"+employee.slug, 1000, true, employee.slug), 403, nil)
	staleB := b.IdentityConnection
	staleB.Revision--
	f.decode(f.provision(staleB, b.ProvisioningToken, admin.sub, "b/"+admin.slug, 3, true, admin.slug), 409, nil)
	if replay := f.call("POST", activation, companyWebsiteSecret, activationToken, activationBytes); replay.Code == 200 {
		t.Fatal("activation proof replay changed source")
	}
	// this active-source delta used to fail because the admin is still bound
	// to A. it must record eligibility, without binding or role mutation.
	for _, p := range []*person{admin, formerAdmin, employee, suspended, removed} {
		f.decode(f.provision(b.IdentityConnection, b.ProvisioningToken, p.sub, "b/"+p.slug, 2, true, "ignored-new-slug"), 204, nil)
		if got := f.membership(p.personal.Identity.Identity.Id, team.ID); got != p.before {
			t.Fatal("new-source eligibility changed membership", p.slug, p.before, got)
		}
		if f.active(p.before) {
			t.Fatal("new-source eligibility silently restored old binding", p.slug)
		}
	}
	f.decode(f.provision(b.IdentityConnection, b.ProvisioningToken, admin.sub, "b/"+admin.slug, 1, false, admin.slug), 409, nil)
	f.decode(f.provision(b.IdentityConnection, b.ProvisioningToken, contractor.sub, "b/"+contractor.slug, 2, false, contractor.slug), 204, nil)
	if got := f.membership(contractor.personal.Identity.Identity.Id, team.ID); got != contractor.before {
		t.Fatal("replacement changed contractor exception", got)
	}
	f.decode(f.call("GET", "/v1/teams/"+team.ID, contractor.personal.AccessToken, "", nil), 200, nil)
	// unattended runs continue while their creator's member-owned runs and
	// credentials are denied. their creator has not yet received a B rebind.
	checkReplacementPublications(t, f, publicTeam, publicMember, privateTeam, privateMember)
	admissions := map[*person]authorityv1.CompanyAdmissionRequest{}
	newSessions := map[*person]authorityv1.ControlSessionResponse{}
	for _, p := range []*person{admin, formerAdmin, employee, suspended} {
		s := f.login(b.IdentityConnection, p.sub, "b/"+p.slug)
		newSessions[p] = s
		f.decode(f.call("GET", "/v1/teams/"+team.ID, s.AccessToken, "", nil), 403, nil)
		var request authorityv1.CompanyAdmissionRequest
		f.decode(f.call("POST", "/v1/auth/company-admissions", s.AccessToken, "", f.encode(authorityv1.RequestCompanyAdmissionJSONRequestBody{TeamId: team.ID, IdentityConnectionId: b.ID, ConnectionRevision: b.Revision, MemberSlug: p.slug})), 200, &request)
		if request.State != "pending" {
			t.Fatal("managed mode automatically rebound old source", p.slug, request)
		}
		admissions[p] = request
	}
	decisionPath := "/v1/service/teams/" + team.ID + "/company-admissions/" + admissions[employee].RequestId
	decision := map[string]any{"connection_revision": b.Revision, "decision": "approved"}
	f.decode(f.ownerCall("POST", decisionPath, owner.sub, f.proof(a.IdentityConnection, owner.dir), decision), 403, nil)
	f.decode(f.ownerCall("POST", decisionPath, founder.sub, f.proof(b.IdentityConnection, "b/"+founder.slug), decision), 403, nil)
	f.decode(f.ownerCall("POST", decisionPath, admin.sub, f.proof(b.IdentityConnection, "b/"+admin.slug), decision), 403, nil)
	f.decode(f.ownerCall("POST", decisionPath, formerAdmin.sub, f.proof(b.IdentityConnection, "b/"+formerAdmin.slug), decision), 403, nil)
	f.decode(f.ownerCall("POST", decisionPath, owner.sub, f.proof(b.IdentityConnection, "b/"+owner.slug), map[string]any{"connection_revision": b.Revision - 1, "decision": "approved"}), 409, nil)
	for _, p := range []*person{admin, formerAdmin, employee, suspended} {
		path := "/v1/service/teams/" + team.ID + "/company-admissions/" + admissions[p].RequestId
		f.decode(f.ownerCall("POST", path, owner.sub, f.proof(b.IdentityConnection, "b/"+owner.slug), decision), 204, nil)
		expected := p.before
		expected.SourceID = b.ID
		if got := f.membership(p.personal.Identity.Identity.Id, team.ID); got != expected {
			t.Fatal("explicit rebind changed membership identity, role or manual decision", p.slug, expected, got)
		}
		status := 200
		if p == suspended {
			status = 403
		}
		f.decode(f.call("GET", "/v1/teams/"+team.ID, newSessions[p].AccessToken, "", nil), status, nil)
	}
	// a former admin does not regain administrator/owner authority after rebind.
	f.decode(f.ownerCall("POST", decisionPath, formerAdmin.sub, f.proof(b.IdentityConnection, "b/"+formerAdmin.slug), decision), 403, nil)
	removedSession := f.login(b.IdentityConnection, removed.sub, "b/"+removed.slug)
	f.decode(f.call("GET", "/v1/teams/"+team.ID, removedSession.AccessToken, "", nil), 403, nil)
	f.decode(f.call("POST", "/v1/auth/company-admissions", removedSession.AccessToken, "", f.encode(authorityv1.RequestCompanyAdmissionJSONRequestBody{TeamId: team.ID, IdentityConnectionId: b.ID, ConnectionRevision: b.Revision, MemberSlug: removed.slug})), 409, nil)
	if got := f.membership(removed.personal.Identity.Identity.Id, team.ID); got != removed.before {
		t.Fatal("replacement resurrected removal tombstone", got)
	}
	var removedRows int
	if err = f.sql.QueryRow(ctx, `SELECT count(*) FROM control.team_memberships WHERE identity_id=$1 AND team_id=$2`, removed.before.IdentityID, team.ID).Scan(&removedRows); err != nil || removedRows != 1 {
		t.Fatal("replacement recreated removed membership", removedRows, err)
	}
	// a genuinely new staged account is admitted only by a fresh active delta,
	// while the staged facts alone do not create a membership at activation.
	if err = f.sql.QueryRow(ctx, `SELECT count(*) FROM control.team_memberships WHERE identity_id=$1 AND team_id=$2`, stagedNew.personal.Identity.Identity.Id, team.ID).Scan(&stagedMemberships); err != nil || stagedMemberships != 0 {
		t.Fatal("activation admitted staged account", stagedMemberships, err)
	}
	stagedSession := f.login(b.IdentityConnection, stagedNew.sub, "b/"+stagedNew.slug)
	f.decode(f.call("GET", "/v1/teams/"+team.ID, stagedSession.AccessToken, "", nil), 403, nil)
	f.decode(f.provision(b.IdentityConnection, b.ProvisioningToken, stagedNew.sub, "b/"+stagedNew.slug, 2, true, stagedNew.slug), 204, nil)
	f.decode(f.call("GET", "/v1/teams/"+team.ID, stagedSession.AccessToken, "", nil), 200, nil)
	if got := f.membership(stagedNew.personal.Identity.Identity.Id, team.ID); got.Role != "member" || got.SourceID != b.ID {
		t.Fatal("new-source managed admission escalated", got)
	}
	f.decode(f.provision(a.IdentityConnection, a.ProvisioningToken, employee.sub, employee.dir, 2000, false, employee.slug), 403, nil)
	f.decode(f.call("GET", "/v1/teams/"+team.ID, newSessions[employee].AccessToken, "", nil), 200, nil)
	// resumption permits a new member-owned run without reopening the closed
	// old run or changing the saved URL/namespace. team-owned runs remain live.
	url, err := d.GetPublicURLForAuthorization(ctx, publicMember.url.ID)
	if err != nil {
		t.Fatal(err)
	}
	if url.ID != publicMember.url.ID || url.Namespace != publicMember.url.Namespace || url.LifecycleState != controlstate.PublicURLLifecycleEnabled {
		t.Fatal("replacement lost saved publication", url)
	}
	resumed := replacementPublicRun(t, f, publicMember.publisher, publicMember.key, url, "after-owner-rebind")
	if resumed.PublishRunNumber != publicMember.run.PublishRunNumber+1 {
		t.Fatal("replacement did not retain publish run numbering")
	}
	if _, err = d.HeartbeatPublishRun(ctx, publicTeam.auth(), time.Now().UTC(), time.Hour, time.Hour); err != nil {
		t.Fatal("team public run lost continuity after member rebind", err)
	}
	if _, err = d.HeartbeatServiceRun(ctx, privateTeam.service.ID, privateTeam.run.RunID, privateTeam.run.Token, time.Now().UTC(), controlstate.ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal("team private run lost continuity after member rebind", err)
	}
}

type replacementPublicPublication struct {
	publisher controlstate.PublisherIdentity
	key       ed25519.PrivateKey
	url       controlstate.PublicURL
	run       controlstate.PublishRunSetup
}

func (p replacementPublicPublication) auth() controlstate.PublishRunAuthentication {
	return controlstate.PublishRunAuthentication{PublishRunID: p.run.PublishRunID, PublicURLID: p.url.ID, PublishRunNumber: p.run.PublishRunNumber, PublishRunToken: p.run.PublishRunToken}
}

type replacementPrivatePublication struct {
	publisher controlstate.PublisherIdentity
	service   controlstate.ServiceRecord
	run       controlstate.ServiceRunState
}

func replacementPublicRun(t *testing.T, f *companyHTTPFixture, p controlstate.PublisherIdentity, key ed25519.PrivateKey, url controlstate.PublicURL, attempt string) controlstate.PublishRunSetup {
	t.Helper()
	plan, err := f.d.PublisherRunPlan(t.Context(), p, url, false)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := publisherproof.SignRun(key, url.ID, attempt)
	if err != nil {
		t.Fatal(err)
	}
	run, err := f.d.CreatePublishRun(t.Context(), controlstate.PublishRunRequest{PublicURLID: url.ID, TeamID: url.TeamID, MembershipID: url.MembershipID, ActingIdentityID: p.CreatorID, IdempotencyKey: attempt, RequestDigest: sha256.Sum256([]byte(attempt)), PolicyRevision: uint64(url.PolicyRevision), ExpectedMutationRevision: url.MutationRevision, CertificateCacheKey: plan.CacheKey, CertificateScope: plan.Scope, CertificateIdentifiers: plan.Identifiers, CertificateChallenge: plan.ChallengeMethod, PublisherIdentityID: p.ID, PublisherGrantID: p.GrantID, PublisherKeyID: p.KeyID, PublisherRunProof: proof}, time.Now().UTC(), time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func replacementPublications(t *testing.T, f *companyHTTPFixture, team controlstate.Team, domainOwner, session authorityv1.ControlSessionResponse, member companyMembershipSnapshot) (replacementPublicPublication, replacementPublicPublication, replacementPrivatePublication, replacementPrivatePublication) {
	t.Helper()
	d := f.d
	ctx := t.Context()
	actor := f.principal(session)
	actorCtx := controlstate.WithControlPrincipal(ctx, actor)
	leases := map[string]controlstate.RelayLease{}
	for _, name := range []string{"replacement-relay-a", "replacement-relay-b"} {
		lease, err := d.RegisterRelay(ctx, controlstate.RelayRegistration{RelayServiceID: name, RelayID: name, RelayRunID: name + "-run", ProtocolVersion: 1, RelayAddress: name + ".example.test:443", TLSServerName: name + ".example.test", InternalRelayAddress: name + ".internal:9445", ConnectionCapacity: 100, StreamCapacity: 100}, time.Now().UTC(), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		leases[name] = lease
	}
	// the generic authority worker fixture marks DNS ready without a live DNS
	// provider. publisher identity, key, grants, runs and relay claims are real.
	domainActor := f.principal(domainOwner)
	domain, err := d.ClaimTeamDomain(controlstate.WithControlPrincipal(ctx, domainActor), controlstate.ClaimDomainRequest{IdentityID: domainActor.IdentityID, TeamID: team.ID, IdempotencyKey: "replacement-domain", RequestDigest: sha256.Sum256([]byte("replacement-domain")), Domain: "replacement.example.org"}, time.Now().UTC())
	if err != nil {
		t.Fatal("claim publisher fixture domain", err)
	}
	work, found, err := d.ClaimDNSAuthorityWork(ctx, "replacement-dns", time.Now().UTC(), time.Minute)
	if err != nil || !found {
		t.Fatal("claim DNS fixture", found, err)
	}
	work.State, work.ProviderZoneID, work.Nameservers = "ready", "ZREPLACEMENT", []string{"ns.replacement.example.org"}
	if _, err = d.SaveDNSAuthorityWork(ctx, work, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	enroll := func(scope controlstate.PublisherScope, ownership, name string) (controlstate.PublisherIdentity, ed25519.PrivateKey) {
		t.Helper()
		memberships, err := d.IdentityContext(actorCtx, actor.IdentityID)
		if err != nil {
			t.Fatal(err)
		}
		var revision int64
		for _, m := range memberships.Memberships {
			if m.TeamID == team.ID {
				revision = m.PolicyRevision
			}
		}
		e, err := d.IssuePublisherEnrollment(actorCtx, controlstate.CreatePublisherEnrollmentRequest{Ownership: ownership, Scope: scope, Name: name, Kind: "installed", EditorID: actor.IdentityID, EditorMembershipID: member.ID, PolicyRevision: uint64(revision), Now: time.Now().UTC()})
		if err != nil {
			t.Fatal(err)
		}
		public, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		p, err := d.RedeemPublisherEnrollment(ctx, e.Key, public, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		return p, key
	}
	public := func(ownership string) replacementPublicPublication {
		t.Helper()
		scope := controlstate.PublicURLScopeShared
		membership := ""
		hostname := "team.replacement.example.org"
		if ownership == "member" {
			scope = controlstate.PublicURLScopeMember
			membership = member.ID
			ns, _ := naming.PublicURLNamespace(naming.NamespaceFacts{Domain: domain.CanonicalDomain, Mode: naming.ManagedURLModeGenerated, TeamName: team.DisplayName, MemberSlug: member.Slug, ManagedLabel: member.ManagedLabel})
			hostname = "app." + ns
		}
		u, err := d.CreatePublicURL(actorCtx, controlstate.CreatePublicURLRequest{TeamID: team.ID, DomainID: domain.ID, MembershipID: membership, ActingIdentityID: actor.IdentityID, IdempotencyKey: "replacement-" + ownership, RequestDigest: sha256.Sum256([]byte(ownership)), CanonicalHostname: hostname, Target: "http://127.0.0.1:3000", PublicURLScope: scope, Purpose: controlstate.PublicURLPurposeApp, DNSState: controlstate.PublicURLDNSPending, DNSAuthorityReference: domain.DNSAuthorityReference}, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		p, key := enroll(controlstate.PublisherScope{TeamID: team.ID, Kind: "saved_public_url", PublicURLID: u.ID}, ownership, "public-"+ownership)
		return replacementPublicPublication{publisher: p, key: key, url: u, run: replacementPublicRun(t, f, p, key, u, "before-replacement")}
	}
	teamPublic, memberPublic := public("team"), public("member")
	service, err := d.CreateServiceAt(actorCtx, team.ID, actor.IdentityID, "replacement-private", "replacement-private", controlstate.ServicePlacement{}, time.Now().UTC(), controlstate.ServiceMetadata{Protocol: "tcp", PublisherPool: true})
	if err != nil {
		t.Fatal(err)
	}
	private := func(ownership string) replacementPrivatePublication {
		t.Helper()
		p, _ := enroll(controlstate.PublisherScope{TeamID: team.ID, Kind: "service", ServiceID: service.ID}, ownership, "private-"+ownership)
		prepared, err := d.PrepareServiceRun(ctx, service.ID, p, "before-replacement", time.Now().UTC(), service.ServiceMetadata)
		if err != nil {
			t.Fatal(err)
		}
		run, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, p, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		managedcert.Install(t, d, prepared, run, time.Now().UTC())
		for _, slot := range run.Connections {
			lease := leases[slot.RelayServiceID].RelayLeaseIdentity
			if _, err = d.ClaimServicePublisherConnection(ctx, slot.PublisherConnectionID, service.ID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, lease, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			if _, err = d.ReadyServicePublisherConnection(ctx, slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
		}
		if current, err := d.HeartbeatServiceRun(ctx, service.ID, run.RunID, run.Token, time.Now().UTC(), controlstate.ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil || current.State != "ready" {
			t.Fatal("private publication not ready", current, err)
		}
		return replacementPrivatePublication{publisher: p, service: service, run: run}
	}
	return teamPublic, memberPublic, private("team"), private("member")
}

func checkReplacementPublications(t *testing.T, f *companyHTTPFixture, team, member replacementPublicPublication, privateTeam, privateMember replacementPrivatePublication) {
	t.Helper()
	ctx := t.Context()
	d := f.d
	if team.publisher.Ownership != "team" || privateTeam.publisher.Ownership != "team" || member.publisher.Ownership != "member" || privateMember.publisher.Ownership != "member" {
		t.Fatal("publisher ownership was not explicit")
	}
	if _, err := d.HeartbeatPublishRun(ctx, team.auth(), time.Now().UTC(), time.Hour, time.Hour); err != nil {
		t.Fatal("team-owned public run depended on offboarded creator", err)
	}
	if _, err := d.HeartbeatServiceRun(ctx, privateTeam.service.ID, privateTeam.run.RunID, privateTeam.run.Token, time.Now().UTC(), controlstate.ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal("team-owned private run depended on offboarded creator", err)
	}
	for _, run := range []struct {
		id      string
		private bool
	}{{member.run.PublishRunID, false}, {privateMember.run.RunID, true}} {
		var closed bool
		query := `SELECT closed_at IS NOT NULL FROM control.publish_runs WHERE id=$1`
		if run.private {
			query = `SELECT closed_at IS NOT NULL FROM control.service_runs WHERE id=$1`
		}
		if err := f.sql.QueryRow(ctx, query, run.id).Scan(&closed); err != nil || !closed {
			t.Fatal("member-owned run survived replacement", run.id, closed, err)
		}
	}
	assertion, err := publisherproof.Sign(member.publisher.ID, member.publisher.KeyID, member.publisher.GrantID, "https://control.example/v1/publisher-token", member.key, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.ExchangePublisherAssertion(ctx, member.publisher.ID, member.publisher.GrantID, "https://control.example/v1/publisher-token", assertion, "", time.Now().UTC()); !errors.Is(err, controlstate.ErrPublisherIdentity) {
		t.Fatal("member-owned credential survived old-source suspension", err)
	}
	if _, err = d.HeartbeatServiceRun(ctx, privateMember.service.ID, privateMember.run.RunID, privateMember.run.Token, time.Now().UTC(), controlstate.ServiceRunHealth{Healthy: true, StreamCapacity: 64}); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatal("closed member-owned private run renewed", err)
	}
}
