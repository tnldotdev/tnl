package public

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	"github.com/tnldotdev/tnl/internal/control/oidc"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func TestIntegrationCompanyWebsiteSetupAdmissionAndRefresh(t *testing.T) {
	f := newCompanyHTTPFixture(t, "company_owner_proof")
	d, ctx, now := f.d, t.Context(), f.now
	signer, issuer, mux, server := f.signer, f.issuer, f.mux, f.server
	token, call, encode, ownerCall, decode, basic := f.token, f.call, f.encode, f.ownerCall, f.decode, f.basic
	const website = companyWebsiteSecret
	const ownerSub = "11111111-1111-4111-8111-111111111111"
	const memberSub = "22222222-2222-4222-8222-222222222222"
	owner := basic(ownerSub)
	member := basic(memberSub)
	team, err := d.CreateTeam(ctx, controlstate.CreateTeamRequest{IdentityID: owner.Identity.Identity.Id, DisplayName: "company-proof", MemberSlug: "owner", IdempotencyKey: "team", RequestDigest: sha256.Sum256([]byte("team"))}, now)
	if err != nil {
		t.Fatal(err)
	}
	base := "/v1/service/teams/" + team.ID + "/identity-connections"
	secondOwner := basic("33333333-3333-4333-8333-333333333333")
	ownerInvitation, err := d.CreateTeamInvitation(ctx, controlstate.CreateInvitationRequest{IdentityID: owner.Identity.Identity.Id, TeamID: team.ID, MemberSlug: "second-owner", InitialRole: controlstate.TeamRoleOwner, IdempotencyKey: "second-owner", ExpiresAt: now.Add(time.Hour), RetrySecret: bytes.Repeat([]byte{7}, 32)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.AcceptInvitation(ctx, secondOwner.Identity.Identity.Id, credentials.InvitationToken(ownerInvitation.Secret), now); err != nil {
		t.Fatal(err)
	}
	initialMembers, err := d.ListTeamMemberships(ctx, owner.Identity.Identity.Id, team.ID)
	if err != nil {
		t.Fatal(err)
	}
	var ownerMembership string
	for _, m := range initialMembers {
		if m.IdentityID == owner.Identity.Identity.Id {
			ownerMembership = m.ID
		}
	}
	setupBody := authorityv1.CreateIdentityConnectionRequest{Admission: authorityv1.CreateConnectionApproval, SourceId: "opaque-source-alpha"}
	if w := call("POST", base, website, "", encode(setupBody)); w.Code != 400 {
		t.Fatal("website token alone configured company", w.Code)
	}
	if w := ownerCall("POST", base, memberSub, nil, setupBody); w.Code != 403 {
		t.Fatal("non-owner configured company", w.Code, w.Body.String())
	}
	var failed controlstate.IdentityConnectionSetup
	decode(ownerCall("POST", base, ownerSub, nil, setupBody), 201, &failed)
	if failed.State != "pending" || !strings.HasPrefix(failed.ID, "icn_") {
		t.Fatal("control did not own pending ID", failed)
	}
	if w := call("GET", "/v1/teams/"+team.ID, owner.AccessToken, "", nil); w.Code != 200 {
		t.Fatal("setup locked out owner", w.Code)
	}
	activation := base + "/" + failed.ID + "/activate"
	if w := ownerCall("POST", activation, ownerSub, nil, map[string]any{"expected_revision": failed.Revision, "setup_token": failed.SetupToken}); w.Code != 400 {
		t.Fatal("activation accepted a missing precommitted credential", w.Code, w.Body.String())
	}
	if w := ownerCall("POST", activation, ownerSub, nil, f.activationRequest(failed)); w.Code != 403 {
		t.Fatal("activation without tenant consent", w.Code, w.Body.String())
	}
	decode(ownerCall("DELETE", base+"/"+failed.ID, ownerSub, nil, map[string]any{"expected_revision": failed.Revision}), 204, nil)
	if w := call("GET", "/v1/teams/"+team.ID, owner.AccessToken, "", nil); w.Code != 200 {
		t.Fatal("failed consent changed owner access", w.Code)
	}
	var setup controlstate.IdentityConnectionSetup
	rawSetup := encode(setupBody)
	proofToken := token(ownerSub, controlstate.CompanyActorNonce("POST", base, rawSetup), nil)
	decode(call("POST", base, website, proofToken, rawSetup), 201, &setup)
	if w := call("POST", base, website, proofToken, rawSetup); w.Code != 401 {
		t.Fatal("owner operation proof replay", w.Code)
	}
	provision := func(account, directory, capability string, c controlstate.IdentityConnection, revision int64, eligible bool) *httptest.ResponseRecorder {
		t.Helper()
		raw := encode(authorityv1.CompanyEligibilityRequest{TeamId: team.ID, IdentityConnectionId: c.ID, ConnectionRevision: c.Revision, AccountSubject: account, Subject: directory, Revision: revision, Eligible: eligible, ValidUntil: now.Add(4 * time.Hour), MemberSlug: "member"})
		r := httptest.NewRequest("POST", "/v1/service/company-eligibility", bytes.NewReader(raw))
		r.Header.Set("Authorization", "Bearer "+website)
		r.Header.Set("X-Tnl-Provisioning-Token", capability)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	if w := provision(owner.Identity.Identity.Id, "directory-owner", setup.SetupToken, setup.IdentityConnection, 1, true); w.Code == 204 {
		t.Fatal("control identity ID accepted as website OIDC sub")
	}
	decode(provision(ownerSub, "directory-owner", setup.SetupToken, setup.IdentityConnection, 1, true), 204, nil)
	companyProof := func(c controlstate.IdentityConnection, subject string) []oidc.TeamContext {
		return []oidc.TeamContext{{TeamID: team.ID, IdentityConnectionID: c.ID, ConnectionRevision: c.Revision, SourceID: c.SourceID, Subject: subject, AuthenticatedAt: now.Unix()}}
	}
	badSource := companyProof(setup.IdentityConnection, "directory-owner")
	badSource[0].SourceID = "other-tenant"
	activation = base + "/" + setup.ID + "/activate"
	activateBody := f.activationRequest(setup)
	if w := ownerCall("POST", activation, ownerSub, badSource, activateBody); w.Code != 403 {
		t.Fatal("wrong tenant activated", w.Code, w.Body.String())
	}
	badTeam := companyProof(setup.IdentityConnection, "directory-owner")
	badTeam[0].TeamID = owner.Identity.PersonalTeamId
	if w := ownerCall("POST", activation, ownerSub, badTeam, activateBody); w.Code != 403 {
		t.Fatal("wrong team consent activated", w.Code, w.Body.String())
	}
	wrongIssuer := signer.Token(t, "key-1", map[string]any{"iss": "https://other-issuer.example", "sub": ownerSub, "aud": "tnl-control", "name": "owner", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "nonce": controlstate.CompanyActorNonce("POST", activation, encode(activateBody))})
	if w := call("POST", activation, website, wrongIssuer, encode(activateBody)); w.Code != 401 {
		t.Fatal("wrong issuer owner proof accepted", w.Code)
	}
	if _, err = d.SetMembershipRole(ctx, owner.Identity.Identity.Id, team.ID, ownerMembership, controlstate.TeamRoleAdmin, now); err != nil {
		t.Fatal(err)
	}
	if w := ownerCall("POST", activation, ownerSub, companyProof(setup.IdentityConnection, "directory-owner"), activateBody); w.Code != 403 {
		t.Fatal("former owner activated pending consent", w.Code, w.Body.String())
	}
	if _, err = d.SetMembershipRole(ctx, secondOwner.Identity.Identity.Id, team.ID, ownerMembership, controlstate.TeamRoleOwner, now); err != nil {
		t.Fatal(err)
	}
	var active controlstate.IdentityConnectionSecret
	decode(ownerCall("POST", activation, ownerSub, companyProof(setup.IdentityConnection, "directory-owner"), activateBody), 200, &active)
	if active.Revision != setup.Revision+1 {
		t.Fatal("activation did not fence setup revision")
	}
	if w := call("GET", "/v1/teams/"+team.ID, owner.AccessToken, "", nil); w.Code != 403 {
		t.Fatal("personal owner session bypassed active company policy", w.Code)
	}
	if w := provision(ownerSub, "directory-owner", setup.SetupToken, setup.IdentityConnection, 2, true); w.Code == 204 {
		t.Fatal("setup credential survived activation")
	}
	login := func(sub, subject string) authorityv1.ControlSessionResponse {
		t.Helper()
		client, e := clientauthority.New(server.URL, server.Client(), "")
		if e != nil {
			t.Fatal(e)
		}
		intent, e := client.CreateCompanyLoginIntent(ctx, team.ID)
		if e != nil {
			t.Fatal(e)
		}
		if intent.BindingToken == nil {
			t.Fatal("intent did not return its private binding")
		}
		if intent.ClientId != "tnl-control" || intent.RedirectUri != server.URL+"/v1/auth/device/callback" {
			t.Fatal("unbound login intent", intent)
		}
		if _, e = client.ResolveCompanyLoginIntent(ctx, intent.IntentId, "wrong-binding"); e == nil {
			t.Fatal("intent binding ignored")
		}
		if _, e = f.exchangeIntent(ctx, intent.IntentId, *intent.BindingToken, token(sub, "wrong-nonce", companyProof(active.IdentityConnection, subject))); e == nil {
			t.Fatal("nonce-unbound company proof authorized")
		}
		wrongAudience := signer.Token(t, "key-1", map[string]any{"iss": issuer.URL, "sub": sub, "aud": "other-client", "name": "Company user", "nonce": intent.Nonce, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "tnl_team_contexts": companyProof(active.IdentityConnection, subject)})
		if _, e = f.exchangeIntent(ctx, intent.IntentId, *intent.BindingToken, wrongAudience); e == nil {
			t.Fatal("wrong client consumed company intent")
		}
		signed := token(sub, intent.Nonce, companyProof(active.IdentityConnection, subject))
		_, e = f.exchangeIntent(ctx, intent.IntentId, *intent.BindingToken, signed)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.exchangeIntent(ctx, intent.IntentId, *intent.BindingToken, token(sub, intent.Nonce, companyProof(active.IdentityConnection, subject))); e == nil {
			t.Fatal("intent replay authorized")
		}
		return f.login(active.IdentityConnection, sub, subject)
	}
	companyOwner := login(ownerSub, "directory-owner")
	if companyOwner.CompanyAuthenticationExpiresAt == nil || !companyOwner.CompanyAuthenticationExpiresAt.After(now.Add(50*time.Minute)) || companyOwner.CompanyAuthenticationExpiresAt.After(now.Add(time.Hour)) {
		t.Fatal("derived proof lifetime is not explicit and authentication-age bounded", companyOwner.CompanyAuthenticationExpiresAt)
	}
	if w := call("GET", "/v1/teams/"+team.ID, companyOwner.AccessToken, "", nil); w.Code != 200 {
		t.Fatal("signed company claim did not authorize team operation", w.Code, w.Body.String())
	}
	refreshed, err := d.RefreshControlSession(ctx, credentials.RefreshToken(companyOwner.RefreshToken), time.Hour, now.Add(10*time.Minute))
	if err != nil {
		t.Fatal("five-minute ID-token expiry capped derived control proof", err)
	}
	p, err := d.AuthenticateAccessToken(ctx, refreshed.AccessToken, now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err = d.AuthorizeTeamSession(ctx, p, team.ID, now.Add(10*time.Minute)); err != nil {
		t.Fatal("refresh lost current company context", err)
	}
	if _, err = d.RefreshControlSession(ctx, refreshed.RefreshToken, time.Hour, now.Add(61*time.Minute)); !errors.Is(err, controlstate.ErrControlAuthentication) {
		t.Fatal("refresh slid authentication age", err)
	}
	companyOwner = login(ownerSub, "directory-owner")
	contractor := basic("44444444-4444-4444-8444-444444444444")
	ownerForInvitation, err := d.AuthenticateAccessToken(ctx, credentials.AccessToken(companyOwner.AccessToken), now)
	if err != nil {
		t.Fatal(err)
	}
	contractorInvitation, err := d.CreateTeamInvitation(controlstate.WithControlPrincipal(ctx, ownerForInvitation), controlstate.CreateInvitationRequest{IdentityID: owner.Identity.Identity.Id, TeamID: team.ID, MemberSlug: "contractor", InitialRole: controlstate.TeamRoleMember, IdempotencyKey: "contractor", ExpiresAt: now.Add(time.Hour), RetrySecret: bytes.Repeat([]byte{8}, 32)}, now)
	if err != nil {
		t.Fatal(err)
	}
	contractorPath := "/v1/service/teams/" + team.ID + "/invitations/" + contractorInvitation.Invitation.ID + "/company-decision"
	decode(ownerCall("PUT", contractorPath, ownerSub, companyProof(active.IdentityConnection, "directory-owner"), map[string]any{"personal_account_exception": true}), 204, nil)
	if _, err = d.AcceptInvitation(ctx, contractor.Identity.Identity.Id, credentials.InvitationToken(contractorInvitation.Secret), now); err != nil {
		t.Fatal(err)
	}
	decode(provision("44444444-4444-4444-8444-444444444444", "directory-contractor", active.ProvisioningToken, active.IdentityConnection, 1, false), 204, nil)
	if w := call("GET", "/v1/teams/"+team.ID, contractor.AccessToken, "", nil); w.Code != 200 {
		t.Fatal("owner contractor invitation did not permit personal sign-in", w.Code, w.Body.String())
	}
	decode(provision(memberSub, "directory-member", active.ProvisioningToken, active.IdentityConnection, 1, true), 204, nil)
	companyMember := login(memberSub, "directory-member")
	if w := call("GET", "/v1/teams/"+team.ID, companyMember.AccessToken, "", nil); w.Code != 403 {
		t.Fatal("eligibility implicitly admitted membership", w.Code)
	}
	var admission authorityv1.CompanyAdmissionRequest
	decode(call("POST", "/v1/auth/company-admissions", companyMember.AccessToken, "", encode(authorityv1.RequestCompanyAdmissionJSONRequestBody{TeamId: team.ID, IdentityConnectionId: active.ID, ConnectionRevision: active.Revision, MemberSlug: "member"})), 200, &admission)
	decisionPath := "/v1/service/teams/" + team.ID + "/company-admissions/" + admission.RequestId
	decode(ownerCall("POST", decisionPath, ownerSub, companyProof(active.IdentityConnection, "directory-owner"), map[string]any{"connection_revision": active.Revision, "decision": "approved"}), 204, nil)
	if w := call("GET", "/v1/teams/"+team.ID, companyMember.AccessToken, "", nil); w.Code != 200 {
		t.Fatal("owner approval did not admit current eligible user", w.Code, w.Body.String())
	}
	memberContext, err := d.IdentityContext(ctx, member.Identity.Identity.Id)
	if err != nil {
		t.Fatal(err)
	}
	var memberID string
	for _, m := range memberContext.Memberships {
		if m.TeamID == team.ID {
			memberID = m.ID
			if m.Role != controlstate.TeamRoleMember {
				t.Fatal("website escalated role")
			}
		}
	}
	ownerPrincipal, err := d.AuthenticateAccessToken(ctx, credentials.AccessToken(companyOwner.AccessToken), now)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.RemoveMembership(controlstate.WithControlPrincipal(ctx, ownerPrincipal), owner.Identity.Identity.Id, team.ID, memberID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	decode(provision(memberSub, "directory-member", active.ProvisioningToken, active.IdentityConnection, 2, true), 204, nil)
	if w := ownerCall("POST", decisionPath, ownerSub, companyProof(active.IdentityConnection, "directory-owner"), map[string]any{"connection_revision": active.Revision, "decision": "approved"}); w.Code != 409 {
		t.Fatal("owner approval resurrected removal tombstone", w.Code, w.Body.String())
	}
	if w := call("POST", "/v1/auth/company-admissions", companyMember.AccessToken, "", encode(authorityv1.RequestCompanyAdmissionJSONRequestBody{TeamId: team.ID, IdentityConnectionId: active.ID, ConnectionRevision: active.Revision, MemberSlug: "member"})); w.Code != 409 {
		t.Fatal("admission resurrected manual removal", w.Code, w.Body.String())
	}
	// aborted replacement preserves the old active source and its session.
	replacementBody := authorityv1.CreateIdentityConnectionRequest{Admission: authorityv1.CreateConnectionManaged, SourceId: "opaque-source-beta", ReplaceId: &active.ID, ExpectedRevision: &active.Revision}
	var replacement controlstate.IdentityConnectionSetup
	decode(ownerCall("POST", base, ownerSub, companyProof(active.IdentityConnection, "directory-owner"), replacementBody), 201, &replacement)
	var view authorityv1.CompanyConnections
	decode(ownerCall("GET", base, ownerSub, companyProof(active.IdentityConnection, "directory-owner"), nil), 200, &view)
	if view.Active == nil || view.Setup == nil || view.Active.IdentityConnectionId != active.ID {
		t.Fatal("pending replacement discarded active source", view)
	}
	decode(ownerCall("DELETE", base+"/"+replacement.ID, ownerSub, companyProof(active.IdentityConnection, "directory-owner"), map[string]any{"expected_revision": replacement.Revision}), 204, nil)
	if w := call("GET", "/v1/teams/"+team.ID, companyOwner.AccessToken, "", nil); w.Code != 200 {
		t.Fatal("aborted replacement revoked current access", w.Code)
	}
	if w := call("PUT", "/v1/teams/"+team.ID+"/identity-connections/"+active.ID, companyOwner.AccessToken, "", encode(map[string]any{"state": "active", "expected_revision": active.Revision})); w.Code != 404 {
		t.Fatal("superseded state setter retained", w.Code)
	}
	var rotated controlstate.IdentityConnectionSecret
	decode(ownerCall("POST", base+"/"+active.ID+"/provisioning-token", ownerSub, companyProof(active.IdentityConnection, "directory-owner"), map[string]any{"expected_revision": active.Revision}), 200, &rotated)
	if w := provision(ownerSub, "directory-owner", active.ProvisioningToken, active.IdentityConnection, 2, true); w.Code != 403 {
		t.Fatal("old provisioning token survived rotation", w.Code)
	}
	decode(provision(ownerSub, "directory-owner", rotated.ProvisioningToken, rotated.IdentityConnection, 2, true), 204, nil)
	decode(ownerCall("DELETE", base+"/"+active.ID, ownerSub, companyProof(active.IdentityConnection, "directory-owner"), map[string]any{"expected_revision": active.Revision}), 204, nil)
	view = authorityv1.CompanyConnections{}
	decode(ownerCall("GET", base, ownerSub, nil, nil), 200, &view)
	if view.Active != nil || view.Setup != nil {
		t.Fatal("disconnect read retained a current source", view)
	}
	if w := provision(ownerSub, "directory-owner", rotated.ProvisioningToken, rotated.IdentityConnection, 3, true); w.Code != 403 {
		t.Fatal("disconnected source provisioned", w.Code)
	}
	if w := call("GET", "/v1/teams/"+team.ID, companyOwner.AccessToken, "", nil); w.Code != 403 {
		t.Fatal("disconnect restored old-source team access", w.Code)
	}
}
