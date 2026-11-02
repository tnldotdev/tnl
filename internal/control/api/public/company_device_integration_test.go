package public

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	"github.com/tnldotdev/tnl/internal/control/oidc"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil/oidctest"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func TestIntegrationCompanyDevicePublicServiceAdmissionAndReauthentication(t *testing.T) {
	f := newCompanyHTTPFixture(t, "company_direct_device")
	ctx := t.Context()
	d := f.d
	owner := f.basic("owner")
	person := f.basic("person")
	team, err := d.CreateTeam(ctx, controlstate.CreateTeamRequest{IdentityID: owner.Identity.Identity.Id, DisplayName: "studio", MemberSlug: "owner", IdempotencyKey: "studio", RequestDigest: sha256.Sum256([]byte("studio"))}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := d.CreateTeam(ctx, controlstate.CreateTeamRequest{IdentityID: owner.Identity.Identity.Id, DisplayName: "other", MemberSlug: "owner", IdempotencyKey: "other", RequestDigest: sha256.Sum256([]byte("other"))}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	rules := []oidc.AdmissionRule{{Team: "studio", SourceID: "direct-company", Subjects: []string{"owner", "person"}}, {Team: "other", SourceID: "other-company", Subjects: []string{"owner", "person"}}}
	if err := d.ConfigureOIDCAdmissions(ctx, f.issuer.URL, rules, f.now); err != nil {
		t.Fatal(err)
	}
	api, err := clientauthority.New(f.server.URL, f.server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	login := func(subject, selection, refresh string, proof []oidc.TeamContext) (authorityv1.ControlSessionResponse, error) {
		f.mu.Lock()
		f.browserSubject, f.browserProof = subject, proof
		f.mu.Unlock()
		body := authorityv1.StartDeviceLoginRequest{Team: &selection}
		if refresh != "" {
			body.RefreshToken = &refresh
		}
		challenge, err := api.StartDeviceLogin(ctx, body)
		if err != nil {
			return authorityv1.ControlSessionResponse{}, err
		}
		if err := oidctest.Approve(ctx, f.server.Client(), challenge.ApprovalUrl); err != nil {
			return authorityv1.ControlSessionResponse{}, err
		}
		result, err := api.PollDeviceLogin(ctx, challenge.PollingCredential)
		if err != nil {
			return authorityv1.ControlSessionResponse{}, err
		}
		if result.Session == nil {
			return authorityv1.ControlSessionResponse{}, errors.New("missing session")
		}
		return *result.Session, nil
	}
	companyOwner, err := login("owner", "studio", owner.RefreshToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	company, err := login("person", "studio", person.RefreshToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	if company.Identity.Identity.Id != person.Identity.Identity.Id || company.Identity.DefaultTeamId == nil || *company.Identity.DefaultTeamId != team.ID {
		t.Fatal("team name or stable subject identity lost")
	}
	if w := f.call("GET", "/v1/teams/"+team.ID, company.AccessToken, "", nil); w.Code != 200 {
		t.Fatalf("company operation: %d %s", w.Code, w.Body)
	}
	if w := f.call("GET", "/v1/teams/"+team.ID, person.AccessToken, "", nil); w.Code != 403 {
		t.Fatal("personal sign-in acquired company access")
	}
	if _, err := login("github-only", "studio", "", nil); err == nil {
		t.Fatal("unmapped personal identity passed admission")
	}
	if _, err := login("owner", "studio", person.RefreshToken, nil); err == nil {
		t.Fatal("reauthentication switched identities")
	}
	if _, err := login("person", "studio", "", []oidc.TeamContext{{TeamID: team.ID, IdentityConnectionID: "wrong", ConnectionRevision: 1, SourceID: "wrong", Subject: "person", AuthenticatedAt: f.now.Unix()}}); err == nil {
		t.Fatal("provider custom context bypassed direct source mapping")
	}
	combined, err := login("person", "other", company.RefreshToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := f.principal(combined)
	for _, id := range []string{team.ID, other.ID} {
		if err := d.AuthorizeTeamSession(ctx, p, id, time.Now()); err != nil {
			t.Fatal("reauth lost another valid team", err)
		}
	}
	var firstDeadline, secondDeadline time.Time
	if err := f.sql.QueryRow(ctx, `SELECT expires_at FROM control.company_session_contexts WHERE session_id=$1 AND team_id=$2`, company.SessionId, team.ID).Scan(&firstDeadline); err != nil {
		t.Fatal(err)
	}
	if err := f.sql.QueryRow(ctx, `SELECT expires_at FROM control.company_session_contexts WHERE session_id=$1 AND team_id=$2`, combined.SessionId, team.ID).Scan(&secondDeadline); err != nil || !firstDeadline.Equal(secondDeadline) {
		t.Fatal("reauthentication extended other-team authentication", err)
	}
	ownerCtx := controlstate.WithControlPrincipal(ctx, f.principal(companyOwner))
	companyCtx := controlstate.WithControlPrincipal(ctx, p)
	personalCtx := controlstate.WithControlPrincipal(ctx, f.principal(person))
	service, err := d.CreateServiceAt(ownerCtx, team.ID, companyOwner.Identity.Identity.Id, "database", "database", controlstate.ServicePlacement{}, time.Now(), controlstate.ServiceMetadata{Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateServiceGrant(ownerCtx, service.ID, companyOwner.Identity.Identity.Id, "person-grant", "identity", p.IdentityID, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := d.EnrollVisitorDevice(companyCtx, p.IdentityID, pub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.IssueServiceClientCertificate(personalCtx, service.ID, p.IdentityID, device.ID, csr, time.Now()); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("personal certificate issuance: %v", err)
	}
	cert, err := d.IssueServiceClientCertificate(companyCtx, service.ID, p.IdentityID, device.ID, csr, time.Now())
	if err != nil || cert.CertificatePEM == "" {
		t.Fatal("company certificate issuance", err)
	}
	domains, err := d.ListTeamDomains(companyCtx, p.IdentityID, team.ID)
	if err != nil {
		t.Fatal(err)
	}
	var member authorityv1.Membership
	for _, m := range combined.Identity.Memberships {
		if m.TeamId == team.ID {
			member = m
		}
	}
	u, err := d.CreatePublicURL(companyCtx, controlstate.CreatePublicURLRequest{TeamID: team.ID, DomainID: domains[0].ID, MembershipID: member.Id, ActingIdentityID: p.IdentityID, IdempotencyKey: "app", CanonicalHostname: "app." + member.ManagedLabel + ".example.test", Target: "http://127.0.0.1:3000", PublicURLScope: controlstate.PublicURLScopeMember, Purpose: controlstate.PublicURLPurposeApp, DNSState: controlstate.PublicURLDNSUnmanaged}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"device-relay-a", "device-relay-b"} {
		if _, err := d.RegisterRelay(ctx, controlstate.RelayRegistration{RelayServiceID: name, RelayID: name, RelayRunID: name + "-run", ProtocolVersion: 1, RelayAddress: name + ".example.test:443", TLSServerName: name + ".example.test", InternalRelayAddress: name + ".internal:9445", ConnectionCapacity: 10, StreamCapacity: 10}, time.Now(), time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	run, err := d.CreatePublishRun(companyCtx, controlstate.PublishRunRequest{PublicURLID: u.ID, TeamID: team.ID, MembershipID: member.Id, ActingIdentityID: p.IdentityID, RetrySecret: p.RetrySecret[:], IdempotencyKey: "device-run", RequestDigest: sha256.Sum256([]byte("device-run")), PolicyRevision: uint64(u.PolicyRevision), ExpectedMutationRevision: u.MutationRevision, CertificateCacheKey: u.CanonicalHostname, CertificateScope: u.CanonicalHostname, CertificateIdentifiers: []string{u.CanonicalHostname}, CertificateChallenge: "dns-01"}, time.Now(), time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// this test owns authentication, so mark the fixture publication ready rather
	// than contacting an external CA or carrying application traffic.
	if _, err := f.sql.Exec(ctx, `UPDATE control.publish_runs SET state='ready',ready_at=$2 WHERE id=$1`, run.PublishRunID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.IssueControlBrowserHandoff(personalCtx, credentials.AccessToken(person.AccessToken), credentials.RefreshToken(person.RefreshToken), u.ID, time.Hour, 24*time.Hour, time.Now()); err == nil {
		t.Fatal("personal public visitor handoff issued")
	}
	handoff, _, err := d.IssueControlBrowserHandoff(companyCtx, credentials.AccessToken(combined.AccessToken), credentials.RefreshToken(combined.RefreshToken), u.ID, time.Hour, 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal("company public visitor handoff", err)
	}
	auth := controlstate.PublishRunAuthentication{PublicURLID: u.ID, PublishRunID: run.PublishRunID, PublishRunNumber: run.PublishRunNumber, PublishRunToken: run.PublishRunToken}
	cookie, _, _, _, _, err := d.RedeemBrowserHandoff(ctx, auth, handoff.Token, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	permission, err := d.BrowserAuthorizationForRun(ctx, auth, cookie, time.Now())
	if err != nil || !permission.VisitAllowed {
		t.Fatal("company public visitor permission", permission, err)
	}
	if _, err := d.RefreshControlSession(ctx, credentials.RefreshToken(combined.RefreshToken), time.Hour, f.now.Add(61*time.Minute)); !errors.Is(err, controlstate.ErrControlAuthentication) {
		t.Fatalf("refresh extended company authentication: %v", err)
	}
	if err := d.RemoveMembership(ownerCtx, companyOwner.Identity.Identity.Id, team.ID, member.Id, time.Now()); err != nil {
		t.Fatal(err)
	}
	again, err := login("person", "studio", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.AuthorizeTeamSession(ctx, f.principal(again), team.ID, time.Now()); !errors.Is(err, controlstate.ErrAuthorityAccess) {
		t.Fatal("direct admission restored removed membership", err)
	}
}
