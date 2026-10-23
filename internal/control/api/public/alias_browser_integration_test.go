package public

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationAliasBrowserHTTPAuthorizationAndLogout(t *testing.T) {
	f := newCompanyHTTPFixture(t, "alias_browser_http")
	owner := f.basic("alias-owner")
	m := owner.Identity.Memberships[0]
	p := f.principal(owner)
	ctx := controlstate.WithControlPrincipal(t.Context(), p)
	domains, err := f.d.ListTeamDomains(ctx, p.IdentityID, m.TeamId)
	if err != nil {
		t.Fatal(err)
	}
	u, err := f.d.CreatePublicURL(ctx, controlstate.CreatePublicURLRequest{TeamID: m.TeamId, DomainID: domains[0].ID, MembershipID: m.Id, ActingIdentityID: p.IdentityID,
		IdempotencyKey: "alias", RequestDigest: sha256.Sum256([]byte("alias")), CanonicalHostname: "alias." + m.ManagedLabel + ".example.test", Target: "http://127.0.0.1:3000",
		PublicURLScope: controlstate.PublicURLScopeMember, Purpose: controlstate.PublicURLPurposeAlias, DNSState: controlstate.PublicURLDNSUnmanaged}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alias-relay-a", "alias-relay-b"} {
		if _, err := f.d.RegisterRelay(ctx, controlstate.RelayRegistration{RelayServiceID: name, RelayID: name, RelayRunID: name + "-run", ProtocolVersion: tunnelv1.Version,
			RelayAddress: name + ".example.test:443", TLSServerName: name + ".example.test", InternalRelayAddress: name + ".internal:9445", ConnectionCapacity: 10, StreamCapacity: 10}, f.now, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	run, err := f.d.CreatePublishRun(ctx, controlstate.PublishRunRequest{PublicURLID: u.ID, TeamID: m.TeamId, MembershipID: m.Id, ActingIdentityID: p.IdentityID,
		RetrySecret: p.RetrySecret[:], IdempotencyKey: "alias-run", RequestDigest: sha256.Sum256([]byte("alias-run")), PolicyRevision: uint64(u.PolicyRevision), ExpectedMutationRevision: u.MutationRevision,
		CertificateCacheKey: u.CanonicalHostname, CertificateScope: u.CanonicalHostname, CertificateIdentifiers: []string{u.CanonicalHostname}, CertificateChallenge: "dns-01"}, f.now, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// the fixture owns authorization, not certificate issuance or placement.
	if _, err := f.sql.Exec(ctx, `UPDATE control.publish_runs SET state='ready',ready_at=$2 WHERE id=$1`, run.PublishRunID, f.now); err != nil {
		t.Fatal(err)
	}
	api, err := NewHandler(Config{ControlURL: f.server.URL, HTTPClient: f.server.Client()}, f.d, f.d, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.mux.Handle("/", api)
	client, err := clientcontrol.New(f.server.URL, f.server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	handoff, _, err := f.d.IssueControlBrowserHandoff(ctx, credentials.AccessToken(owner.AccessToken), credentials.RefreshToken(owner.RefreshToken), u.ID, time.Hour, 24*time.Hour, f.now)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := client.RedeemBrowserHandoff(ctx, run.PublishRunID, run.PublishRunNumber, handoff.Token, run.PublishRunToken)
	if err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: u.ID}
	policy, err := visitorlease.New(scope, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer policy.Close()
	refresh := func() visitortoken.View {
		t.Helper()
		started := policy.Begin()
		update, err := client.ReadPublisherVisitorPolicy(ctx, controlv1.PublisherVisitorPolicyRequest{Resource: installed.Permission.Resource, RunId: run.PublishRunID,
			RunNumber: int64(run.PublishRunNumber), AfterRevision: started.AfterRevision}, run.PublishRunToken.String())
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := visitorlease.Decode(update)
		if err != nil {
			t.Fatal(err)
		}
		if err := policy.Apply(started, decoded); err != nil {
			t.Fatal(err)
		}
		view, _, _ := policy.Current()
		return view
	}
	view := refresh()
	allowed, err := visitortoken.VerifyBearer(visitortoken.Token(installed.Permission.VisitorToken), view, time.Now())
	if err != nil {
		t.Fatal("alias owner permission failed local verification", err)
	}
	browser, ok := allowed.Subject.(visitortoken.Browser)
	if !ok || browser.IdentityID != p.IdentityID || allowed.Scope != scope || !allowed.ExpiresAt.After(f.now) {
		t.Fatal("alias owner permission changed identity, scope, or deadline")
	}
	source, err := json.Marshal(controlv1.VisitorTokenBrowserSessionSource{Kind: controlv1.VisitorTokenBrowserSession, Secret: installed.CookieSecret})
	if err != nil {
		t.Fatal(err)
	}
	input := controlv1.VisitorTokenRequest{Resource: installed.Permission.Resource, Source: source}
	renewed, err := client.IssueVisitorToken(ctx, input)
	if err != nil || renewed.Resource != installed.Permission.Resource || renewed.VisitorToken == "" {
		t.Fatal("alias browser sign-in could not renew its signed visitor permission", err)
	}
	if err := client.RevokeBrowserAccess(ctx, run.PublishRunID, run.PublishRunNumber, installed.CookieSecret, run.PublishRunToken); err != nil {
		t.Fatal(err)
	}
	_, err = client.IssueVisitorToken(ctx, input)
	var problem *clientcontrol.ProblemError
	if !errors.As(err, &problem) || problem.Status != 403 || errors.Is(err, clientcontrol.ErrUnavailable) {
		t.Fatalf("logout must return terminal permission failure: %v", err)
	}
	view = refresh()
	if _, err := visitortoken.VerifyBearer(visitortoken.Token(renewed.VisitorToken), view, time.Now()); !errors.Is(err, visitortoken.ErrToken) {
		t.Fatal("logout left the previous signed visitor permission usable", err)
	}
}
