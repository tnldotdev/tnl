package public

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/testutil/managedcert"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func publishBrowserService(t *testing.T, f *companyHTTPFixture, ctx context.Context, actor, team, member, name string) (controlstate.ServiceRecord, controlstate.ServiceHTTPRun) {
	t.Helper()
	local, err := f.d.RealizeLocalProjectService(ctx, controlstate.RealizeLocalProjectServiceRequest{
		TeamID: team, ActorID: actor, ProjectKey: "browser", SourceFingerprint: strings.Repeat("a", 64),
		Service: name, WorktreeKey: "browser", Configuration: controlstate.ProjectServiceConfiguration{Target: "localhost:3000"}, Now: f.now,
	})
	if err != nil {
		t.Fatal("realize browser service", err)
	}
	service, err := f.d.GetService(ctx, local.ServiceID, actor)
	if err != nil {
		t.Fatal("read browser service", err)
	}
	var revision int64
	if err := f.sql.QueryRow(ctx, `SELECT policy_revision FROM control.teams WHERE id=$1`, team).Scan(&revision); err != nil {
		t.Fatal("read browser service team revision", err)
	}
	enrollment, err := f.d.IssuePublisherEnrollment(ctx, controlstate.CreatePublisherEnrollmentRequest{
		Scope: controlstate.PublisherScope{TeamID: team, Kind: "service", ServiceID: service.ID},
		Name:  name, Kind: "installed", EditorID: actor, EditorMembershipID: member, PolicyRevision: uint64(revision), Now: f.now,
	})
	if err != nil {
		t.Fatal("enroll browser service publisher", err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate browser service publisher key", err)
	}
	publisher, err := f.d.RedeemPublisherEnrollment(ctx, enrollment.Key, public, f.now)
	if err != nil {
		t.Fatal("redeem browser service publisher enrollment", err)
	}
	relays := newAuditCompositionRelays(t, f.d, f.now)
	prepared, err := f.d.PrepareServiceRun(ctx, service.ID, publisher, name, f.now, controlstate.ServiceRunRequest{Metadata: service.ServiceMetadata})
	if err != nil {
		t.Fatal("prepare browser service run", err)
	}
	run, err := f.d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, publisher, f.now)
	if err != nil {
		t.Fatal("start browser service run", err)
	}
	managedcert.Install(t, f.d, prepared, run, f.now)
	for _, slot := range run.Connections {
		lease := relays[slot.RelayServiceID].RelayLeaseIdentity
		if _, err := f.d.ClaimServicePublisherConnection(ctx, slot.PublisherConnectionID, service.ID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, netip.MustParseAddr("127.0.0.1"), lease, f.now); err != nil {
			t.Fatal(err)
		}
		if _, err := f.d.ReadyServicePublisherConnection(ctx, slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, f.now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.d.HeartbeatServiceRun(ctx, service.ID, run.RunID, run.Token, f.now, controlstate.ServiceRunHealth{Healthy: true, StreamCapacity: 20}); err != nil {
		t.Fatal(err)
	}
	return service, controlstate.ServiceHTTPRun{Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: service.ID}, RunID: run.RunID, Number: run.RunNumber, Token: credentials.ServiceRunToken(run.Token)}
}

func TestIntegrationAliasBrowserHTTPAuthorizationAndLogout(t *testing.T) {
	f := newCompanyHTTPFixture(t, "alias_browser_http")
	owner := f.basic("alias-owner")
	m := owner.Identity.Memberships[0]
	p := f.principal(owner)
	ctx := controlstate.WithControlPrincipal(t.Context(), p)
	service, auth := publishBrowserService(t, f, ctx, p.IdentityID, m.TeamId, m.Id, "alias")
	runID, number, token := auth.RunID, auth.Number, auth.Token
	if err := f.d.PrepareVisitorSigningKeys(ctx, f.server.URL, f.now); err != nil {
		t.Fatal(err)
	}
	api, err := NewHandler(Config{ControlURL: f.server.URL, HTTPClient: f.server.Client()}, DatabaseStores(f.d), f.d, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.mux.Handle("/", api)
	client, err := clientcontrol.New(f.server.URL, f.server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	handoff, err := f.d.IssueControlBrowserHandoff(ctx, credentials.AccessToken(owner.AccessToken), credentials.RefreshToken(owner.RefreshToken), service.ID, time.Hour, 24*time.Hour, f.now)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := client.RedeemServiceBrowserHandoff(ctx, service.ID, runID, token, controlv1.ServiceBrowserRequest{RunNumber: number, Secret: handoff.Token})
	if err != nil || installed.Permission == nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: service.ID}
	policy, err := visitorlease.New(scope, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer policy.Close()
	refresh := func() visitortoken.View {
		t.Helper()
		started := policy.Begin()
		update, err := client.ReadPublisherVisitorPolicy(ctx, controlv1.PublisherVisitorPolicyRequest{Resource: installed.Permission.Resource, RunId: runID,
			RunNumber: number, AfterRevision: started.AfterRevision}, token.String())
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
	browser, ok := allowed.Facts().Subject.(visitortoken.Browser)
	if !ok || browser.IdentityID != p.IdentityID || allowed.Facts().Scope != scope || !allowed.Facts().ExpiresAt.After(f.now) {
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
	if err := client.RevokeServiceBrowserSession(ctx, service.ID, runID, token, controlv1.ServiceBrowserRequest{RunNumber: number, Secret: installed.CookieSecret}); err != nil {
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

func TestIntegrationShareReviewerSignInRetainsShareVisitorPermission(t *testing.T) {
	f := newCompanyHTTPFixture(t, "share_reviewer_browser")
	owner, reviewer := f.basic("share-owner"), f.basic("outside-reviewer")
	m := owner.Identity.Memberships[0]
	p := f.principal(owner)
	ctx := controlstate.WithControlPrincipal(t.Context(), p)
	service, auth := publishBrowserService(t, f, ctx, p.IdentityID, m.TeamId, m.Id, "reviewer")
	preview, err := f.d.CreatePreview(ctx, m.TeamId, p.IdentityID, "share-reviewer", f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.AddPreviewService(ctx, controlstate.AddPreviewServiceRequest{PreviewID: preview.ID, ServiceID: service.ID, TeamID: m.TeamId, IdentityID: p.IdentityID}, f.now); err != nil {
		t.Fatal(err)
	}
	if err := f.d.PrepareVisitorSigningKeys(ctx, f.server.URL, f.now); err != nil {
		t.Fatal(err)
	}
	secret := []byte("0123456789abcdefghijklmnopqrstuv")
	share, err := f.d.CreateShare(ctx, controlstate.CreateShareRequest{PreviewID: preview.ID, TeamID: m.TeamId, ActingIdentityID: p.IdentityID,
		IdempotencyKey: "reviewer-share", SecretFingerprint: sha256.Sum256(secret), ExpiresAt: f.now.Add(time.Hour),
		ServiceIDs: []string{service.ID}, EntryServiceID: service.ID}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	shareSession, err := f.d.RedeemShare(ctx, auth, share.ID, secret, nil, f.now)
	if err != nil {
		t.Fatal(err)
	}
	handoff, err := f.d.IssueBrowserHandoff(ctx, controlstate.BrowserLoginAttempt{PreviewID: preview.ID, Subject: auth.Subject, ServiceRunIDs: []string{auth.RunID}, ReturnPath: "/"}, controlstate.BrowserAccessSession{
		IdentityID: reviewer.Identity.Identity.Id, DisplayName: "Outside reviewer", AccessToken: reviewer.AccessToken, RefreshToken: reviewer.RefreshToken,
		AccessExpiresAt: f.now.Add(30 * time.Minute), ExpiresAt: f.now.Add(time.Hour)}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	api, err := NewHandler(Config{ControlURL: f.server.URL, HTTPClient: f.server.Client()}, DatabaseStores(f.d), f.d, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.mux.Handle("/", api)
	client, err := clientcontrol.New(f.server.URL, f.server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	installed, err := client.RedeemServiceBrowserHandoff(ctx, service.ID, auth.RunID, auth.Token, controlv1.ServiceBrowserRequest{RunNumber: auth.Number, Secret: handoff.Token, ShareId: &share.ID, ShareCookieSecret: &shareSession.CookieSecret})
	if err != nil || installed.CookieSecret == "" || installed.Permission == nil || installed.Permission.VisitorToken == "" {
		t.Fatal("share reviewer sign-in failed before visitor handoff", err)
	}
	update, err := client.ReadPublisherVisitorPolicy(ctx, controlv1.PublisherVisitorPolicyRequest{Resource: installed.Permission.Resource, RunId: auth.RunID, RunNumber: auth.Number}, auth.Token.String())
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := visitorlease.Decode(update)
	if err != nil {
		t.Fatal(err)
	}
	view := decoded.View
	permission, err := visitortoken.VerifyBearer(visitortoken.Token(installed.Permission.VisitorToken), view, time.Now())
	if err != nil || permission.Facts().Subject != (visitortoken.Share{ShareID: share.ID}) {
		t.Fatal("share reviewer received a browser visitor grant", err)
	}
	identity, err := client.CheckServiceBrowserSession(ctx, service.ID, auth.RunID, auth.Token, controlv1.ServiceBrowserRequest{RunNumber: auth.Number, Secret: installed.CookieSecret})
	if err != nil || identity.IdentityId != reviewer.Identity.Identity.Id || identity.VisitAllowed {
		t.Fatal("share reviewer's sign-in identity was mistaken for visitor access", err)
	}
}
