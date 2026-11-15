package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func finalVisitorIdentity(t *testing.T, d *Database, now time.Time, email string) string {
	t.Helper()
	id, err := opaqueid.New(opaqueid.IdentityPrefix)
	if err != nil {
		t.Fatal(err)
	}
	insertAuthorityIdentity(t, d, id, email, email != "", now)
	return id
}

func finalServiceHTTPPermission(ctx context.Context, d *Database, serviceID, identityID string, now time.Time) (VisitorPermission, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return VisitorPermission{}, err
	}
	defer tx.Rollback(ctx)
	permission, err := d.serviceHTTPIdentityPermission(ctx, tx, serviceID, identityID, now)
	if err != nil {
		return permission, err
	}
	return permission, tx.Commit(ctx)
}

func TestIntegrationFinalVisitorGrantsInventoryInvitationAndRevocation(t *testing.T) {
	f := newServiceHTTPFixture(t)
	d := f.database
	owner := f.project.ActorID
	visitor := finalVisitorIdentity(t, d, f.now, "visitor@example.test")

	check := func(person string, allowed bool, at time.Time) {
		t.Helper()
		permission, err := finalServiceHTTPPermission(t.Context(), d, f.service.ID, person, at)
		if !allowed {
			if err == nil && permission.VisitAllowed {
				t.Fatal("visitor allowed")
			}
			return
		}
		if err != nil || !permission.VisitAllowed {
			t.Fatalf("allowed=%t want=%t: %+v %v", permission.VisitAllowed, allowed, permission, err)
		}
	}
	check(owner, true, f.now)
	check(visitor, false, f.now)
	inventory, _, err := d.ListAvailableServices(t.Context(), visitor, "", controlv1.ServiceAccessPathConnector, f.now)
	if err != nil || len(inventory) != 0 {
		t.Fatalf("outsider inventory: %+v %v", inventory, err)
	}
	ownerCtx := WithControlPrincipal(t.Context(), ControlPrincipal{IdentityID: owner})
	invitation, err := d.InviteServiceVisitor(ownerCtx, f.service.ID, owner, "named", "visitor@example.test", f.now.Add(time.Hour), f.now)
	if err != nil || invitation.Secret == "" {
		t.Fatal(invitation, err)
	}
	wrong := finalVisitorIdentity(t, d, f.now, "another@example.test")
	if _, err = d.AcceptServiceInvitation(t.Context(), wrong, invitation.Secret, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("wrong verified email accepted: %v", err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			_, err := d.AcceptServiceInvitation(t.Context(), visitor, invitation.Secret, f.now)
			results <- err
		})
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrServiceAccess) {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent invitation successes=%d", successes)
	}
	check(visitor, true, f.now)
	check(visitor, false, f.now.Add(time.Hour))
	var memberships int
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.team_memberships WHERE team_id=$1 AND identity_id=$2`, f.project.TeamID, visitor).Scan(&memberships); err != nil || memberships != 0 {
		t.Fatalf("visitor gained membership: %d %v", memberships, err)
	}
	inventory, _, err = d.ListAvailableServices(t.Context(), visitor, "", controlv1.ServiceAccessPathConnector, f.now)
	if err != nil || len(inventory) != 1 || inventory[0].ID != f.service.ID || inventory[0].VisitorAccess != "identity_grant" {
		t.Fatalf("invited inventory: %+v %v", inventory, err)
	}
	encoded, _ := json.Marshal(inventory)
	for _, forbidden := range [][]byte{[]byte("target"), []byte("ip_policy"), []byte("token"), []byte("secret"), []byte("digest")} {
		if bytes.Contains(encoded, forbidden) {
			t.Fatalf("visitor inventory exposed %s", forbidden)
		}
	}
	if err = d.RevokeServiceInvitation(ownerCtx, f.service.ID, owner, invitation.ID, f.now); err != nil {
		t.Fatal(err)
	}
	check(visitor, false, f.now)
	visitorCtx := WithControlPrincipal(t.Context(), ControlPrincipal{IdentityID: visitor})
	if _, err = d.CreateServiceGrant(visitorCtx, f.service.ID, visitor, "outsider", "team", "", nil, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("visitor managed grants: %v", err)
	}
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.teams SET kind='organization' WHERE id=$1`, f.project.TeamID); err != nil {
		t.Fatal(err)
	}
	member := addAuthorityMember(t, d, f.now, owner, f.project.TeamID, "colleague", TeamRoleMember)
	grant, err := d.CreateServiceGrant(ownerCtx, f.service.ID, owner, "perpetual", "team", "", nil, f.now)
	if err != nil {
		t.Fatal(err)
	}
	check(member.IdentityID, true, f.now.Add(2*time.Hour))
	if err = d.RemoveMembership(t.Context(), owner, f.project.TeamID, member.ID, f.now); err != nil {
		t.Fatal(err)
	}
	check(member.IdentityID, false, f.now)
	if err = d.RevokeServiceGrant(ownerCtx, f.service.ID, owner, grant.ID, f.now); err != nil {
		t.Fatal(err)
	}
	inventory, _, err = d.ListAvailableServices(t.Context(), visitor, "", controlv1.ServiceAccessPathConnector, f.now)
	if err != nil || len(inventory) != 0 {
		t.Fatal("revocation left the service in visitor inventory", inventory, err)
	}
}

func TestIntegrationFinalVisitorLiveIPPolicyAndRunBoundary(t *testing.T) {
	f := newServiceHTTPFixture(t)
	f.service = f.local(t, "web", &config.HTTPService{Access: &config.Access{Mode: "anonymous"}})
	f.run = f.publish(t, f.service)
	auth := f.auth()
	input := preparedVisitorInput{SourceIP: "192.0.2.9"}
	check := func(a ServiceHTTPRun, allowed bool, at time.Time) {
		t.Helper()
		p, err := preparedServiceHTTPPermission(t.Context(), f.database, a, input, at)
		if err != nil || p.VisitAllowed != allowed {
			t.Fatalf("IP allowed=%t want=%t: %+v %v", p.VisitAllowed, allowed, p, err)
		}
	}
	check(auth, true, f.now)
	f.local(t, "web", &config.HTTPService{Access: &config.Access{Mode: "anonymous", IP: []string{"192.0.2.0/24"}}})
	check(auth, true, f.now)
	input.SourceIP = "198.51.100.9"
	check(auth, false, f.now)
	input.SourceIP = "192.0.2.9"
	f.local(t, "web", &config.HTTPService{Access: &config.Access{Mode: "anonymous", IP: []string{"198.51.100.9/32"}}})
	check(auth, false, f.now)
	input.SourceIP = "198.51.100.9"
	check(auth, true, f.now)
	f.local(t, "web", &config.HTTPService{Access: &config.Access{Mode: "anonymous"}})
	input.SourceIP = "192.0.2.9"
	check(auth, true, f.now)
	wrong := auth
	wrong.Number++
	if _, err := preparedServiceHTTPPermission(t.Context(), f.database, wrong, input, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("wrong run number admitted: %v", err)
	}
	if err := f.database.CloseServiceRun(t.Context(), auth.Subject.ID, auth.RunID, auth.Token.String(), f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := preparedServiceHTTPPermission(t.Context(), f.database, auth, input, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("closed run admitted: %v", err)
	}
}

func finalBrowserSession(t *testing.T, f serviceHTTPFixture, previewID, identityID string) (string, ControlSession) {
	t.Helper()
	d := f.database
	handoff, issued := f.browser(t, previewID, identityID)
	cookie, err := d.RedeemServiceBrowserHandoff(t.Context(), f.auth(), handoff.Token, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.RedeemServiceBrowserHandoff(t.Context(), f.auth(), handoff.Token, f.now); !errors.Is(err, ErrVisitorSignIn) {
		t.Fatalf("handoff replay: %v", err)
	}
	return cookie.CookieSecret, issued
}

func TestIntegrationFinalVisitorBrowserIdentityFeedbackAuthorPolicyAndSessionRevocation(t *testing.T) {
	f := newServiceHTTPFixture(t)
	f.run = f.publish(t, f.service)
	auth := f.auth()
	d := f.database
	owner := f.project.ActorID
	preview := f.preview(t, "final-feedback", f.service)
	visitor := finalVisitorIdentity(t, d, f.now, "reviewer@example.test")
	cookie, issued := finalBrowserSession(t, f, preview.ID, visitor)
	p, err := d.ServiceBrowserSession(t.Context(), auth, cookie, false, f.now)
	if err != nil || p.IdentityID != visitor || p.VisitAllowed {
		t.Fatalf("identity alone admitted: %+v %v", p, err)
	}
	if err := d.CloseServiceRun(t.Context(), auth.Subject.ID, auth.RunID, auth.Token.String(), f.now); err != nil {
		t.Fatal(err)
	}
	f.service = f.local(t, "web", &config.HTTPService{Access: &config.Access{Mode: "anonymous"}})
	f.run = f.publish(t, f.service)
	auth = f.auth()
	cookie, issued = finalBrowserSession(t, f, preview.ID, visitor)
	ip := FeedbackActor{Kind: "reviewer", SourceIP: "192.0.2.9", ServiceRun: &auth}
	report := CreateFeedbackRequest{PreviewID: preview.ID, Service: "web", PagePath: "/", ReportText: "immutable report", AuthorDisplayName: "anonymous name", Anchor: json.RawMessage(`null`), Evidence: json.RawMessage(`{"schema_version":1,"actions":[],"failed_requests":[]}`), SourceAtReport: feedbackTestSource(t), IdempotencyKey: "anonymous", Actor: ip}
	anonymous, err := d.CreateFeedback(t.Context(), auth, report, f.now)
	if err != nil || anonymous.AuthorVerified {
		t.Fatal(anonymous, err)
	}
	if _, err = d.SetTeamFeedbackPolicy(t.Context(), owner, f.project.TeamID, "signed_in", f.now); err != nil {
		t.Fatal(err)
	}
	report.IdempotencyKey = "signin-required"
	if _, err = d.CreateFeedback(t.Context(), auth, report, f.now); !errors.Is(err, ErrVisitorSignIn) {
		t.Fatalf("anonymous policy bypass: %v", err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(cookie)
	signed := ip
	signed.BrowserCookieSecret = raw
	signed.DisplayName = "forged"
	report.Actor = signed
	report.IdempotencyKey = "signed"
	thread, err := d.CreateFeedback(t.Context(), auth, report, f.now)
	if err != nil || !thread.AuthorVerified || thread.AuthorIdentityID != visitor || thread.AuthorDisplayName == "forged" {
		t.Fatalf("verified author: %+v %v", thread, err)
	}
	for _, event := range []FeedbackEventType{FeedbackReply, FeedbackThreadResolved, FeedbackThreadReopened} {
		request := AppendFeedbackRequest{FeedbackID: thread.ID, Type: event, Text: "note", IdempotencyKey: string(event), Actor: ip}
		if _, err = d.AppendFeedback(t.Context(), request, f.now); !errors.Is(err, ErrVisitorSignIn) {
			t.Fatalf("anonymous %s bypass: %v", event, err)
		}
		request.Actor = signed
		stored, err := d.AppendFeedback(t.Context(), request, f.now)
		if err != nil || !stored.AuthorVerified || stored.AuthorIdentityID != visitor {
			t.Fatal(stored, err)
		}
	}
	original, err := d.GetFeedback(t.Context(), thread.ID)
	if err != nil || original.ReportText != thread.ReportText || original.AuthorIdentityID != thread.AuthorIdentityID {
		t.Fatal("report changed", err)
	}
	if _, err = d.SetTeamFeedbackPolicy(t.Context(), owner, f.project.TeamID, "team_members", f.now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.AppendFeedback(t.Context(), AppendFeedbackRequest{FeedbackID: thread.ID, Type: FeedbackReply, Text: "no permission", IdempotencyKey: "team-only", Actor: signed}, f.now); !errors.Is(err, ErrFeedbackAccess) {
		t.Fatalf("nonmember author policy bypass: %v", err)
	}
	if err = d.RevokeControlSession(t.Context(), ControlPrincipal{IdentityID: visitor, SessionID: issued.SessionID}, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.ServiceBrowserSession(t.Context(), auth, cookie, false, f.now); !errors.Is(err, ErrVisitorSignIn) {
		t.Fatalf("revoked current control session admitted: %v", err)
	}
	if _, err = d.CreateFeedback(t.Context(), auth, report, f.now); !errors.Is(err, ErrVisitorSignIn) {
		t.Fatalf("revoked browser wrote: %v", err)
	}
}

func TestIntegrationFinalVisitorDeviceEnrollmentRevocationAndIdentityBoundary(t *testing.T) {
	f := newServiceHTTPFixture(t)
	d := f.database
	key, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := f.project.ActorID
	device, err := d.EnrollVisitorDevice(t.Context(), identity, key, f.now)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := d.EnrollVisitorDevice(t.Context(), identity, key, f.now)
	if err != nil || retry.ID != device.ID {
		t.Fatal("device enrollment retry changed key identity", err)
	}
	other := finalVisitorIdentity(t, d, f.now, "device@example.test")
	if err = d.RevokeVisitorDevice(t.Context(), other, device.ID, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("another identity revoked device: %v", err)
	}
	if err = d.RevokeVisitorDevice(t.Context(), identity, device.ID, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.EnrollVisitorDevice(t.Context(), identity, key, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("revoked key was resurrected: %v", err)
	}
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, identity, f.now); err != nil {
		t.Fatal(err)
	}
	key, _, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.EnrollVisitorDevice(t.Context(), identity, key, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("disabled identity enrolled key: %v", err)
	}
}

func TestIntegrationFinalVisitorAdminBrowserHandoffHasIndependentSessionAndFollowsCLIRevocation(t *testing.T) {
	f := newServiceHTTPFixture(t)
	f.run = f.publish(t, f.service)
	auth := f.auth()
	d := f.database
	parent := newOIDCSession(t, d, f.now)
	handoff, err := d.IssueControlBrowserHandoff(t.Context(), parent.AccessToken, parent.RefreshToken, f.service.ID, time.Hour, 24*time.Hour, f.now)
	if err != nil || handoff.Origin == "" {
		t.Fatal(err)
	}
	cookie, err := d.RedeemServiceBrowserHandoff(t.Context(), auth, handoff.Token, f.now)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := browserDigest(cookie.CookieSecret)
	var sessionID, keyID string
	var ciphertext []byte
	if err := d.pool.QueryRow(t.Context(), `SELECT control_session_id,storage_key_id,refresh_ciphertext FROM control.service_http_browser_sessions WHERE token_digest=$1`, digest).Scan(&sessionID, &keyID, &ciphertext); err != nil {
		t.Fatal(err)
	}
	refresh, _, err := d.storageKey.Open(keyID, browserContext(digest), ciphertext)
	if err != nil || sessionID == parent.SessionID || string(refresh) == parent.RefreshToken.String() {
		t.Fatal("CLI control session or refresh token reused for browser", err)
	}
	if permission, err := d.ServiceBrowserSession(t.Context(), auth, cookie.CookieSecret, false, f.now); err != nil || !permission.VisitAllowed {
		t.Fatal(permission, err)
	}
	if err = d.RevokeControlSession(t.Context(), ControlPrincipal{SessionID: parent.SessionID, IdentityID: parent.Identity.Identity.ID}, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.ServiceBrowserSession(t.Context(), auth, cookie.CookieSecret, false, f.now); !errors.Is(err, ErrVisitorSignIn) {
		t.Fatal("browser survived parent revocation", err)
	}
	if _, err = d.IssueControlBrowserHandoff(t.Context(), parent.AccessToken, parent.RefreshToken, f.service.ID, time.Hour, 24*time.Hour, f.now); !errors.Is(err, ErrControlAuthentication) {
		t.Fatal("revoked CLI created handoff", err)
	}
}

func TestIntegrationFinalVisitorHTTPDecisionUsesShareWithoutIPGrant(t *testing.T) {
	f := newServiceHTTPFixture(t)
	f.run = f.publish(t, f.service)
	auth := f.auth()
	d := f.database
	input := preparedVisitorInput{SourceIP: "192.0.2.9"}
	if p, err := preparedServiceHTTPPermission(t.Context(), d, auth, input, f.now); err != nil || p.VisitAllowed || p.IdentityID != "" {
		t.Fatal(p, err)
	}
	preview := f.preview(t, "visitor-shares", f.service)
	secret := bytes.Repeat([]byte{1}, 32)
	share := f.share(t, preview.ID, "anonymous", secret, f.service)
	redemption, err := d.RedeemShare(t.Context(), auth, share.ID, secret, nil, f.now)
	if err != nil {
		t.Fatal(err)
	}
	cookie, _ := base64.RawURLEncoding.Strict().DecodeString(redemption.CookieSecret)
	input.ShareID, input.ShareCookieSecret = share.ID, cookie
	if p, err := preparedServiceHTTPPermission(t.Context(), d, auth, input, f.now); err != nil || !p.VisitAllowed || p.IdentityID != "" || p.Reason != "anonymous_share" {
		t.Fatal(p, err)
	}
	if _, err = d.RevokeShare(t.Context(), share.ID, f.project.ActorID, f.now); err != nil {
		t.Fatal(err)
	}
	if p, err := preparedServiceHTTPPermission(t.Context(), d, auth, input, f.now); err != nil || p.VisitAllowed {
		t.Fatal("revoked share admitted", p, err)
	}
}

func TestIntegrationReplaceVisitorAccessChangesLiveRunWithoutIPBypass(t *testing.T) {
	f := newServiceHTTPFixture(t)
	f.run = f.publish(t, f.service)
	auth := f.auth()
	input := preparedVisitorInput{SourceIP: "192.0.2.9"}
	check := func(allowed bool) {
		t.Helper()
		permission, err := preparedServiceHTTPPermission(t.Context(), f.database, auth, input, f.now)
		if err != nil || permission.VisitAllowed != allowed {
			t.Fatalf("visitor allowed=%t, want %t: %+v %v", permission.VisitAllowed, allowed, permission, err)
		}
	}
	check(false)
	f.local(t, "web", &config.HTTPService{Access: &config.Access{Mode: "anonymous", IP: []string{"192.0.2.0/24"}}})
	check(true)
	input.SourceIP = "198.51.100.9"
	check(false)
	f.local(t, "web", &config.HTTPService{Access: &config.Access{Mode: "restricted"}})
	check(false)
}

func TestIntegrationExactURLShareSecretAndCookieAreInterchangeable(t *testing.T) {
	f := newServiceHTTPFixture(t)
	f.run = f.publish(t, f.service)
	auth := f.auth()
	d := f.database
	secret := bytes.Repeat([]byte{7}, 32)
	digest := sha256.Sum256(secret)
	share, err := d.CreateShare(t.Context(), CreateShareRequest{
		TeamID: f.project.TeamID, ActingIdentityID: f.project.ActorID,
		IdempotencyKey: "automation", Label: "ci", SecretFingerprint: digest,
		ExpiresAt: f.now.Add(30 * time.Second), ServiceIDs: []string{f.service.ID}, EntryServiceID: f.service.ID,
	}, f.now)
	if err != nil || share.Scope != "service" || share.PreviewID != "" || !slices.Equal(share.ServiceIDs, []string{f.service.ID}) {
		t.Fatalf("exact URL share: %+v, %v", share, err)
	}
	input := preparedVisitorInput{SourceIP: "192.0.2.1", ShareID: share.ID, ShareSecret: secret}
	check := func(at time.Time, allowed bool) {
		t.Helper()
		decision, err := preparedServiceHTTPPermission(t.Context(), d, auth, input, at)
		if err != nil || decision.VisitAllowed != allowed {
			t.Fatalf("share permission = %+v, want %t: %v", decision, allowed, err)
		}
	}
	check(f.now, true)
	if permission, err := preparedServiceHTTPPermission(t.Context(), d, auth, input, f.now); err != nil || permission.ExpiresAt == nil || permission.ExpiresAt.After(share.ExpiresAt) {
		t.Fatalf("HTTP decision outlived its share: %+v %v", permission, err)
	}
	redeemed, err := d.RedeemShare(t.Context(), auth, share.ID, secret, nil, f.now)
	if err != nil {
		t.Fatal(err)
	}
	cookie, _ := base64.RawURLEncoding.Strict().DecodeString(redeemed.CookieSecret)
	input.ShareSecret, input.ShareCookieSecret = nil, cookie
	check(f.now, true)
	if permission, err := preparedServiceHTTPPermission(t.Context(), d, auth, input, f.now); err != nil || permission.ExpiresAt == nil || permission.ExpiresAt.After(share.ExpiresAt) {
		t.Fatalf("browser cookie decision outlived its share: %+v %v", permission, err)
	}
	if err := d.CloseServiceRun(t.Context(), auth.Subject.ID, auth.RunID, auth.Token.String(), f.now); err != nil {
		t.Fatal(err)
	}
	f.service = f.local(t, "web", &config.HTTPService{Access: &config.Access{IP: []string{"192.0.2.0/24"}}})
	f.run = f.publish(t, f.service)
	auth = f.auth()
	check(f.now, false)
	redeemed, err = d.RedeemShare(t.Context(), auth, share.ID, secret, nil, f.now)
	if err != nil {
		t.Fatal(err)
	}
	input.ShareCookieSecret, _ = base64.RawURLEncoding.Strict().DecodeString(redeemed.CookieSecret)
	input.SourceIP = "198.51.100.9"
	check(f.now, false)
	input.SourceIP = "192.0.2.1"
	check(f.now.Add(time.Hour), false)
	input.ShareID = "shr_other"
	check(f.now, false)
	input.ShareID, input.ShareSecret, input.ShareCookieSecret = share.ID, secret, nil
	if _, err := d.RevokeShare(t.Context(), share.ID, f.project.ActorID, f.now); err != nil {
		t.Fatal(err)
	}
	check(f.now, false)
}
