package state

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationBrowserLoginHandoffAndRevocation(t *testing.T) {
	f := newServiceHTTPFixture(t)
	database, now := f.database, f.now
	f.run = f.publish(t, f.service)
	preview := f.preview(t, "browser-access", f.service)
	binding := bytes.Repeat([]byte{7}, 32)
	state, err := database.BeginServiceBrowserLogin(t.Context(), f.auth().Subject, preview.ID, "/settings?tab=profile", "nonce-at-least-sixteen", strings.Repeat("v", 43), binding, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ConsumeBrowserLogin(t.Context(), state, bytes.Repeat([]byte{8}, 32), now); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("another browser consumed login state: %v", err)
	}
	login, err := database.ConsumeBrowserLogin(t.Context(), state, binding, now)
	if err != nil || login.PreviewID != preview.ID || login.Subject != f.auth().Subject ||
		!slices.Equal(login.ServiceRunIDs, []string{f.run.RunID}) || login.ReturnPath != "/settings?tab=profile" {
		t.Fatalf("browser login = %+v, %v", login, err)
	}
	if _, err := database.ConsumeBrowserLogin(t.Context(), state, binding, now); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("replayed login = %v", err)
	}
	issued := browserTestControlSession(t, database, f.project.ActorID, now)
	handoff, err := database.IssueBrowserHandoff(t.Context(), login, BrowserAccessSession{
		IdentityID: f.project.ActorID, AccessToken: issued.AccessToken.String(), RefreshToken: issued.RefreshToken.String(),
		AccessExpiresAt: issued.AccessExpiresAt, ExpiresAt: issued.RefreshExpiresAt,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	var ciphertext []byte
	if err := database.pool.QueryRow(t.Context(), `SELECT refresh_ciphertext FROM control.service_http_browser_sessions WHERE control_session_id=$1`, issued.SessionID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte(issued.AccessToken.String())) || bytes.Contains(ciphertext, []byte(issued.RefreshToken.String())) {
		t.Fatal("browser tokens were stored in plaintext")
	}
	wrong := f.auth()
	wrong.Subject.ID = "svc_" + strings.Repeat("Z", 22)
	if _, err := database.RedeemServiceBrowserHandoff(t.Context(), wrong, handoff.Token, now); err == nil {
		t.Fatal("different service redeemed browser handoff")
	}
	redeemed, err := database.RedeemServiceBrowserHandoff(t.Context(), f.auth(), handoff.Token, now)
	if err != nil || redeemed.CookieSecret == "" || redeemed.ReturnPath != login.ReturnPath {
		t.Fatalf("browser handoff = %+v, %v", redeemed, err)
	}
	if _, err := database.RedeemServiceBrowserHandoff(t.Context(), f.auth(), handoff.Token, now); !errors.Is(err, ErrVisitorSignIn) {
		t.Fatalf("replayed browser handoff = %v", err)
	}
	identity, err := database.ServiceBrowserSession(t.Context(), f.auth(), redeemed.CookieSecret, false, now)
	if err != nil || identity.IdentityID != f.project.ActorID || !identity.Authenticated {
		t.Fatalf("browser session identity = %+v, %v", identity, err)
	}
	now = now.Add(2 * time.Second)
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, issued.SessionID, now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.RefreshServiceBrowserSession(t.Context(), f.service.ID, redeemed.CookieSecret, now,
		func(context.Context, string) (BrowserTokenRotation, error) {
			return BrowserTokenRotation{IdentityID: "another person", AccessToken: issued.AccessToken.String(), RefreshToken: "invalid", AccessExpiresAt: now.Add(time.Hour)}, nil
		}); !errors.Is(err, ErrPreviewAccess) {
		t.Fatal("browser rotation accepted a different identity", err)
	}
	var rotations atomic.Int32
	results := make(chan error, 2)
	for range 2 {
		go func() {
			updated, err := database.RefreshServiceBrowserSession(t.Context(), f.service.ID, redeemed.CookieSecret, now,
				func(ctx context.Context, previous string) (BrowserTokenRotation, error) {
					if previous != issued.RefreshToken.String() {
						return BrowserTokenRotation{}, ErrPreviewAccess
					}
					rotations.Add(1)
					rotated, err := database.RefreshControlSession(ctx, issued.RefreshToken, time.Hour, now)
					return BrowserTokenRotation{IdentityID: f.project.ActorID, AccessToken: rotated.AccessToken.String(),
						RefreshToken: rotated.RefreshToken.String(), AccessExpiresAt: rotated.AccessExpiresAt}, err
				})
			if err == nil && (!updated.AccessExpiresAt.After(now) || !updated.ExpiresAt.Equal(redeemed.ExpiresAt)) {
				err = ErrPreviewAccess
			}
			results <- err
		}()
	}
	for range 2 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent browser refresh blocked")
		}
	}
	if rotations.Load() != 1 {
		t.Fatalf("authority refresh calls = %d, want one", rotations.Load())
	}
	if _, err := database.ServiceBrowserSession(t.Context(), f.auth(), redeemed.CookieSecret, true, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ServiceBrowserSession(t.Context(), f.auth(), redeemed.CookieSecret, false, now); !errors.Is(err, ErrVisitorSignIn) {
		t.Fatalf("revoked browser session = %v", err)
	}
}

func TestIntegrationNonmemberWithAnonymousAccessPostsVerifiedFeedback(t *testing.T) {
	f := newServiceHTTPFixture(t)
	database, now := f.database, f.now
	f.service = f.local(t, "web", &config.HTTPService{Access: &config.Access{Mode: "anonymous"}})
	f.run = f.publish(t, f.service)
	preview := f.preview(t, "browser-feedback", f.service)
	const identityID = "00000000-0000-4000-8000-000000000002"
	insertAuthorityIdentity(t, database, identityID, "", false, now)
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.identities SET display_name='Sam' WHERE id=$1`, identityID); err != nil {
		t.Fatal(err)
	}
	handoff, _ := f.browser(t, preview.ID, identityID)
	redeemed, err := database.RedeemServiceBrowserHandoff(t.Context(), f.auth(), handoff.Token, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.Strict().DecodeString(redeemed.CookieSecret)
	auth := f.auth()
	actor := FeedbackActor{Kind: "reviewer", SourceIP: "192.0.2.9", ServiceRun: &auth,
		IdentityID: identityID, DisplayName: "forged", BrowserCookieSecret: raw}
	request := CreateFeedbackRequest{
		PreviewID: preview.ID, Service: "web", PagePath: "/", ReportText: "The label is unclear",
		Anchor:         json.RawMessage(`null`),
		Evidence:       json.RawMessage(`{"schema_version":1,"actions":[],"failed_requests":[]}`),
		SourceAtReport: feedbackTestSource(t), IdempotencyKey: "signed-report", Actor: actor,
	}
	thread, err := database.CreateFeedback(t.Context(), auth, request, now)
	if err != nil || thread.AuthorDisplayName != "Sam" || thread.AuthorIdentityID != identityID || !thread.AuthorVerified {
		t.Fatalf("verified report identity = %+v, %v", thread, err)
	}
	reply, err := database.AppendFeedback(t.Context(), AppendFeedbackRequest{
		FeedbackID: thread.ID, Type: FeedbackReply, Text: "One more detail", IdempotencyKey: "signed-reply", Actor: actor,
	}, now)
	if err != nil || reply.AuthorIdentityID != identityID || reply.AuthorDisplayName != "Sam" || !reply.AuthorVerified {
		t.Fatalf("verified reply identity = %+v, %v", reply, err)
	}
	// the local publisher closes its single-publisher run before replacement.
	// realization alone does not stop that runtime.
	if err := database.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, now); err != nil {
		t.Fatal(err)
	}
	previousAuth, previousCookie := auth, redeemed.CookieSecret
	f.service = f.local(t, "web", &config.HTTPService{Access: &config.Access{Mode: "restricted"}})
	f.run = f.publish(t, f.service)
	auth = f.auth()
	if _, err := database.ServiceBrowserSession(t.Context(), previousAuth, previousCookie, false, now); err == nil {
		t.Fatal("closed run retained browser access after replacement")
	}
	handoff, _ = f.browser(t, preview.ID, identityID)
	redeemed, err = database.RedeemServiceBrowserHandoff(t.Context(), auth, handoff.Token, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = base64.RawURLEncoding.Strict().DecodeString(redeemed.CookieSecret)
	actor.BrowserCookieSecret, actor.ServiceRun = raw, &auth
	secret := []byte("0123456789abcdefghijklmnopqrstuv")
	share := f.share(t, preview.ID, "nonmember-share", secret, f.service)
	redemption, err := database.RedeemShare(t.Context(), auth, share.ID, secret, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	actor.ShareID = share.ID
	actor.CookieSecret, _ = base64.RawURLEncoding.Strict().DecodeString(redemption.CookieSecret)
	request.Actor, request.IdempotencyKey, request.ReportText = actor, "signed-link-report", "Suggestion through a share"
	sharedReport, err := database.CreateFeedback(t.Context(), auth, request, now)
	if err != nil || !sharedReport.AuthorVerified || sharedReport.AuthorIdentityID != identityID {
		t.Fatalf("signed-in nonmember with link = %+v, %v", sharedReport, err)
	}
	actor.ShareID, actor.CookieSecret, actor.TeamMember = "", nil, true
	if _, _, err := database.ReviewerFeedbackScope(t.Context(), auth, preview.ID, actor, now); !errors.Is(err, ErrFeedbackAccess) {
		t.Fatalf("nonmember used team access without a team grant: %v", err)
	}
}

func TestIntegrationBrowserLoginInstallsAccessOnReadyPreviewHostnames(t *testing.T) {
	f := newServiceHTTPFixture(t)
	f.run = f.publish(t, f.service)
	other := f
	other.service = f.local(t, "api", nil)
	other.run = f.publish(t, other.service)
	preview := f.preview(t, "browser-multi-host", f.service, other.service)
	handoff, control := f.browser(t, preview.ID, f.project.ActorID)
	first, err := f.database.RedeemServiceBrowserHandoff(t.Context(), f.auth(), handoff.Token, f.now)
	prefix := "https://" + other.service.Endpoint.Hostname + "/__tnl/team/handoff/"
	if err != nil || first.ReturnPath != "/" || first.NextUrl == nil || !strings.HasPrefix(*first.NextUrl, prefix) {
		t.Fatalf("first host returned %+v, %v", first, err)
	}
	ticket := strings.TrimPrefix(*first.NextUrl, prefix)
	// an unconsumed host binding cannot revoke the shared session.
	if _, err := f.database.ServiceBrowserSession(t.Context(), other.auth(), first.CookieSecret, true, f.now); err != nil {
		t.Fatal(err)
	}
	next, err := f.database.RedeemServiceBrowserHandoff(t.Context(), other.auth(), ticket, f.now)
	if err != nil || next.CookieSecret != first.CookieSecret || next.NextUrl == nil || *next.NextUrl != "https://"+f.service.Endpoint.Hostname+"/" {
		t.Fatalf("other host handoff = %+v, %v", next, err)
	}
	if _, err := f.database.ServiceBrowserSession(t.Context(), other.auth(), first.CookieSecret, false, f.now); err != nil {
		t.Fatalf("other host browser session: %v", err)
	}
	unrelated, unrelatedControl := f.browser(t, "", f.project.ActorID)
	unrelatedCookie, err := f.database.RedeemServiceBrowserHandoff(t.Context(), f.auth(), unrelated.Token, f.now)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := browserDigest(first.CookieSecret)
	if err != nil {
		t.Fatal(err)
	}
	// a consumed service binding is still not authority for another run.
	if err := controlstatedb.New(f.database.pool).RevokeServiceHTTPBrowserSession(t.Context(), controlstatedb.RevokeServiceHTTPBrowserSessionParams{
		ServiceID: f.service.ID, ServiceRunID: other.run.RunID, CookieDigest: digest, Now: timestamptz(f.now),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.ServiceBrowserSession(t.Context(), f.auth(), first.CookieSecret, false, f.now); err != nil {
		t.Fatalf("mismatched run revoked the shared session: %v", err)
	}
	if _, err := f.database.ServiceBrowserSession(t.Context(), other.auth(), first.CookieSecret, true, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.ServiceBrowserSession(t.Context(), f.auth(), first.CookieSecret, false, f.now); !errors.Is(err, ErrVisitorSignIn) {
		t.Fatalf("other hostname's logout left shared session usable: %v", err)
	}
	if _, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, f.auth().Subject, BrowserSessionTokenSource{Secret: first.CookieSecret}, f.now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatalf("logged-out shared session renewed visitor permission: %v", err)
	}
	if _, err := f.database.ServiceBrowserSession(t.Context(), f.auth(), unrelatedCookie.CookieSecret, false, f.now); err != nil {
		t.Fatalf("logout revoked another browser session: %v", err)
	}
	for _, session := range []ControlSession{control, unrelatedControl} {
		if _, err := f.database.AuthenticateAccessToken(t.Context(), session.AccessToken, f.now); err != nil {
			t.Fatalf("browser logout revoked a control session: %v", err)
		}
	}
	pending, _ := f.browser(t, preview.ID, f.project.ActorID)
	pendingCookie, err := f.database.RedeemServiceBrowserHandoff(t.Context(), f.auth(), pending.Token, f.now)
	if err != nil || pendingCookie.NextUrl == nil || !strings.HasPrefix(*pendingCookie.NextUrl, prefix) {
		t.Fatalf("pending hostname chain = %+v, %v", pendingCookie, err)
	}
	if _, err := f.database.ServiceBrowserSession(t.Context(), f.auth(), pendingCookie.CookieSecret, true, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.RedeemServiceBrowserHandoff(t.Context(), other.auth(), strings.TrimPrefix(*pendingCookie.NextUrl, prefix), f.now); !errors.Is(err, ErrVisitorSignIn) {
		t.Fatalf("logged-out shared session installed a pending host cookie: %v", err)
	}
}

func browserTestControlSession(t *testing.T, d *Database, identityID string, now time.Time) ControlSession {
	t.Helper()
	tx, err := d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	result, err := d.createControlSession(t.Context(), controlstatedb.New(tx), identityID, time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestIntegrationAliasOwnerBrowserHandoffs(t *testing.T) {
	for _, native := range []bool{false, true} {
		name := "browser"
		if native {
			name = "native"
		}
		t.Run(name, func(t *testing.T) {
			f := newServiceHTTPFixture(t)
			f.service = f.local(t, "alias", nil)
			f.run = f.publish(t, f.service)
			session := browserTestControlSession(t, f.database, f.project.ActorID, f.now)
			var handoff BrowserHandoff
			var err error
			if native {
				otherSession := browserTestControlSession(t, f.database, f.project.ActorID, f.now)
				if _, err := f.database.IssueControlBrowserHandoff(t.Context(), session.AccessToken, otherSession.RefreshToken, f.service.ID, time.Hour, 24*time.Hour, f.now); !errors.Is(err, ErrControlAuthentication) {
					t.Fatalf("native handoff accepted an access/refresh pair from different sessions: %v", err)
				}
				handoff, err = f.database.IssueControlBrowserHandoff(t.Context(), session.AccessToken, session.RefreshToken, f.service.ID, time.Hour, 24*time.Hour, f.now)
			} else {
				handoff, _ = f.browser(t, "", f.project.ActorID)
			}
			if err != nil {
				t.Fatalf("alias owner handoff issuance: %v", err)
			}
			wrong := f.auth()
			wrong.RunID = "srun_" + strings.Repeat("Z", 22)
			if _, err := f.database.RedeemServiceBrowserHandoff(t.Context(), wrong, handoff.Token, f.now); err == nil {
				t.Fatal("replacement run redeemed the alias handoff")
			}
			cookie, err := f.database.RedeemServiceBrowserHandoff(t.Context(), f.auth(), handoff.Token, f.now)
			if err != nil {
				t.Fatalf("alias owner handoff redemption: %v", err)
			}
			if got, err := f.database.ServiceBrowserSession(t.Context(), f.auth(), cookie.CookieSecret, false, f.now); err != nil || got.IdentityID != f.project.ActorID {
				t.Fatalf("alias owner session: %+v, %v", got, err)
			}
			if _, err := f.database.RedeemServiceBrowserHandoff(t.Context(), f.auth(), handoff.Token, f.now); !errors.Is(err, ErrVisitorSignIn) {
				t.Fatalf("alias handoff replay: %v", err)
			}
		})
	}
}
