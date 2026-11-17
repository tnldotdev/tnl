package state

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func feedbackBrowserSecret(t *testing.T, ctx context.Context, f serviceHTTPFixture, preview, identity string) []byte {
	t.Helper()
	handoff, _ := f.browser(t, preview, identity)
	cookie, err := f.database.RedeemServiceBrowserHandoff(ctx, f.auth(), handoff.Token, f.now)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(cookie.CookieSecret)
	if err != nil {
		t.Fatal(err)
	}
	return secret
}

func TestIntegrationFeedbackCombinedBrowserShareUsesVerifiedAuthor(t *testing.T) {
	f := newServiceHTTPFixture(t)
	d, now := f.database, f.now
	f.run = f.publish(t, f.service)
	preview := f.preview(t, "combined-feedback", f.service)
	identity := mustOpaqueID(t, "ident_")
	insertAuthorityIdentity(t, d, identity, "", false, now)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.identities SET display_name='Verified reviewer' WHERE id=$1`, identity); err != nil {
		t.Fatal(err)
	}
	browser := feedbackBrowserSecret(t, t.Context(), f, preview.ID, identity)
	secret := []byte(strings.Repeat("s", 32))
	share := f.share(t, preview.ID, "combined-share", secret, f.service)
	actor := FeedbackActor{Kind: "reviewer", ShareID: share.ID, ShareSecret: secret, BrowserCookieSecret: browser, IdentityID: "forged", DisplayName: "forged", SourceIP: "192.0.2.9"}
	for _, operation := range []string{"report", "reply"} {
		decision, err := d.AuthorizeReviewerFeedback(t.Context(), f.auth(), preview.ID, operation, actor, now)
		if err != nil || !decision.Author.Verified || decision.Author.IdentityId == nil || *decision.Author.IdentityId != identity || decision.Author.DisplayName != "Verified reviewer" {
			t.Fatal("combined share permission lost its verified browser author", decision, err)
		}
	}
	if _, err := d.RevokeShare(t.Context(), share.ID, f.project.ActorID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AuthorizeReviewerFeedback(t.Context(), f.auth(), preview.ID, "reply", actor, now); !errors.Is(err, ErrFeedbackAccess) {
		t.Fatal("revoked share retained feedback access", err)
	}
}

func TestIntegrationFeedbackImplementerManagementCurrent(t *testing.T) {
	f := newServiceHTTPFixture(t)
	f.run = f.publish(t, f.service)
	preview := f.preview(t, "management-feedback", f.service)
	session := browserTestControlSession(t, f.database, f.project.ActorID, f.now)
	principal := ControlPrincipal{IdentityID: f.project.ActorID, SessionID: session.SessionID}
	ctx := WithControlPrincipal(t.Context(), principal)
	for _, operation := range []string{"read", "reply", "update", "thread.resolved", "thread.reopened", "delete"} {
		decision, err := f.database.AuthorizeImplementerFeedback(ctx, f.project.ActorID, f.service.ID, preview.ID, operation, f.now)
		if err != nil || decision.Author.IdentityId == nil || *decision.Author.IdentityId != f.project.ActorID || !decision.Author.Verified || decision.Actor != "implementer" {
			t.Fatal("management did not derive author", operation, decision, err)
		}
	}
	if _, err := f.database.AuthorizeImplementerFeedback(ctx, f.project.ActorID, f.service.ID, preview.ID, "report", f.now); !errors.Is(err, ErrFeedbackInvalid) {
		t.Fatal("implementer created a reviewer report", err)
	}
	if _, err := f.database.AuthorizeImplementerFeedback(ctx, "different-identity", f.service.ID, preview.ID, "update", f.now); err == nil {
		t.Fatal("unrelated identity authorized update")
	}
	if err := f.database.RevokeControlSession(t.Context(), principal, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.AuthorizeImplementerFeedback(ctx, f.project.ActorID, f.service.ID, preview.ID, "delete", f.now); err == nil {
		t.Fatal("revoked management session authorized delete")
	}
}

func TestIntegrationFeedbackResolvedReplyRechecksAuthorAndPreviewAccess(t *testing.T) {
	for _, change := range []string{"missing author", "no preview access", "share revoked", "share expired",
		"author session revoked", "author session wrong service", "author policy", "preview removed"} {
		t.Run(change, func(t *testing.T) {
			f := newServiceHTTPFixture(t)
			d, ctx := f.database, t.Context()
			f.run = f.publish(t, f.service)
			preview := f.preview(t, "resolved-access", f.service)
			secret := []byte(strings.Repeat("s", 32))
			share := f.share(t, preview.ID, "resolved-share", secret, f.service)
			identity := finalVisitorIdentity(t, d, f.now, "resolved-reviewer@example.test")
			cookie, session := finalBrowserSession(t, f, preview.ID, identity)
			browser, err := base64.RawURLEncoding.Strict().DecodeString(cookie)
			if err != nil {
				t.Fatal(err)
			}
			auth := f.auth()
			actor := FeedbackActor{Kind: "reviewer", SourceIP: "192.0.2.9", ServiceRun: &auth,
				ShareID: share.ID, ShareSecret: secret, BrowserCookieSecret: browser}
			if _, err := d.AuthorizeReviewerFeedback(ctx, auth, preview.ID, "reply", actor, f.now); err != nil {
				t.Fatal("current reviewer could not reply", err)
			}
			at, want := f.now, ErrFeedbackAccess
			switch change {
			case "missing author":
				actor.BrowserCookieSecret = nil
				want = ErrVisitorSignIn
			case "no preview access":
				actor.ShareID, actor.ShareSecret = "", nil
			case "share revoked":
				_, err = d.RevokeShare(ctx, share.ID, f.project.ActorID, f.now)
			case "share expired":
				_, err = d.pool.Exec(ctx, `UPDATE control.shares SET expires_at=$2 WHERE id=$1`, share.ID, f.now.Add(time.Second))
				at = f.now.Add(2 * time.Second)
			case "author session revoked":
				err = d.RevokeControlSession(ctx, ControlPrincipal{IdentityID: identity, SessionID: session.SessionID}, f.now)
				want = ErrVisitorSignIn
			case "author session wrong service":
				other := f
				other.service = f.local(t, "other", nil)
				other.run = f.publish(t, other.service)
				otherPreview := other.preview(t, "other-preview", other.service)
				actor.BrowserCookieSecret = feedbackBrowserSecret(t, ctx, other, otherPreview.ID, identity)
				want = ErrVisitorSignIn
			case "author policy":
				_, err = d.SetTeamFeedbackPolicy(ctx, f.project.ActorID, f.project.TeamID, "team_members", f.now)
			case "preview removed":
				_, err = d.pool.Exec(ctx, `DELETE FROM control.preview_services WHERE preview_id=$1 AND service_id=$2`, preview.ID, f.service.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			decision, err := d.AuthorizeReviewerFeedback(ctx, auth, preview.ID, "reply", actor, at)
			if !errors.Is(err, want) || decision.ServiceId != "" {
				t.Fatal("reply bypassed current author or preview permission", decision, err)
			}
		})
	}
}
