package controlstate

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

func newBrowserReviewer(t *testing.T, database *Database, previewID, publicURLID, identityID string, now time.Time) (FeedbackActor, string, ControlSession) {
	t.Helper()
	tx, err := database.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	session, err := database.createControlSession(t.Context(), controlstatedb.New(tx), identityID, false, oidcAuthenticationMethod, 1, time.Hour, 24*time.Hour, now.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	handoff, err := database.IssueBrowserHandoff(t.Context(), BrowserLoginAttempt{
		PreviewID: previewID, PublicURLID: publicURLID, ReturnPath: "/",
	}, BrowserAccessSession{
		IdentityID: identityID, DisplayName: "stale session name", AccessToken: session.AccessToken.String(), RefreshToken: session.RefreshToken.String(),
		AccessExpiresAt: session.AccessExpiresAt, ExpiresAt: session.RefreshExpiresAt,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	cookie, _, _, _, _, err := database.RedeemBrowserHandoff(t.Context(), publicURLID, handoff.Token, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(cookie)
	if err != nil {
		t.Fatal(err)
	}
	return FeedbackActor{Kind: "reviewer", IdentityID: identityID, DisplayName: "untrusted caller name", BrowserCookieSecret: raw}, cookie, session
}

func browserFeedbackPreview(t *testing.T, f publishRunFixture) Preview {
	t.Helper()
	preview, err := f.database.CreatePreview(t.Context(), f.request.TeamID, f.request.ActingIdentityID, "browser-authorization", f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{
		PreviewID: preview.ID, PublicURLID: f.setup.PublicURLID, TeamID: f.request.TeamID,
		IdentityID: f.request.ActingIdentityID, PolicyRevision: 1, ExpectedMutationRevision: 2,
	}, f.now); err != nil {
		t.Fatal(err)
	}
	return preview
}

func browserFeedbackReport(t *testing.T, previewID string, actor FeedbackActor, key string) CreateFeedbackRequest {
	t.Helper()
	return CreateFeedbackRequest{
		PreviewID: previewID, Service: "web", PagePath: "/", ReportText: "The label is unclear", AuthorDisplayName: "untrusted report name",
		Anchor: json.RawMessage(`null`), Evidence: json.RawMessage(`{"schema_version":1,"actions":[],"failed_requests":[]}`),
		SourceAtReport: feedbackTestSource(t), IdempotencyKey: key, Actor: actor,
	}
}

func setBrowserTeamGrant(t *testing.T, f publishRunFixture, preview Preview, enabled bool) {
	t.Helper()
	team, err := f.database.GetTeam(t.Context(), f.request.ActingIdentityID, f.request.TeamID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.SetPreviewTeamAccess(t.Context(), SetPreviewTeamAccessRequest{
		PreviewID: preview.ID, TeamID: f.request.TeamID, IdentityID: f.request.ActingIdentityID, Enabled: enabled,
		PolicyRevision: uint64(team.PolicyRevision), PublicURLs: []AuthorizedSharePublicURL{{PublicURLID: f.setup.PublicURLID, ExpectedMutationRevision: 2}},
	}, f.now); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationBrowserAuthorizationUsesCurrentGrantAndMembership(t *testing.T) {
	f := newPublishRunFixture(t)
	preview := browserFeedbackPreview(t, f)
	database, now := f.database, f.now
	// the fixture's owner may sign in, but needs the same opt-in grant as other members.
	owner, ownerCookie, _ := newBrowserReviewer(t, database, preview.ID, f.setup.PublicURLID, f.request.ActingIdentityID, now)
	access, err := database.BrowserAuthorization(t.Context(), f.setup.PublicURLID, ownerCookie, now)
	if err != nil || access.Identity.IdentityID != owner.IdentityID || access.VisitAllowed {
		t.Fatalf("owner without grant = %+v, %v", access, err)
	}
	if _, err := database.CreateFeedback(t.Context(), f.authentication(), browserFeedbackReport(t, preview.ID, owner, "no-grant"), now); !errors.Is(err, ErrFeedbackAccess) {
		t.Fatalf("identity alone posted feedback: %v", err)
	}
	// use a current ordinary membership on a shared public URL, rather than an owner capability.
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.teams SET kind = 'organization' WHERE id = $1`, f.request.TeamID); err != nil {
		t.Fatal(err)
	}
	member := addAuthorityMember(t, database, now, f.request.ActingIdentityID, f.request.TeamID, "browser-reviewer", TeamRoleMember)
	actor, cookie, _ := newBrowserReviewer(t, database, preview.ID, f.setup.PublicURLID, member.IdentityID, now)
	setBrowserTeamGrant(t, f, preview, true)
	access, err = database.BrowserAuthorization(t.Context(), f.setup.PublicURLID, cookie, now)
	if err != nil || !access.VisitAllowed || access.Identity.IdentityID != member.IdentityID {
		t.Fatalf("member with current grant = %+v, %v", access, err)
	}
	thread, err := database.CreateFeedback(t.Context(), f.authentication(), browserFeedbackReport(t, preview.ID, actor, "member-report"), now)
	if err != nil || !thread.AuthorVerified || thread.AuthorIdentityID != member.IdentityID || thread.AuthorDisplayName != member.IdentityID {
		t.Fatalf("current-member report attribution = %+v, %v", thread, err)
	}
	if err := database.RemoveMembership(t.Context(), f.request.ActingIdentityID, f.request.TeamID, member.ID, now); err != nil {
		t.Fatal(err)
	}
	access, err = database.BrowserAuthorization(t.Context(), f.setup.PublicURLID, cookie, now)
	if err != nil || access.VisitAllowed || access.Identity.IdentityID != member.IdentityID {
		t.Fatalf("removed member identity/permission = %+v, %v", access, err)
	}
	if _, err := database.AppendFeedback(t.Context(), AppendFeedbackRequest{
		FeedbackID: thread.ID, Type: FeedbackReply, Text: "Another detail", IdempotencyKey: "removed-member", Actor: actor,
	}, now); !errors.Is(err, ErrFeedbackAccess) {
		t.Fatalf("removed member wrote feedback: %v", err)
	}
	actor.AllowedIP = true
	if event, err := database.AppendFeedback(t.Context(), AppendFeedbackRequest{
		FeedbackID: thread.ID, Type: FeedbackReply, Text: "Allowed by IP", IdempotencyKey: "removed-member-ip", Actor: actor,
	}, now); err != nil || !event.AuthorVerified || event.AuthorIdentityID != member.IdentityID {
		t.Fatalf("removed member with allowed IP lost verified attribution: %+v, %v", event, err)
	}
	setBrowserTeamGrant(t, f, preview, false)
	access, err = database.BrowserAuthorization(t.Context(), f.setup.PublicURLID, ownerCookie, now)
	if err != nil || access.VisitAllowed {
		t.Fatalf("disabled grant = %+v, %v", access, err)
	}
}

func TestIntegrationBrowserAuthorizationRejectsStaleIdentityAndScope(t *testing.T) {
	for _, change := range []string{"browser revoked", "browser expired", "browser access expired", "control revoked", "control expired", "identity disabled", "identity changed", "token replaced", "wrong preview", "wrong public URL"} {
		t.Run(change, func(t *testing.T) {
			f := newPublishRunFixture(t)
			preview := browserFeedbackPreview(t, f)
			actor, cookie, session := newBrowserReviewer(t, f.database, preview.ID, f.setup.PublicURLID, f.request.ActingIdentityID, f.now)
			actor.AllowedIP = true
			thread, err := f.database.CreateFeedback(t.Context(), f.authentication(), browserFeedbackReport(t, preview.ID, actor, "before-change"), f.now)
			if err != nil {
				t.Fatal(err)
			}
			digest, _ := browserDigest(cookie)
			publicURLID, previewID := f.setup.PublicURLID, preview.ID
			var query string
			var args []any
			switch change {
			case "browser revoked":
				query, args = `UPDATE control.browser_access_sessions SET revoked_at = $2 WHERE token_digest = $1`, []any{digest, f.now}
			case "browser expired":
				query, args = `UPDATE control.browser_access_sessions SET expires_at = $2 WHERE token_digest = $1`, []any{digest, f.now}
			case "browser access expired":
				query, args = `UPDATE control.browser_access_sessions SET access_expires_at = $2 WHERE token_digest = $1`, []any{digest, f.now}
			case "control revoked":
				if err := f.database.RevokeControlSession(t.Context(), ControlPrincipal{SessionID: session.SessionID, IdentityID: actor.IdentityID}, f.now); err != nil {
					t.Fatal(err)
				}
			case "control expired":
				query, args = `UPDATE control.control_sessions SET access_expires_at = $2 WHERE id = $1`, []any{session.SessionID, f.now}
			case "identity disabled":
				query, args = `UPDATE control.identities SET disabled_at = $2 WHERE id = $1`, []any{actor.IdentityID, f.now}
			case "identity changed":
				insertAuthorityIdentity(t, f.database, "other-browser-identity", "", false, f.now)
				query, args = `UPDATE control.browser_access_sessions SET identity_id = $2 WHERE token_digest = $1`, []any{digest, "other-browser-identity"}
			case "token replaced":
				query, args = `UPDATE control.control_sessions SET access_token_digest = $2 WHERE id = $1`, []any{session.SessionID, make([]byte, 32)}
			case "wrong preview":
				other, err := f.database.CreatePreview(t.Context(), f.request.TeamID, f.request.ActingIdentityID, "other-preview", f.now)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{
					PreviewID: other.ID, PublicURLID: f.setup.PublicURLID, TeamID: f.request.TeamID,
					IdentityID: f.request.ActingIdentityID, PolicyRevision: 1, ExpectedMutationRevision: 2,
				}, f.now); err != nil {
					t.Fatal(err)
				}
				previewID = other.ID
			case "wrong public URL":
				seedControlPublicURL(t, f.database, f.now, "other_browser")
				publicURLID = "public_url_other_browser"
			}
			if query != "" {
				if _, err := f.database.pool.Exec(t.Context(), query, args...); err != nil {
					t.Fatal(err)
				}
			}
			if change != "wrong preview" {
				if _, err := f.database.BrowserAuthorization(t.Context(), publicURLID, cookie, f.now); !errors.Is(err, ErrPreviewAccess) {
					t.Fatalf("stale browser identity was accepted: %v", err)
				}
			}
			auth := f.authentication()
			auth.PublicURLID = publicURLID
			if _, _, err := f.database.ReviewerFeedbackScope(t.Context(), auth, previewID, actor, f.now); !errors.Is(err, ErrFeedbackAccess) {
				t.Fatalf("stale reviewer scope was accepted: %v", err)
			}
			if _, err := f.database.CreateFeedback(t.Context(), auth, browserFeedbackReport(t, previewID, actor, "stale-report"), f.now); !errors.Is(err, ErrFeedbackAccess) {
				t.Fatalf("stale reviewer created feedback: %v", err)
			}
			if change != "wrong preview" && change != "wrong public URL" {
				if _, err := f.database.AppendFeedback(t.Context(), AppendFeedbackRequest{
					FeedbackID: thread.ID, Type: FeedbackReply, Text: "Stale identity", IdempotencyKey: "stale-reply", Actor: actor,
				}, f.now); !errors.Is(err, ErrFeedbackAccess) {
					t.Fatalf("stale reviewer appended feedback: %v", err)
				}
			}
		})
	}
}

func TestIntegrationReviewerWritesWaitForTeamBeforePublicURL(t *testing.T) {
	for _, operation := range []string{"report", "reply"} {
		t.Run(operation, func(t *testing.T) {
			f := newPublishRunFixture(t)
			preview := browserFeedbackPreview(t, f)
			actor, _, _ := newBrowserReviewer(t, f.database, preview.ID, f.setup.PublicURLID, f.request.ActingIdentityID, f.now)
			setBrowserTeamGrant(t, f, preview, true)
			thread, err := f.database.CreateFeedback(t.Context(), f.authentication(), browserFeedbackReport(t, preview.ID, actor, "initial"), f.now)
			if err != nil {
				t.Fatal(err)
			}
			seedControlPublicURL(t, f.database, f.now, "unrelated_browser")
			otherPreview, err := f.database.CreatePreview(t.Context(), "team_unrelated_browser", "identity_unrelated_browser", "unrelated", f.now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{
				PreviewID: otherPreview.ID, PublicURLID: "public_url_unrelated_browser", TeamID: "team_unrelated_browser",
				IdentityID: "identity_unrelated_browser", PolicyRevision: 1, ExpectedMutationRevision: 1,
			}, f.now); err != nil {
				t.Fatal(err)
			}
			_, otherCookie, _ := newBrowserReviewer(t, f.database, otherPreview.ID, "public_url_unrelated_browser", "identity_unrelated_browser", f.now)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			mutation, err := f.database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, mutation)
			queries := controlstatedb.New(mutation)
			if _, err := queries.LockLocalTeamForMutation(ctx, f.request.TeamID); err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			done := make(chan error, 1)
			request := browserFeedbackReport(t, preview.ID, actor, "waiting-report")
			workers.Go(func() {
				var err error
				if operation == "report" {
					_, err = f.database.CreateFeedback(ctx, f.authentication(), request, f.now)
				} else {
					_, err = f.database.AppendFeedback(ctx, AppendFeedbackRequest{FeedbackID: thread.ID, Type: FeedbackReply, Text: "Waiting reply", IdempotencyKey: "waiting-reply", Actor: actor}, f.now)
				}
				done <- err
			})
			waitForPostgresBlock(t, ctx, f.database, int32(mutation.Conn().PgConn().PID()), done)
			if access, err := f.database.BrowserAuthorization(ctx, "public_url_unrelated_browser", otherCookie, f.now); err != nil || access.Identity.IdentityID != "identity_unrelated_browser" {
				t.Fatalf("unrelated browser authorization blocked on another team: %+v, %v", access, err)
			}
			// the queued reviewer must not hold the public URL needed by the mutation.
			if _, err := queries.LockPublicURLForRun(ctx, f.setup.PublicURLID); err != nil {
				t.Fatal(err)
			}
			if err := queries.SetPreviewTeamAccess(ctx, controlstatedb.SetPreviewTeamAccessParams{PreviewID: preview.ID, Enabled: false}); err != nil {
				t.Fatal(err)
			}
			if err := mutation.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrFeedbackAccess) {
				t.Fatalf("queued reviewer ignored the revoked grant: %v", err)
			}
		})
	}
}
