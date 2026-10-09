package controlstate

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
)

func TestIntegrationBrowserOwnershipUsesCurrentMembershipAndURLScope(t *testing.T) {
	for _, sessionScope := range []string{"public URL", "preview"} {
		for _, urlScope := range []PublicURLScope{PublicURLScopeMember, PublicURLScopeShared} {
			t.Run(sessionScope+"/"+string(urlScope), func(t *testing.T) {
				f := newPublishRunFixture(t)
				database, now := f.database, f.now
				preview := browserFeedbackPreview(t, f)
				if _, err := database.pool.Exec(t.Context(), `UPDATE control.teams SET kind = 'organization' WHERE id = $1`, f.request.TeamID); err != nil {
					t.Fatal(err)
				}
				member := addAuthorityMember(t, database, now, f.request.ActingIdentityID, f.request.TeamID, "url-owner", TeamRoleMember)
				admin := addAuthorityMember(t, database, now, f.request.ActingIdentityID, f.request.TeamID, "team-admin", TeamRoleAdmin)
				other := addAuthorityMember(t, database, now, f.request.ActingIdentityID, f.request.TeamID, "other-member", TeamRoleMember)
				if urlScope == PublicURLScopeMember {
					if _, err := database.pool.Exec(t.Context(), `UPDATE control.public_urls SET public_url_scope = 'member', membership_id = $2 WHERE id = $1`, f.setup.PublicURLID, member.ID); err != nil {
						t.Fatal(err)
					}
				}
				previewID := ""
				if sessionScope == "preview" {
					previewID = preview.ID
				}
				cookies := map[string]string{}
				for _, identityID := range []string{member.IdentityID, admin.IdentityID, other.IdentityID, f.request.ActingIdentityID} {
					_, cookie, _ := newBrowserReviewer(t, database, previewID, f.setup.PublicURLID, identityID, now)
					cookies[identityID] = cookie
				}
				check := func(identityID string, allowed bool) {
					t.Helper()
					access, err := database.BrowserAuthorization(t.Context(), f.setup.PublicURLID, cookies[identityID], now)
					if err != nil || access.Identity.IdentityID != identityID || access.VisitAllowed != allowed {
						t.Fatalf("current identity %q allowed=%t, want %t: %v", identityID, access.VisitAllowed, allowed, err)
					}
				}
				check(member.IdentityID, urlScope == PublicURLScopeMember)
				check(admin.IdentityID, urlScope == PublicURLScopeShared)
				check(f.request.ActingIdentityID, urlScope == PublicURLScopeShared)
				check(other.IdentityID, false)
				// seed the grant directly: this test exercises admission, while grant
				// mutation authorization has separate coverage for URL ownership.
				if _, err := database.pool.Exec(t.Context(), `UPDATE control.previews SET team_access_enabled = true WHERE id = $1`, preview.ID); err != nil {
					t.Fatal(err)
				}
				check(other.IdentityID, sessionScope == "preview")
				check(admin.IdentityID, urlScope == PublicURLScopeShared || sessionScope == "preview")
				if _, err := database.pool.Exec(t.Context(), `UPDATE control.previews SET team_access_enabled = false WHERE id = $1`, preview.ID); err != nil {
					t.Fatal(err)
				}
				check(other.IdentityID, false)
				check(member.IdentityID, urlScope == PublicURLScopeMember)
				check(admin.IdentityID, urlScope == PublicURLScopeShared)
				if _, err := database.SetMembershipRole(t.Context(), f.request.ActingIdentityID, f.request.TeamID, admin.ID, TeamRoleMember, now); err != nil {
					t.Fatal(err)
				}
				check(admin.IdentityID, false)
				if err := database.RemoveMembership(t.Context(), f.request.ActingIdentityID, f.request.TeamID, member.ID, now); err != nil {
					t.Fatal(err)
				}
				check(member.IdentityID, false)
			})
		}
	}
}

func TestIntegrationBrowserURLScopedOwnerFeedbackHasSeparatePreview(t *testing.T) {
	f := newPublishRunFixture(t)
	preview := browserFeedbackPreview(t, f)
	actor, cookie, _ := newBrowserReviewer(t, f.database, "", f.setup.PublicURLID, f.request.ActingIdentityID, f.now)
	access, err := f.database.BrowserAuthorization(t.Context(), f.setup.PublicURLID, cookie, f.now)
	if err != nil || !access.VisitAllowed || access.Identity.PreviewID != "" {
		t.Fatalf("URL-scoped owner access = %+v, %v", access, err)
	}
	if _, _, err := f.database.ReviewerFeedbackScope(t.Context(), f.authentication(), preview.ID, actor, f.now); err != nil {
		t.Fatal(err)
	}
	thread, err := f.database.CreateFeedback(t.Context(), f.authentication(), browserFeedbackReport(t, preview.ID, actor, "url-owner"), f.now)
	if err != nil || thread.PreviewID != preview.ID || !thread.AuthorVerified || thread.AuthorIdentityID != actor.IdentityID {
		t.Fatalf("URL-scoped owner report = %+v, %v", thread, err)
	}
	event, err := f.database.AppendFeedback(t.Context(), AppendFeedbackRequest{FeedbackID: thread.ID, Type: FeedbackReply, Text: "Owner reply", IdempotencyKey: "url-owner-reply", Actor: actor}, f.now)
	if err != nil || !event.AuthorVerified || event.AuthorIdentityID != actor.IdentityID {
		t.Fatalf("URL-scoped owner reply = %+v, %v", event, err)
	}
}

func TestIntegrationBrowserCapabilityBindsExactLiveAppRun(t *testing.T) {
	for _, change := range []string{"valid", "wrong token", "wrong number", "wrong run", "wrong URL", "ready", "expired", "closed", "alias", "demo", "oauth", "webhooks"} {
		t.Run(change, func(t *testing.T) {
			f := newPublishRunFixture(t)
			auth := f.authentication()
			checkAt := f.now
			var query string
			var args []any
			switch change {
			case "wrong token":
				auth.PublishRunToken, _, _, _ = credentials.NewPublishRunToken()
			case "wrong number":
				auth.PublishRunNumber++
			case "wrong run":
				auth.PublishRunID = "pr_wrong"
			case "wrong URL":
				auth.PublicURLID = "url_wrong"
			case "ready":
				query, args = `UPDATE control.publish_runs SET state = 'ready', ready_at = $2 WHERE id = $1`, []any{auth.PublishRunID, f.now}
			case "expired":
				checkAt = f.setup.ExpiresAt
			case "closed":
				query, args = `UPDATE control.publish_runs SET state = 'closed', closed_at = $2, close_reason = 'publisher_closed' WHERE id = $1`, []any{auth.PublishRunID, f.now}
			case "alias", "demo", "oauth", "webhooks":
				query, args = `UPDATE control.public_urls SET purpose = $2 WHERE id = $1`, []any{auth.PublicURLID, change}
			}
			if query != "" {
				if _, err := f.database.pool.Exec(t.Context(), query, args...); err != nil {
					t.Fatal(err)
				}
			}
			err := f.database.EnableBrowserAccess(t.Context(), auth, checkAt)
			if change != "valid" {
				want := ErrPublishRunStale
				switch change {
				case "wrong token":
					want = ErrPublishRunCredential
				case "wrong URL", "alias", "demo", "oauth", "webhooks":
					want = ErrPreviewAccess
				}
				if !errors.Is(err, want) {
					t.Fatalf("invalid browser registration = %v, want %v", err, want)
				}
				var capable bool
				if err := f.database.pool.QueryRow(t.Context(), `SELECT browser_capable FROM control.publish_runs WHERE id = $1`, f.setup.PublishRunID).Scan(&capable); err != nil || capable {
					t.Fatalf("invalid registration changed capability: %t, %v", capable, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := f.database.EnableBrowserAccess(t.Context(), auth, f.now); err != nil {
				t.Fatalf("registration retry: %v", err)
			}
			if err := f.database.RequireBrowserAccess(t.Context(), auth, f.now); !errors.Is(err, ErrPreviewAccess) {
				t.Fatalf("starting run admitted browser access: %v", err)
			}
			if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.publish_runs SET state = 'ready', ready_at = $2 WHERE id = $1`, auth.PublishRunID, f.now); err != nil {
				t.Fatal(err)
			}
			if err := f.database.RequireBrowserAccess(t.Context(), auth, f.now); err != nil {
				t.Fatal(err)
			}
			var shares bool
			if err := f.database.pool.QueryRow(t.Context(), `SELECT share_capable FROM control.publish_runs WHERE id = $1`, auth.PublishRunID).Scan(&shares); err != nil || shares {
				t.Fatalf("browser registration enabled shares: %t, %v", shares, err)
			}
		})
	}
}

func TestIntegrationBrowserURLSessionLoginRefreshAndLogoutStayOnInitialURL(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "browser-url-session")
	request := builtinRouteRequest(t, database, now)
	route := createTestPublicURL(t, database, request, now)
	auth := insertBrowserTestRun(t, database, testPublishRun{
		ID: "pr_url_browser", PublicURLID: route.ID, TeamID: route.TeamID, MembershipID: route.MembershipID, ActingIdentityID: request.ActingIdentityID,
		CertificateCacheKey: "url-browser", CertificateScope: "public-url", CertificateIdentifiers: []string{route.CanonicalHostname}, ChallengeMethod: "tls-alpn-01", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	preview, err := database.CreatePreview(t.Context(), route.TeamID, request.ActingIdentityID, "url-browser", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{PreviewID: preview.ID, PublicURLID: route.ID, TeamID: route.TeamID, IdentityID: request.ActingIdentityID, PolicyRevision: uint64(route.PolicyRevision), ExpectedMutationRevision: route.MutationRevision}, now); err != nil {
		t.Fatal(err)
	}
	otherID := cloneBrowserPublicURL(t, database, route.ID, "url_other_browser_session", "other-browser.example.test", now)
	if _, err := database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{PreviewID: preview.ID, PublicURLID: otherID, TeamID: route.TeamID, IdentityID: request.ActingIdentityID, PolicyRevision: uint64(route.PolicyRevision), ExpectedMutationRevision: 1}, now); err != nil {
		t.Fatal(err)
	}
	insertBrowserTestRun(t, database, testPublishRun{ID: "pr_other_url_browser", PublicURLID: otherID, TeamID: route.TeamID, MembershipID: route.MembershipID, ActingIdentityID: request.ActingIdentityID, CertificateCacheKey: "other-url-browser", CertificateScope: "public-url", CertificateIdentifiers: []string{"other-browser.example.test"}, ChallengeMethod: "tls-alpn-01", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	binding := bytes.Repeat([]byte{3}, 32)
	state, err := database.BeginBrowserLogin(t.Context(), "", route.ID, "/settings", "nonce-at-least-sixteen", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV", binding, now)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := database.ConsumeBrowserLogin(t.Context(), state, binding, now)
	if err != nil || attempt.PreviewID != "" {
		t.Fatalf("URL-only login scope = %q, %v", attempt.PreviewID, err)
	}
	handoff, err := database.IssueBrowserHandoff(t.Context(), attempt, BrowserAccessSession{IdentityID: request.ActingIdentityID, DisplayName: "Sam", AccessToken: "access", RefreshToken: "refresh", AccessExpiresAt: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour)}, now)
	if err != nil {
		t.Fatal(err)
	}
	cookie, _, next, _, _, err := database.RedeemBrowserHandoff(t.Context(), auth, handoff.Token, now)
	if err != nil || next != "https://"+route.CanonicalHostname+"/settings" {
		t.Fatalf("URL-only login fanned out: %q, %v", next, err)
	}
	if _, err := database.BrowserSession(t.Context(), otherID, cookie, now); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("URL session reached another URL in the same preview: %v", err)
	}
	refresh := func(_ context.Context, previous string) (BrowserTokenRotation, error) {
		if previous != "refresh" {
			t.Error("refresh used a different credential")
		}
		return BrowserTokenRotation{IdentityID: request.ActingIdentityID, AccessToken: "rotated-access", RefreshToken: "rotated-refresh", AccessExpiresAt: now.Add(time.Hour)}, nil
	}
	if _, err := database.RefreshBrowserSession(t.Context(), otherID, cookie, now.Add(time.Minute), func(context.Context, string) (BrowserTokenRotation, error) {
		t.Error("wrong URL reached authority refresh")
		return BrowserTokenRotation{}, nil
	}); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("wrong URL refreshed session: %v", err)
	}
	if err := database.RevokeBrowserSession(t.Context(), otherID, cookie, now); err != nil {
		t.Fatal(err)
	}
	if session, err := database.RefreshBrowserSession(t.Context(), route.ID, cookie, now.Add(time.Minute), refresh); err != nil || session.PreviewID != "" || session.AccessToken != "rotated-access" {
		t.Fatalf("URL-only refresh = %q, %v", session.AccessToken, err)
	}
	if err := database.RevokeBrowserSession(t.Context(), route.ID, cookie, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.BrowserSession(t.Context(), route.ID, cookie, now); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("URL-only logout did not revoke session: %v", err)
	}
}

func cloneBrowserPublicURL(t *testing.T, database *Database, initialID, id, hostname string, now time.Time) string {
	t.Helper()
	sealed, err := database.sealSecret(publicURLRequestDigestContext(id), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `INSERT INTO control.public_urls (
		id, team_id, domain_id, membership_id, created_by_identity_id, idempotency_key,
		request_digest_ciphertext, request_digest_storage_key_id, canonical_hostname,
		target, public_url_scope, purpose, policy_revision, ip_policy, lifecycle_state, dns_state, created_at, updated_at)
		SELECT $1, team_id, domain_id, membership_id, created_by_identity_id, $1, $2, $3,
		$4, target, public_url_scope, purpose, policy_revision, ip_policy, lifecycle_state, dns_state, $5, $5
		FROM control.public_urls WHERE id = $6`, id, sealed, database.storageKey.CurrentID(), hostname, now, initialID); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestIntegrationBrowserHandoffRechecksScopeCapabilityAndRun(t *testing.T) {
	for _, change := range []string{"share only", "expired", "closed", "wrong number", "wrong token", "wrong URL", "removed preview URL", "replaced run", "specialized purpose"} {
		t.Run(change, func(t *testing.T) {
			f := newPublishRunFixture(t)
			preview := browserFeedbackPreview(t, f)
			readyBrowserTestRun(t, f.database, f.authentication(), f.now)
			handoff, err := f.database.IssueBrowserHandoff(t.Context(), BrowserLoginAttempt{PreviewID: preview.ID, PublicURLID: f.setup.PublicURLID, ReturnPath: "/"}, BrowserAccessSession{IdentityID: f.request.ActingIdentityID, DisplayName: "Sam", AccessToken: "access", RefreshToken: "refresh", AccessExpiresAt: f.now.Add(time.Hour), ExpiresAt: f.now.Add(time.Hour)}, f.now)
			if err != nil {
				t.Fatal(err)
			}
			auth := f.authentication()
			var query string
			var args []any
			switch change {
			case "share only":
				query, args = `UPDATE control.publish_runs SET browser_capable = false, share_capable = true WHERE id = $1`, []any{auth.PublishRunID}
			case "expired":
				query, args = `UPDATE control.publish_runs SET publisher_expires_at = $2 WHERE id = $1`, []any{auth.PublishRunID, f.now.Add(10 * time.Second)}
			case "closed":
				query, args = `UPDATE control.publish_runs SET state = 'closed', closed_at = $2, close_reason = 'publisher_closed' WHERE id = $1`, []any{auth.PublishRunID, f.now}
			case "wrong number":
				auth.PublishRunNumber++
			case "wrong token":
				auth.PublishRunToken, _, _, _ = credentials.NewPublishRunToken()
			case "wrong URL":
				auth.PublicURLID = "url_wrong"
			case "removed preview URL":
				query, args = `DELETE FROM control.preview_public_urls WHERE preview_id = $1 AND public_url_id = $2`, []any{preview.ID, auth.PublicURLID}
			case "replaced run":
				if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.publish_runs SET publisher_expires_at = $2 WHERE id = $1`, auth.PublishRunID, f.now.Add(5*time.Second)); err != nil {
					t.Fatal(err)
				}
				request := f.request
				request.IdempotencyKey, request.ExpectedMutationRevision = "replacement-browser", 2
				replacement, err := f.database.CreatePublishRun(t.Context(), request, f.now.Add(10*time.Second), time.Hour, time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				auth = PublishRunAuthentication{PublishRunID: replacement.PublishRunID, PublicURLID: replacement.PublicURLID, PublishRunNumber: replacement.PublishRunNumber, PublishRunToken: replacement.PublishRunToken}
				readyBrowserTestRun(t, f.database, auth, f.now.Add(10*time.Second))
			case "specialized purpose":
				query, args = `UPDATE control.public_urls SET purpose = 'oauth' WHERE id = $1`, []any{auth.PublicURLID}
			}
			if query != "" {
				if _, err := f.database.pool.Exec(t.Context(), query, args...); err != nil {
					t.Fatal(err)
				}
			}
			// the ticket is still unexpired when a replacement run attempts to use it.
			want := ErrPreviewAccess
			switch change {
			case "expired", "closed", "wrong number":
				want = ErrPublishRunStale
			case "wrong token":
				want = ErrPublishRunCredential
			}
			if _, _, _, _, _, err := f.database.RedeemBrowserHandoff(t.Context(), auth, handoff.Token, f.now.Add(15*time.Second)); !errors.Is(err, want) {
				t.Fatalf("changed browser handoff = %v, want %v", err, want)
			}
		})
	}
}

func TestIntegrationBrowserPreviewSessionFollowsCurrentInclusion(t *testing.T) {
	f := newPublishRunFixture(t)
	preview := browserFeedbackPreview(t, f)
	otherID := cloneBrowserPublicURL(t, f.database, f.setup.PublicURLID, "url_browser_inclusion", "browser-inclusion.example.test", f.now)
	_, cookie, _ := newBrowserReviewer(t, f.database, preview.ID, f.setup.PublicURLID, f.request.ActingIdentityID, f.now)
	if _, err := f.database.BrowserSession(t.Context(), otherID, cookie, f.now); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("session reached URL outside preview: %v", err)
	}
	if _, err := f.database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{PreviewID: preview.ID, PublicURLID: otherID, TeamID: f.request.TeamID, IdentityID: f.request.ActingIdentityID, PolicyRevision: 1, ExpectedMutationRevision: 1}, f.now); err != nil {
		t.Fatal(err)
	}
	if access, err := f.database.BrowserAuthorization(t.Context(), otherID, cookie, f.now); err != nil || !access.VisitAllowed {
		t.Fatalf("session did not follow added URL: %+v, %v", access, err)
	}
	if session, err := f.database.RefreshBrowserSession(t.Context(), otherID, cookie, f.now, nil); err != nil || session.PreviewID != preview.ID {
		t.Fatalf("included URL could not use current session: %v", err)
	}
	if _, err := f.database.pool.Exec(t.Context(), `DELETE FROM control.preview_public_urls WHERE preview_id = $1 AND public_url_id = $2`, preview.ID, otherID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.BrowserSession(t.Context(), otherID, cookie, f.now); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("removed URL retained session scope: %v", err)
	}
	if _, err := f.database.BrowserAuthorization(t.Context(), otherID, cookie, f.now); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("removed URL retained owner admission: %v", err)
	}
	if _, err := f.database.RefreshBrowserSession(t.Context(), otherID, cookie, f.now, func(context.Context, string) (BrowserTokenRotation, error) {
		t.Error("removed URL reached authority refresh")
		return BrowserTokenRotation{}, nil
	}); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("removed URL retained refresh scope: %v", err)
	}
	if err := f.database.RevokeBrowserSession(t.Context(), otherID, cookie, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.BrowserSession(t.Context(), f.setup.PublicURLID, cookie, f.now); err != nil {
		t.Fatalf("removed URL revoked a session outside its scope: %v", err)
	}
}

func TestIntegrationBrowserHandoffFanoutRequiresReadyAppBrowserCapability(t *testing.T) {
	f := newPublishRunFixture(t)
	preview := browserFeedbackPreview(t, f)
	readyBrowserTestRun(t, f.database, f.authentication(), f.now)
	for _, excluded := range []string{"share-only", "starting", "expired", "alias", "demo", "oauth", "webhooks"} {
		id := cloneBrowserPublicURL(t, f.database, f.setup.PublicURLID, "url_browser_"+excluded, excluded+".example.test", f.now)
		if _, err := f.database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{PreviewID: preview.ID, PublicURLID: id, TeamID: f.request.TeamID, IdentityID: f.request.ActingIdentityID, PolicyRevision: 1, ExpectedMutationRevision: 1}, f.now); err != nil {
			t.Fatal(err)
		}
		createdAt := f.now
		if excluded == "expired" {
			createdAt = f.now.Add(-time.Minute)
		}
		auth := insertBrowserTestRun(t, f.database, testPublishRun{ID: "pr_browser_" + excluded, PublicURLID: id, TeamID: f.request.TeamID, MembershipID: f.request.MembershipID, ActingIdentityID: f.request.ActingIdentityID, CertificateCacheKey: excluded, CertificateScope: "public-url", CertificateIdentifiers: []string{excluded + ".example.test"}, ChallengeMethod: "tls-alpn-01", CreatedAt: createdAt, ExpiresAt: f.now.Add(time.Hour)})
		switch excluded {
		case "share-only":
			_, err := f.database.pool.Exec(t.Context(), `UPDATE control.publish_runs SET browser_capable = false, share_capable = true WHERE id = $1`, auth.PublishRunID)
			if err != nil {
				t.Fatal(err)
			}
		case "starting":
			_, err := f.database.pool.Exec(t.Context(), `UPDATE control.publish_runs SET state = 'starting', ready_at = NULL WHERE id = $1`, auth.PublishRunID)
			if err != nil {
				t.Fatal(err)
			}
		case "expired":
			_, err := f.database.pool.Exec(t.Context(), `UPDATE control.publish_runs SET publisher_expires_at = $2 WHERE id = $1`, auth.PublishRunID, f.now)
			if err != nil {
				t.Fatal(err)
			}
		default:
			_, err := f.database.pool.Exec(t.Context(), `UPDATE control.public_urls SET purpose = $2 WHERE id = $1`, id, excluded)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	handoff, err := f.database.IssueBrowserHandoff(t.Context(), BrowserLoginAttempt{PreviewID: preview.ID, PublicURLID: f.setup.PublicURLID, ReturnPath: "/settings"}, BrowserAccessSession{IdentityID: f.request.ActingIdentityID, DisplayName: "Sam", AccessToken: "access", RefreshToken: "refresh", AccessExpiresAt: f.now.Add(time.Hour), ExpiresAt: f.now.Add(time.Hour)}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	_, _, next, _, _, err := f.database.RedeemBrowserHandoff(t.Context(), f.authentication(), handoff.Token, f.now)
	if err != nil || strings.Contains(next, "/handoff/") {
		t.Fatalf("browser handoff included unsupported hostname: %q, %v", next, err)
	}
}

func TestIntegrationBrowserAuthorizationForRunRechecksAfterAuthorityIO(t *testing.T) {
	for _, change := range []string{"unchanged", "closed", "expired", "replaced", "capability removed", "not ready", "purpose changed"} {
		t.Run(change, func(t *testing.T) {
			f := newPublishRunFixture(t)
			auth := f.authentication()
			readyBrowserTestRun(t, f.database, auth, f.now)
			_, cookie, session := newBrowserReviewer(t, f.database, "", auth.PublicURLID, f.request.ActingIdentityID, f.now)
			if access, err := f.database.BrowserAuthorizationForRun(t.Context(), auth, cookie, f.now); err != nil || !access.VisitAllowed {
				t.Fatalf("live run browser authorization = %+v, %v", access, err)
			}
			if err := f.database.RequireBrowserAccess(t.Context(), auth, f.now); err != nil {
				t.Fatal(err)
			}
			// force authority refresh; the callback is the external I/O boundary.
			if err := f.database.RotateBrowserSession(t.Context(), cookie, session.AccessToken.String(), session.RefreshToken.String(), f.now.Add(15*time.Second)); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			entered, resume := make(chan struct{}), make(chan struct{})
			type authorizationResult struct {
				access BrowserAuthorization
				err    error
			}
			done := make(chan authorizationResult, 1)
			workers.Go(func() {
				_, err := f.database.RefreshBrowserSession(ctx, auth.PublicURLID, cookie, f.now, func(ctx context.Context, _ string) (BrowserTokenRotation, error) {
					close(entered)
					select {
					case <-resume:
						return BrowserTokenRotation{IdentityID: f.request.ActingIdentityID, AccessToken: session.AccessToken.String(), RefreshToken: session.RefreshToken.String(), AccessExpiresAt: session.AccessExpiresAt}, nil
					case <-ctx.Done():
						return BrowserTokenRotation{}, ctx.Err()
					}
				})
				if err != nil {
					done <- authorizationResult{err: err}
					return
				}
				access, err := f.database.BrowserAuthorizationForRun(ctx, auth, cookie, f.now.Add(3*time.Second))
				done <- authorizationResult{access, err}
			})
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("browser refresh did not reach authority I/O")
			}
			want := ErrPublishRunStale
			switch change {
			case "unchanged":
				want = nil
			case "closed", "replaced":
				if err := f.database.ClosePublishRun(ctx, auth.PublishRunID, auth.PublishRunToken, f.now.Add(time.Second)); err != nil {
					t.Fatalf("authority I/O held a run lock: %v", err)
				}
				if change == "replaced" {
					request := f.request
					request.IdempotencyKey, request.ExpectedMutationRevision = "browser-replacement", 2
					replacement, err := f.database.CreatePublishRun(ctx, request, f.now.Add(2*time.Second), time.Hour, time.Minute)
					if err != nil {
						t.Fatal(err)
					}
					replacementAuth := PublishRunAuthentication{PublishRunID: replacement.PublishRunID, PublicURLID: replacement.PublicURLID, PublishRunNumber: replacement.PublishRunNumber, PublishRunToken: replacement.PublishRunToken}
					readyBrowserTestRun(t, f.database, replacementAuth, f.now.Add(2*time.Second))
				}
			case "expired":
				if _, err := f.database.pool.Exec(ctx, `UPDATE control.publish_runs SET publisher_expires_at = $2 WHERE id = $1`, auth.PublishRunID, f.now.Add(2*time.Second)); err != nil {
					t.Fatal(err)
				}
			case "capability removed":
				want = ErrPreviewAccess
				if _, err := f.database.pool.Exec(ctx, `UPDATE control.publish_runs SET browser_capable = false WHERE id = $1`, auth.PublishRunID); err != nil {
					t.Fatal(err)
				}
			case "not ready":
				want = ErrPreviewAccess
				if _, err := f.database.pool.Exec(ctx, `UPDATE control.publish_runs SET state = 'starting', ready_at = NULL WHERE id = $1`, auth.PublishRunID); err != nil {
					t.Fatal(err)
				}
			case "purpose changed":
				want = ErrPreviewAccess
				if _, err := f.database.pool.Exec(ctx, `UPDATE control.public_urls SET purpose = 'alias' WHERE id = $1`, auth.PublicURLID); err != nil {
					t.Fatal(err)
				}
			}
			close(resume)
			result := awaitIntegrationResult(t, ctx, done)
			if !errors.Is(result.err, want) || (change == "unchanged") != result.access.VisitAllowed {
				t.Fatalf("browser authorization after %s = %+v, %v, want %v", change, result.access, result.err, want)
			}
		})
	}
}

func TestIntegrationBrowserAuthorizationForRunHoldsRunThroughIdentityCheck(t *testing.T) {
	f := newPublishRunFixture(t)
	auth := f.authentication()
	readyBrowserTestRun(t, f.database, auth, f.now)
	_, cookie, _ := newBrowserReviewer(t, f.database, "", auth.PublicURLID, f.request.ActingIdentityID, f.now)
	digest, _ := browserDigest(cookie)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	gate, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := controlstatedb.New(gate).LockBrowserAccessSession(ctx, digest); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	done := make(chan error, 1)
	workers.Go(func() {
		access, err := f.database.BrowserAuthorizationForRun(ctx, auth, cookie, f.now)
		if err == nil && !access.VisitAllowed {
			err = ErrPreviewAccess
		}
		done <- err
	})
	waitForPostgresBlock(t, ctx, f.database, int32(gate.Conn().PgConn().PID()), done)
	mutation, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, mutation)
	if _, err := mutation.Exec(ctx, `SET LOCAL lock_timeout = '200ms'`); err != nil {
		t.Fatal(err)
	}
	_, err = controlstatedb.New(mutation).LockPublishRun(ctx, auth.PublishRunID)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Fatalf("run mutation crossed in-progress identity validation: %v", err)
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, done); err != nil {
		t.Fatal(err)
	}
}
