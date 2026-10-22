package controlstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

func TestIntegrationBrowserLoginHandoffAndRevocation(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "browser-access")
	request := oidcRouteRequest(t, database, now)
	route := createTestPublicURL(t, database, request, now)
	auth := browserTestAuthentication(t, database, route.ID, now)
	preview, err := database.CreatePreview(t.Context(), route.TeamID, request.ActingIdentityID, "browser-access", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{
		PreviewID: preview.ID, PublicURLID: route.ID, TeamID: route.TeamID,
		IdentityID: request.ActingIdentityID, PolicyRevision: uint64(route.PolicyRevision),
		ExpectedMutationRevision: route.MutationRevision,
	}, now); err != nil {
		t.Fatal(err)
	}
	binding := bytes.Repeat([]byte{7}, 32)
	state, err := database.BeginBrowserLogin(t.Context(), preview.ID, route.ID, "/settings?tab=profile", "nonce-at-least-sixteen", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV", binding, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ConsumeBrowserLogin(t.Context(), state, bytes.Repeat([]byte{8}, 32), now); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("another browser consumed login state: %v", err)
	}
	login, err := database.ConsumeBrowserLogin(t.Context(), state, binding, now)
	if err != nil || login.PreviewID != preview.ID || login.PublicURLID != route.ID || login.ReturnPath != "/settings?tab=profile" {
		t.Fatalf("browser login = %+v, %v", login, err)
	}
	if _, err := database.ConsumeBrowserLogin(t.Context(), state, binding, now); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("replayed login = %v", err)
	}
	issued := browserTestControlSession(t, database, request.ActingIdentityID, now)
	access := issued.AccessToken.String()
	refresh := issued.RefreshToken.String()
	handoff, err := database.IssueBrowserHandoff(t.Context(), login, BrowserAccessSession{
		IdentityID: request.ActingIdentityID, DisplayName: "Example User", AccessToken: access,
		RefreshToken: refresh, AccessExpiresAt: now.Add(time.Hour), ExpiresAt: now.Add(24 * time.Hour),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	var accessCiphertext, refreshCiphertext []byte
	if err := database.pool.QueryRow(t.Context(), `SELECT access_ciphertext, refresh_ciphertext FROM control.browser_access_sessions WHERE identity_id = $1`, request.ActingIdentityID).Scan(&accessCiphertext, &refreshCiphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(accessCiphertext, []byte(access)) || bytes.Contains(refreshCiphertext, []byte(refresh)) {
		t.Fatal("browser tokens were stored in plaintext")
	}
	wrong := auth
	wrong.PublicURLID = "url_different"
	if _, _, _, _, _, err := database.RedeemBrowserHandoff(t.Context(), wrong, handoff.Token, now); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("different URL redeemed browser handoff: %v", err)
	}
	cookie, path, _, _, _, err := database.RedeemBrowserHandoff(t.Context(), auth, handoff.Token, now)
	if err != nil || cookie == "" || path != login.ReturnPath {
		t.Fatalf("browser handoff = %q, %q, %v", cookie, path, err)
	}
	if _, _, _, _, _, err := database.RedeemBrowserHandoff(t.Context(), auth, handoff.Token, now); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("replayed browser handoff = %v", err)
	}
	session, err := database.BrowserSession(t.Context(), route.ID, cookie, now)
	if err != nil || session.IdentityID != request.ActingIdentityID || session.AccessToken != access || session.RefreshToken != refresh {
		t.Fatalf("browser session identity = %q, %v", session.IdentityID, err)
	}
	if err := database.RotateBrowserSession(t.Context(), cookie, "new-access", "new-refresh", now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	session, err = database.BrowserSession(t.Context(), route.ID, cookie, now)
	if err != nil || session.AccessToken != "new-access" || session.RefreshToken != "new-refresh" {
		t.Fatalf("browser token rotation failed: %v", err)
	}
	var rotations atomic.Int32
	results := make(chan error, 2)
	for range 2 {
		go func() {
			updated, err := database.RefreshBrowserSession(t.Context(), route.ID, cookie, now.Add(2*time.Hour-15*time.Second),
				func(_ context.Context, previous string) (BrowserTokenRotation, error) {
					if previous != "new-refresh" {
						return BrowserTokenRotation{}, ErrPreviewAccess
					}
					rotations.Add(1)
					return BrowserTokenRotation{
						IdentityID: request.ActingIdentityID, AccessToken: "latest-access", RefreshToken: "latest-refresh",
						AccessExpiresAt: now.Add(3 * time.Hour),
					}, nil
				})
			if err == nil && updated.AccessToken != "latest-access" {
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
	if err := database.RevokeBrowserSession(t.Context(), route.ID, cookie, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.BrowserSession(t.Context(), route.ID, cookie, now); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("revoked browser session = %v", err)
	}
}

func TestIntegrationNonmemberWithAnonymousAccessPostsVerifiedFeedback(t *testing.T) {
	f := newPublishRunFixture(t)
	database, now := f.database, f.now
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.publish_runs SET state='ready',ready_at=$2 WHERE id=$1`, f.setup.PublishRunID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.public_urls SET access_mode='anonymous' WHERE id=$1`, f.setup.PublicURLID); err != nil {
		t.Fatal(err)
	}
	preview, err := database.CreatePreview(t.Context(), f.request.TeamID, f.request.ActingIdentityID, "browser-feedback", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{
		PreviewID: preview.ID, PublicURLID: f.setup.PublicURLID, TeamID: f.request.TeamID,
		IdentityID: f.request.ActingIdentityID, PolicyRevision: 1, ExpectedMutationRevision: 2,
	}, now); err != nil {
		t.Fatal(err)
	}
	identityID := "00000000-0000-4000-8000-000000000002"
	insertAuthorityIdentity(t, database, identityID, "", false, now)
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.identities SET display_name='Sam' WHERE id=$1`, identityID); err != nil {
		t.Fatal(err)
	}
	issued := browserTestControlSession(t, database, identityID, now)
	handoff, err := database.IssueBrowserHandoff(t.Context(), BrowserLoginAttempt{
		PreviewID: preview.ID, PublicURLID: f.setup.PublicURLID, ReturnPath: "/",
	}, BrowserAccessSession{
		IdentityID: identityID, DisplayName: "Sam", AccessToken: issued.AccessToken.String(), RefreshToken: issued.RefreshToken.String(),
		AccessExpiresAt: now.Add(time.Hour), ExpiresAt: now.Add(time.Hour),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	cookie, _, _, _, _, err := database.RedeemBrowserHandoff(t.Context(), f.authentication(), handoff.Token, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(cookie)
	if err != nil {
		t.Fatal(err)
	}
	auth := f.authentication()
	actor := FeedbackActor{Kind: "reviewer", SourceIP: "192.0.2.9", PublishRunAuthentication: &auth, VisitAllowed: true, IdentityID: identityID, DisplayName: "Sam", BrowserCookieSecret: raw}
	thread, err := database.CreateFeedback(t.Context(), f.authentication(), CreateFeedbackRequest{
		PreviewID: preview.ID, Service: "web", PagePath: "/", ReportText: "The label is unclear",
		AuthorDisplayName: "not sam", Anchor: json.RawMessage(`null`),
		Evidence:       json.RawMessage(`{"schema_version":1,"actions":[],"failed_requests":[]}`),
		SourceAtReport: feedbackTestSource(t), IdempotencyKey: "signed-report", Actor: actor,
	}, now)
	if err != nil || thread.AuthorDisplayName != "Sam" || thread.AuthorIdentityID != identityID || !thread.AuthorVerified {
		t.Fatalf("verified report identity = %q, %q, %t, %v", thread.AuthorDisplayName, thread.AuthorIdentityID, thread.AuthorVerified, err)
	}
	reply, err := database.AppendFeedback(t.Context(), AppendFeedbackRequest{
		FeedbackID: thread.ID, Type: FeedbackReply, Text: "One more detail", IdempotencyKey: "signed-reply", Actor: actor,
	}, now)
	if err != nil || reply.AuthorIdentityID != identityID || reply.AuthorDisplayName != "Sam" || !reply.AuthorVerified {
		t.Fatalf("verified reply identity = %q, %q, %t, %v", reply.AuthorIdentityID, reply.AuthorDisplayName, reply.AuthorVerified, err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.public_urls SET access_mode='restricted' WHERE id=$1`, f.setup.PublicURLID); err != nil {
		t.Fatal(err)
	}
	actor.VisitAllowed = false
	shareSecret := []byte("0123456789abcdefghijklmnopqrstuv")
	share, err := database.CreateShare(t.Context(), CreateShareRequest{
		PreviewID: preview.ID, TeamID: f.request.TeamID, ActingIdentityID: f.request.ActingIdentityID,
		IdempotencyKey: "nonmember-share", SecretFingerprint: sha256.Sum256(shareSecret), ExpiresAt: now.Add(time.Hour),
		PolicyRevision: 1, PublicURLs: []AuthorizedSharePublicURL{{PublicURLID: f.setup.PublicURLID, ExpectedMutationRevision: 2}},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	shareCookie := []byte("abcdefghijklmnopqrstuvwxyz012345")
	digest := sha256.Sum256(shareCookie)
	if _, err := controlstatedb.New(database.pool).InsertShareCookie(t.Context(), controlstatedb.InsertShareCookieParams{
		TokenDigest: digest[:], PublicURLID: f.setup.PublicURLID, CreatedAt: timestamptz(now), ShareID: share.ID,
	}); err != nil {
		t.Fatal(err)
	}
	actor.ShareID, actor.CookieSecret = share.ID, shareCookie
	sharedReport, err := database.CreateFeedback(t.Context(), f.authentication(), CreateFeedbackRequest{
		PreviewID: preview.ID, Service: "web", PagePath: "/", ReportText: "Suggestion through a share",
		Anchor: json.RawMessage(`null`), Evidence: json.RawMessage(`{"schema_version":1,"actions":[],"failed_requests":[]}`),
		SourceAtReport: feedbackTestSource(t), IdempotencyKey: "signed-link-report", Actor: actor,
	}, now)
	if err != nil || !sharedReport.AuthorVerified || sharedReport.AuthorIdentityID != identityID {
		t.Fatalf("signed-in nonmember with link = %q, %t, %v", sharedReport.AuthorIdentityID, sharedReport.AuthorVerified, err)
	}
	actor.ShareID, actor.CookieSecret = "", nil
	actor.TeamMember = true
	if _, _, err := database.ReviewerFeedbackScope(t.Context(), f.authentication(), preview.ID, actor, now); !errors.Is(err, ErrFeedbackAccess) {
		t.Fatalf("nonmember used team access without a team grant: %v", err)
	}
}

func TestIntegrationBrowserLoginInstallsAccessOnReadyPreviewHostnames(t *testing.T) {
	f := newPublishRunFixture(t)
	database, now := f.database, f.now
	auth := browserTestAuthentication(t, database, f.setup.PublicURLID, now)
	issued := browserTestControlSession(t, database, f.request.ActingIdentityID, now)
	preview, err := database.CreatePreview(t.Context(), f.request.TeamID, f.request.ActingIdentityID, "browser-multi-host", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{
		PreviewID: preview.ID, PublicURLID: f.setup.PublicURLID, TeamID: f.request.TeamID,
		IdentityID: f.request.ActingIdentityID, PolicyRevision: 1, ExpectedMutationRevision: 2,
	}, now); err != nil {
		t.Fatal(err)
	}
	const otherID = "public_url_browser_api"
	sealed, err := database.sealSecret(publicURLRequestDigestContext(otherID), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `INSERT INTO control.public_urls (
		id, team_id, domain_id, created_by_identity_id, idempotency_key,
		request_digest_ciphertext, request_digest_storage_key_id, canonical_hostname,
		target, public_url_scope, purpose, policy_revision, ip_policy, lifecycle_state, dns_state, created_at, updated_at)
		SELECT $1, team_id, domain_id, created_by_identity_id, 'browser-api', $2, $3,
		'api-session.example.test', target, public_url_scope, purpose, policy_revision, ip_policy, lifecycle_state, dns_state, $4, $4
		FROM control.public_urls WHERE id = $5`, otherID, sealed, database.storageKey.CurrentID(), now, f.setup.PublicURLID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{
		PreviewID: preview.ID, PublicURLID: otherID, TeamID: f.request.TeamID,
		IdentityID: f.request.ActingIdentityID, PolicyRevision: 1, ExpectedMutationRevision: 1,
	}, now); err != nil {
		t.Fatal(err)
	}
	insertTestPublishRun(t, database, testPublishRun{
		ID: "pr_browser_api", PublicURLID: otherID, TeamID: f.request.TeamID,
		MembershipID: f.request.MembershipID, ActingIdentityID: f.request.ActingIdentityID,
		CertificateCacheKey: "certificate_session", CertificateScope: "public-url",
		CertificateIdentifiers: []string{"api-session.example.test"}, ChallengeMethod: "dns-01",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.publish_runs SET state = 'ready', ready_at = $2,
		share_capable = true WHERE id = $1`, "pr_browser_api", now); err != nil {
		t.Fatal(err)
	}
	handoff, err := database.IssueBrowserHandoff(t.Context(), BrowserLoginAttempt{
		PreviewID: preview.ID, PublicURLID: f.setup.PublicURLID, ReturnPath: "/settings",
	}, BrowserAccessSession{
		IdentityID: f.request.ActingIdentityID, DisplayName: "Sam", AccessToken: issued.AccessToken.String(), RefreshToken: issued.RefreshToken.String(),
		AccessExpiresAt: now.Add(time.Hour), ExpiresAt: now.Add(time.Hour),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	cookie, path, next, _, _, err := database.RedeemBrowserHandoff(t.Context(), auth, handoff.Token, now)
	if err != nil || path != "/settings" || !strings.HasPrefix(next, "https://api-session.example.test/__tnl/team/handoff/") {
		t.Fatalf("first host returned %q, %q, %v", path, next, err)
	}
	otherTicket := strings.TrimPrefix(next, "https://api-session.example.test/__tnl/team/handoff/")
	otherCookie, _, finish, _, _, err := database.RedeemBrowserHandoff(t.Context(), browserTestAuthentication(t, database, otherID, now), otherTicket, now)
	if err != nil || otherCookie != cookie || finish != "https://route-session.example.test/settings" {
		t.Fatalf("other host handoff = %t, %q, %v", otherCookie == cookie, finish, err)
	}
	if _, err := database.BrowserSession(t.Context(), otherID, cookie, now); err != nil {
		t.Fatalf("other host browser session: %v", err)
	}
	if err := database.RevokeBrowserSession(t.Context(), otherID, cookie, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.BrowserSession(t.Context(), f.setup.PublicURLID, cookie, now); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("other hostname's logout left session usable: %v", err)
	}
}

func browserTestAuthentication(t *testing.T, d *Database, urlID string, now time.Time) PublishRunAuthentication {
	t.Helper()
	q := controlstatedb.New(d.pool)
	run, err := q.GetOpenPublishRun(t.Context(), urlID)
	if errors.Is(err, pgx.ErrNoRows) {
		url, loadErr := q.GetFeedbackPublicURL(t.Context(), urlID)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		insertTestPublishRun(t, d, testPublishRun{ID: "pr_browser_" + urlID, PublicURLID: urlID, TeamID: url.TeamID, MembershipID: url.MembershipID.String, ActingIdentityID: url.CreatedByIdentityID, CertificateCacheKey: "browser", CertificateScope: "public-url", CertificateIdentifiers: []string{url.CanonicalHostname}, ChallengeMethod: "dns-01", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
		run, err = q.GetOpenPublishRun(t.Context(), urlID)
	}
	if err != nil {
		t.Fatal(err)
	}
	token, id, digest, err := credentials.NewPublishRunToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.publish_runs SET state='ready',ready_at=$2,publish_run_token_id=$3,publish_run_token_digest=$4 WHERE id=$1`, run.ID, now, id.String(), digest[:]); err != nil {
		t.Fatal(err)
	}
	return PublishRunAuthentication{PublishRunID: run.ID, PublicURLID: urlID, PublishRunNumber: uint64(run.PublishRunNumber), PublishRunToken: token}
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
			d, now := newControlStateIntegrationDatabase(t, "alias-browser-"+name)
			request := oidcRouteRequest(t, d, now)
			url := createTestPublicURL(t, d, request, now)
			if _, err := d.pool.Exec(t.Context(), `UPDATE control.public_urls SET purpose='alias' WHERE id=$1`, url.ID); err != nil {
				t.Fatal(err)
			}
			auth := browserTestAuthentication(t, d, url.ID, now)
			session := browserTestControlSession(t, d, request.ActingIdentityID, now)
			var handoff BrowserHandoff
			var err error
			if native {
				handoff, _, err = d.IssueControlBrowserHandoff(t.Context(), session.AccessToken, session.RefreshToken, auth.PublicURLID, time.Hour, 24*time.Hour, now)
			} else {
				binding := bytes.Repeat([]byte{7}, 32)
				state, beginErr := d.BeginBrowserLogin(t.Context(), "", auth.PublicURLID, "/owner", "nonce-at-least-sixteen", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV", binding, nil, now)
				if beginErr != nil {
					t.Fatal(beginErr)
				}
				attempt, consumeErr := d.ConsumeBrowserLogin(t.Context(), state, binding, now)
				if consumeErr != nil || attempt.PublishRunID != auth.PublishRunID {
					t.Fatalf("alias login lost its original run: %+v, %v", attempt, consumeErr)
				}
				handoff, err = d.IssueBrowserHandoff(t.Context(), attempt, BrowserAccessSession{IdentityID: request.ActingIdentityID, DisplayName: "Owner", AccessToken: session.AccessToken.String(), RefreshToken: session.RefreshToken.String(), AccessExpiresAt: session.AccessExpiresAt, ExpiresAt: session.RefreshExpiresAt}, now)
			}
			if err != nil {
				t.Fatalf("alias owner handoff issuance: %v", err)
			}
			wrong := auth
			wrong.PublishRunID = "pr_replacement"
			if _, _, _, _, _, err := d.RedeemBrowserHandoff(t.Context(), wrong, handoff.Token, now); err == nil {
				t.Fatal("replacement run redeemed the alias handoff")
			}
			cookie, _, _, _, _, err := d.RedeemBrowserHandoff(t.Context(), auth, handoff.Token, now)
			if err != nil {
				t.Fatalf("alias owner handoff redemption: %v", err)
			}
			if got, err := d.BrowserSession(t.Context(), auth.PublicURLID, cookie, now); err != nil || got.IdentityID != request.ActingIdentityID {
				t.Fatalf("alias owner session: %+v, %v", got, err)
			}
			if _, _, _, _, _, err := d.RedeemBrowserHandoff(t.Context(), auth, handoff.Token, now); !errors.Is(err, ErrPreviewAccess) {
				t.Fatalf("alias handoff replay: %v", err)
			}
		})
	}
}
