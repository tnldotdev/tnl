package state

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
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func TestIntegrationBrowserLoginHandoffAndRevocation(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "browser-access")
	request := oidcRouteRequest(t, database, now)
	publicURL := createTestPublicURL(t, database, request, now)
	auth := browserTestAuthentication(t, database, publicURL.ID, now)
	prepareVisitorTokenKeys(t, database, now)
	preview, err := database.CreatePreview(t.Context(), publicURL.TeamID, request.ActingIdentityID, "browser-access", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{
		PreviewID: preview.ID, PublicURLID: publicURL.ID, TeamID: publicURL.TeamID,
		IdentityID: request.ActingIdentityID, PolicyRevision: uint64(publicURL.PolicyRevision),
		ExpectedMutationRevision: publicURL.MutationRevision,
	}, now); err != nil {
		t.Fatal(err)
	}
	binding := bytes.Repeat([]byte{7}, 32)
	state, err := database.BeginBrowserLogin(t.Context(), preview.ID, publicURL.ID, "/settings?tab=profile", "nonce-at-least-sixteen", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV", binding, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ConsumeBrowserLogin(t.Context(), state, bytes.Repeat([]byte{8}, 32), now); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("another browser consumed login state: %v", err)
	}
	login, err := database.ConsumeBrowserLogin(t.Context(), state, binding, now)
	if err != nil || login.PreviewID != preview.ID || login.PublicURLID != publicURL.ID || login.ReturnPath != "/settings?tab=profile" {
		t.Fatalf("browser login = %+v, %v", login, err)
	}
	if _, err := database.ConsumeBrowserLogin(t.Context(), state, binding, now); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("replayed login = %v", err)
	}
	expired, err := database.BeginBrowserLogin(t.Context(), preview.ID, publicURL.ID, "/expired", "nonce-at-least-sixteen", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV", binding, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ConsumeBrowserLogin(t.Context(), expired, binding, now.Add(5*time.Minute)); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("expired login state was consumed: %v", err)
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
	if _, err := database.RedeemBrowserHandoffWithPermission(t.Context(), wrong, testVisitorIssuer, handoff.Token, "", "", now); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("different URL redeemed browser handoff: %v", err)
	}
	redemption, err := database.RedeemBrowserHandoffWithPermission(t.Context(), auth, testVisitorIssuer, handoff.Token, "", "", now)
	if err != nil || redemption.CookieSecret == "" || redemption.ReturnPath != login.ReturnPath {
		t.Fatalf("browser handoff = %q, %q, %v", redemption.CookieSecret, redemption.ReturnPath, err)
	}
	if _, err := database.RedeemBrowserHandoffWithPermission(t.Context(), auth, testVisitorIssuer, handoff.Token, "", "", now); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("replayed browser handoff = %v", err)
	}
	cookie := redemption.CookieSecret
	session, err := database.BrowserSession(t.Context(), publicURL.ID, cookie, now)
	if err != nil || session.IdentityID != request.ActingIdentityID || session.AccessToken != access || session.RefreshToken != refresh {
		t.Fatalf("browser session identity = %q, %v", session.IdentityID, err)
	}
	if err := database.RotateBrowserSession(t.Context(), cookie, "new-access", "new-refresh", now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	session, err = database.BrowserSession(t.Context(), publicURL.ID, cookie, now)
	if err != nil || session.AccessToken != "new-access" || session.RefreshToken != "new-refresh" {
		t.Fatalf("browser token rotation failed: %v", err)
	}
	var rotations atomic.Int32
	results := make(chan error, 2)
	for range 2 {
		go func() {
			updated, err := database.RefreshBrowserSession(t.Context(), publicURL.ID, cookie, now.Add(2*time.Hour-15*time.Second),
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
	if err := database.RevokeBrowserSession(t.Context(), publicURL.ID, cookie, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.BrowserSession(t.Context(), publicURL.ID, cookie, now); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("revoked browser session = %v", err)
	}
}

func TestIntegrationBrowserHandoffPermissionCommitsWithTicket(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "browser-handoff-permission")
	request := oidcRouteRequest(t, d, now)
	u := createTestPublicURL(t, d, request, now)
	auth := browserTestAuthentication(t, d, u.ID, now)
	issued := browserTestControlSession(t, d, request.ActingIdentityID, now)
	handoff, err := d.IssueBrowserHandoff(t.Context(), BrowserLoginAttempt{PublicURLID: u.ID, ReturnPath: "/settings"}, BrowserAccessSession{
		IdentityID: request.ActingIdentityID, DisplayName: "Owner", AccessToken: issued.AccessToken.String(), RefreshToken: issued.RefreshToken.String(),
		AccessExpiresAt: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	wrongRun := auth
	wrongRun.PublishRunID = "pr_replacement"
	if _, err := d.RedeemBrowserHandoffWithPermission(t.Context(), wrongRun, testVisitorIssuer, handoff.Token, "", "", now); err == nil {
		t.Fatal("wrong run redeemed ticket")
	}
	wrongToken := auth
	wrongToken.PublishRunToken = "wrong-secret"
	if _, err := d.RedeemBrowserHandoffWithPermission(t.Context(), wrongToken, testVisitorIssuer, handoff.Token, "", "", now); err == nil {
		t.Fatal("wrong run credential redeemed ticket")
	}
	otherSecret, _, err := randomBrowserSecret()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.RedeemBrowserHandoffWithPermission(t.Context(), auth, testVisitorIssuer, otherSecret, "", "", now); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("wrong secret redeemed ticket: %v", err)
	}
	if _, err := d.RedeemBrowserHandoffWithPermission(t.Context(), auth, "https://other.example.test", handoff.Token, "", "", now); !errors.Is(err, ErrVisitorSigningKey) {
		t.Fatalf("post-redemption signing failure: %v", err)
	}
	if _, err := d.RedeemBrowserHandoffWithPermission(t.Context(), auth, "", handoff.Token, "", "", now); !errors.Is(err, ErrVisitorSigningKey) {
		t.Fatalf("empty issuer consumed the ticket without signing: %v", err)
	}
	digest, err := browserDigest(handoff.Token)
	if err != nil {
		t.Fatal(err)
	}
	var consumed bool
	if err := d.pool.QueryRow(t.Context(), `SELECT consumed_at IS NOT NULL FROM control.browser_access_handoffs WHERE token_digest=$1`, digest).Scan(&consumed); err != nil || consumed {
		t.Fatalf("failed token issuance consumed ticket: %t, %v", consumed, err)
	}
	result, err := d.RedeemBrowserHandoffWithPermission(t.Context(), auth, testVisitorIssuer, handoff.Token, "", "", now)
	if err != nil || result.CookieSecret == "" || result.ReturnPath != "/settings" || result.ExpiresAt.Sub(now) != 2*time.Hour {
		t.Fatalf("prepared browser handoff = %+v, %v", result, err)
	}
	permission := result.Issued.Permission
	if permission.Scope != (visitorscope.Scope{Kind: visitorscope.PublicURL, ID: u.ID}) || !permission.ExpiresAt.Before(result.ExpiresAt) {
		t.Fatalf("signed permission widened scope or lifetime: %+v", permission)
	}
	if _, err := visitortoken.VerifyBearer(result.Issued.Token, stateTestVisitorView(permission, stateTestVisitorKeys(t, d, now), now), now); err != nil {
		t.Fatalf("prepared permission did not verify locally: %v", err)
	}
	var retainUntil time.Time
	if err := d.pool.QueryRow(t.Context(), `SELECT retain_until FROM control.visitor_token_keys WHERE retired_at IS NULL`).Scan(&retainUntil); err != nil || retainUntil.Before(permission.ExpiresAt) {
		t.Fatalf("signing key not retained through visitor permission: %s, %v", retainUntil, err)
	}
	if _, err := d.BrowserSession(t.Context(), u.ID, result.CookieSecret, now); err != nil {
		t.Fatalf("redeemed cookie was not installed: %v", err)
	}
	if _, err := d.RedeemBrowserHandoffWithPermission(t.Context(), auth, testVisitorIssuer, handoff.Token, "", "", now); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("ticket replay: %v", err)
	}
	later, err := d.IssueBrowserHandoff(t.Context(), BrowserLoginAttempt{PublicURLID: u.ID, ReturnPath: "/later"}, BrowserAccessSession{
		IdentityID: request.ActingIdentityID, DisplayName: "Owner", AccessToken: issued.AccessToken.String(), RefreshToken: issued.RefreshToken.String(),
		AccessExpiresAt: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.RedeemBrowserHandoffWithPermission(t.Context(), auth, testVisitorIssuer, later.Token, "", "", now.Add(time.Minute)); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("ticket remained redeemable at expiry: %v", err)
	}
}

func TestIntegrationNonmemberWithAnonymousAccessPostsVerifiedFeedback(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "browser-feedback")
	request := oidcRouteRequest(t, database, now)
	publicURL := createTestPublicURL(t, database, request, now)
	auth := browserTestAuthentication(t, database, publicURL.ID, now)
	prepareVisitorTokenKeys(t, database, now)
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.public_urls SET access_mode='anonymous' WHERE id=$1`, publicURL.ID); err != nil {
		t.Fatal(err)
	}
	preview, err := database.CreatePreview(t.Context(), publicURL.TeamID, request.ActingIdentityID, "browser-feedback", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{
		PreviewID: preview.ID, PublicURLID: publicURL.ID, TeamID: publicURL.TeamID,
		IdentityID: request.ActingIdentityID, PolicyRevision: uint64(publicURL.PolicyRevision), ExpectedMutationRevision: publicURL.MutationRevision,
	}, now); err != nil {
		t.Fatal(err)
	}
	identityID, err := opaqueid.New(opaqueid.IdentityPrefix)
	if err != nil {
		t.Fatal(err)
	}
	insertAuthorityIdentity(t, database, identityID, "", false, now)
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.identities SET display_name='Sam' WHERE id=$1`, identityID); err != nil {
		t.Fatal(err)
	}
	issued := browserTestControlSession(t, database, identityID, now)
	handoff, err := database.IssueBrowserHandoff(t.Context(), BrowserLoginAttempt{
		PreviewID: preview.ID, PublicURLID: publicURL.ID, ReturnPath: "/",
	}, BrowserAccessSession{
		IdentityID: identityID, DisplayName: "Sam", AccessToken: issued.AccessToken.String(), RefreshToken: issued.RefreshToken.String(),
		AccessExpiresAt: now.Add(time.Hour), ExpiresAt: now.Add(time.Hour),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	redemption, err := database.RedeemBrowserHandoffWithPermission(t.Context(), auth, testVisitorIssuer, handoff.Token, "", "", now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(redemption.CookieSecret)
	if err != nil {
		t.Fatal(err)
	}
	actor := FeedbackActor{Kind: "reviewer", SourceIP: "192.0.2.9", PublishRunAuthentication: &auth, VisitAllowed: true, IdentityID: identityID, DisplayName: "Sam", BrowserCookieSecret: raw}
	thread, err := database.CreateFeedback(t.Context(), auth, CreateFeedbackRequest{
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
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.public_urls SET access_mode='restricted' WHERE id=$1`, publicURL.ID); err != nil {
		t.Fatal(err)
	}
	actor.VisitAllowed = false
	shareSecret := []byte("0123456789abcdefghijklmnopqrstuv")
	share, err := database.CreateShare(t.Context(), CreateShareRequest{
		PreviewID: preview.ID, TeamID: publicURL.TeamID, ActingIdentityID: request.ActingIdentityID,
		IdempotencyKey: "nonmember-share", SecretFingerprint: sha256.Sum256(shareSecret), ExpiresAt: now.Add(time.Hour),
		PolicyRevision: uint64(publicURL.PolicyRevision), PublicURLs: []AuthorizedSharePublicURL{{PublicURLID: publicURL.ID, ExpectedMutationRevision: publicURL.MutationRevision}},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	shareCookie := []byte("abcdefghijklmnopqrstuvwxyz012345")
	digest := sha256.Sum256(shareCookie)
	if _, err := controlstatedb.New(database.pool).InsertShareCookie(t.Context(), controlstatedb.InsertShareCookieParams{
		TokenDigest: digest[:], PublicURLID: publicURL.ID, CreatedAt: timestamptz(now), ShareID: share.ID,
	}); err != nil {
		t.Fatal(err)
	}
	actor.ShareID, actor.CookieSecret = share.ID, shareCookie
	sharedReport, err := database.CreateFeedback(t.Context(), auth, CreateFeedbackRequest{
		PreviewID: preview.ID, Service: "web", PagePath: "/", ReportText: "Suggestion through a share",
		Anchor: json.RawMessage(`null`), Evidence: json.RawMessage(`{"schema_version":1,"actions":[],"failed_requests":[]}`),
		SourceAtReport: feedbackTestSource(t), IdempotencyKey: "signed-link-report", Actor: actor,
	}, now)
	if err != nil || !sharedReport.AuthorVerified || sharedReport.AuthorIdentityID != identityID {
		t.Fatalf("signed-in nonmember with link = %q, %t, %v", sharedReport.AuthorIdentityID, sharedReport.AuthorVerified, err)
	}
	actor.ShareID, actor.CookieSecret = "", nil
	actor.TeamMember = true
	if _, _, err := database.ReviewerFeedbackScope(t.Context(), auth, preview.ID, actor, now); !errors.Is(err, ErrFeedbackAccess) {
		t.Fatalf("nonmember used team access without a team grant: %v", err)
	}
}

func TestIntegrationBrowserLoginInstallsAccessOnReadyPreviewHostnames(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "browser-multi-host")
	request := oidcRouteRequest(t, database, now)
	publicURL := createTestPublicURL(t, database, request, now)
	auth := browserTestAuthentication(t, database, publicURL.ID, now)
	issued := browserTestControlSession(t, database, request.ActingIdentityID, now)
	prepareVisitorTokenKeys(t, database, now)
	preview, err := database.CreatePreview(t.Context(), publicURL.TeamID, request.ActingIdentityID, "browser-multi-host", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{
		PreviewID: preview.ID, PublicURLID: publicURL.ID, TeamID: publicURL.TeamID,
		IdentityID: request.ActingIdentityID, PolicyRevision: uint64(publicURL.PolicyRevision), ExpectedMutationRevision: publicURL.MutationRevision,
	}, now); err != nil {
		t.Fatal(err)
	}
	otherID, err := opaqueid.New(opaqueid.PublicURLPrefix)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := database.sealSecret(publicURLRequestDigestContext(otherID), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `INSERT INTO control.public_urls (
		id, team_id, domain_id, created_by_identity_id, idempotency_key,
		request_digest_ciphertext, request_digest_storage_key_id, canonical_hostname,
		target, public_url_scope, membership_id, purpose, policy_revision, ip_policy, lifecycle_state, dns_state, created_at, updated_at)
		SELECT $1, team_id, domain_id, created_by_identity_id, 'browser-api', $2, $3,
		'api-session.example.test', target, public_url_scope, membership_id, purpose, policy_revision, ip_policy, lifecycle_state, dns_state, $4, $4
		FROM control.public_urls WHERE id = $5`, otherID, sealed, database.storageKey.CurrentID(), now, publicURL.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{
		PreviewID: preview.ID, PublicURLID: otherID, TeamID: publicURL.TeamID,
		IdentityID: request.ActingIdentityID, PolicyRevision: uint64(publicURL.PolicyRevision), ExpectedMutationRevision: 1,
	}, now); err != nil {
		t.Fatal(err)
	}
	insertTestPublishRun(t, database, testPublishRun{
		ID: "pr_browser_api", PublicURLID: otherID, TeamID: publicURL.TeamID,
		MembershipID: publicURL.MembershipID, ActingIdentityID: request.ActingIdentityID,
		CertificateCacheKey: "certificate_session", CertificateScope: "public-url",
		CertificateIdentifiers: []string{"api-session.example.test"}, ChallengeMethod: "dns-01",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.publish_runs SET state = 'ready', ready_at = $2,
		share_capable = true WHERE id = $1`, "pr_browser_api", now); err != nil {
		t.Fatal(err)
	}
	handoff, err := database.IssueBrowserHandoff(t.Context(), BrowserLoginAttempt{
		PreviewID: preview.ID, PublicURLID: publicURL.ID, ReturnPath: "/settings",
	}, BrowserAccessSession{
		IdentityID: request.ActingIdentityID, DisplayName: "Sam", AccessToken: issued.AccessToken.String(), RefreshToken: issued.RefreshToken.String(),
		AccessExpiresAt: now.Add(time.Hour), ExpiresAt: now.Add(time.Hour),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	first, err := database.RedeemBrowserHandoffWithPermission(t.Context(), auth, testVisitorIssuer, handoff.Token, "", "", now)
	if err != nil || first.ReturnPath != "/settings" || first.NextUrl == nil || !strings.HasPrefix(*first.NextUrl, "https://api-session.example.test/__tnl/team/handoff/") {
		t.Fatalf("first host returned %q, %v, %v", first.ReturnPath, first.NextUrl, err)
	}
	if first.Issued.Permission.Scope != (visitorscope.Scope{Kind: visitorscope.PublicURL, ID: publicURL.ID}) {
		t.Fatal("first host prepared permission for another URL")
	}
	otherTicket := strings.TrimPrefix(*first.NextUrl, "https://api-session.example.test/__tnl/team/handoff/")
	other, err := database.RedeemBrowserHandoffWithPermission(t.Context(), browserTestAuthentication(t, database, otherID, now), testVisitorIssuer, otherTicket, "", "", now)
	if err != nil || other.CookieSecret != first.CookieSecret || other.NextUrl == nil || *other.NextUrl != "https://"+publicURL.CanonicalHostname+"/settings" {
		t.Fatalf("other host handoff = %t, %v, %v", other.CookieSecret == first.CookieSecret, other.NextUrl, err)
	}
	if other.Issued.Permission.Scope != (visitorscope.Scope{Kind: visitorscope.PublicURL, ID: otherID}) {
		t.Fatal("second host reused first host's visitor permission")
	}
	if _, err := database.BrowserSession(t.Context(), otherID, first.CookieSecret, now); err != nil {
		t.Fatalf("other host browser session: %v", err)
	}
	if err := database.RevokeBrowserSession(t.Context(), otherID, first.CookieSecret, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.BrowserSession(t.Context(), publicURL.ID, first.CookieSecret, now); !errors.Is(err, ErrPreviewAccess) {
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
			prepareVisitorTokenKeys(t, d, now)
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
			if _, err := d.RedeemBrowserHandoffWithPermission(t.Context(), wrong, testVisitorIssuer, handoff.Token, "", "", now); err == nil {
				t.Fatal("replacement run redeemed the alias handoff")
			}
			redemption, err := d.RedeemBrowserHandoffWithPermission(t.Context(), auth, testVisitorIssuer, handoff.Token, "", "", now)
			if err != nil {
				t.Fatalf("alias owner handoff redemption: %v", err)
			}
			if got, err := d.BrowserSession(t.Context(), auth.PublicURLID, redemption.CookieSecret, now); err != nil || got.IdentityID != request.ActingIdentityID {
				t.Fatalf("alias owner session: %+v, %v", got, err)
			}
			if _, err := d.RedeemBrowserHandoffWithPermission(t.Context(), auth, testVisitorIssuer, handoff.Token, "", "", now); !errors.Is(err, ErrPreviewAccess) {
				t.Fatalf("alias handoff replay: %v", err)
			}
		})
	}
}
