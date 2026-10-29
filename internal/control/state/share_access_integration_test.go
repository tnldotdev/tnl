package state

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func TestIntegrationShareAccessBindsPublisherAndRevocation(t *testing.T) {
	database, now, runRequest, leases := newPublishRunPrerequisites(t)
	request := oidcRouteRequest(t, database, now)
	publicURL := createTestPublicURL(t, database, request, now)
	runRequest.PublicURLID, runRequest.TeamID, runRequest.ActingIdentityID, runRequest.MembershipID = publicURL.ID, request.TeamID, request.ActingIdentityID, request.MembershipID
	runRequest.CertificateIdentifiers = []string{publicURL.CanonicalHostname}
	setup, err := database.CreatePublishRun(t.Context(), runRequest, now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f := publishRunFixture{database, now, runRequest, setup, leases}
	preview, err := database.CreatePreview(t.Context(), f.request.TeamID, f.request.ActingIdentityID, "share-test", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.RedeemShare(t.Context(), f.authentication(), "shr_0123456789abcdefghijkl", []byte(strings.Repeat("s", 32)), nil, now); !errors.Is(err, ErrPublishRunStale) {
		t.Fatalf("unmarked publisher redeemed share: %v", err)
	}
	if err := database.EnableShareAccess(t.Context(), f.authentication(), preview.ID); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("unassigned preview was enabled: %v", err)
	}
	_, err = database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{
		PreviewID: preview.ID, PublicURLID: f.setup.PublicURLID, TeamID: f.request.TeamID,
		IdentityID: f.request.ActingIdentityID, PolicyRevision: 1, ExpectedMutationRevision: 2,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.EnableShareAccess(t.Context(), f.authentication(), preview.ID); err != nil {
		t.Fatal(err)
	}
	secret := []byte("0123456789abcdefghijklmnopqrstuv")
	fingerprint := sha256.Sum256(secret)
	share, err := database.CreateShare(t.Context(), CreateShareRequest{
		PreviewID: preview.ID, TeamID: f.request.TeamID, ActingIdentityID: f.request.ActingIdentityID,
		IdempotencyKey: "share-test", SecretFingerprint: fingerprint, ExpiresAt: now.Add(24 * time.Hour),
		PolicyRevision: 1, PublicURLs: []AuthorizedSharePublicURL{{PublicURLID: f.setup.PublicURLID, ExpectedMutationRevision: 2}},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.RedeemShare(t.Context(), f.authentication(), share.ID, []byte(strings.Repeat("x", 32)), nil, now); !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("wrong secret redeemed: %v", err)
	}
	redemption, err := database.RedeemShare(t.Context(), f.authentication(), share.ID, secret, nil, now)
	if err != nil || redemption.ShareID != share.ID || redemption.NextURL != "https://"+publicURL.CanonicalHostname+"/" || redemption.CookieSecret == "" {
		t.Fatalf("redeemed link = %+v, %v", redemption, err)
	}
	cookie, err := base64.RawURLEncoding.DecodeString(redemption.CookieSecret)
	if err != nil || len(cookie) != 32 || strings.Contains(redemption.CookieSecret, ".") {
		t.Fatalf("issued cookie = %q, %v", redemption.CookieSecret, err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: f.setup.PublicURLID}
	source := ShareSessionTokenSource{ShareID: share.ID, Secret: redemption.CookieSecret}
	permission, err := database.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, now)
	if err != nil || permission.Permission.Subject != (visitortoken.Share{ShareID: share.ID}) {
		t.Fatal("redeemed session lost its exact share permission", err)
	}
	if _, err := database.RevokeShare(t.Context(), share.ID, f.request.ActingIdentityID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, now.Add(2*time.Second)); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("revoked share session issued permission", err)
	}
	if _, err := database.RedeemShare(t.Context(), f.authentication(), share.ID, secret, nil, now.Add(2*time.Second)); !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("revoked share redeemed again: %v", err)
	}
}

func TestIntegrationShareHandoffIsShortLivedAndBoundToTheTargetPublicURL(t *testing.T) {
	f := newPublishRunFixture(t)
	database, now := f.database, f.now
	preview, err := database.CreatePreview(t.Context(), f.request.TeamID, f.request.ActingIdentityID, "handoff", now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{
		PreviewID: preview.ID, PublicURLID: f.setup.PublicURLID, TeamID: f.request.TeamID,
		IdentityID: f.request.ActingIdentityID, PolicyRevision: 1, ExpectedMutationRevision: 2,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	apiRoute := createTestPublicURL(t, database, CreatePublicURLRequest{
		TeamID: f.request.TeamID, DomainID: "domain_session", ActingIdentityID: f.request.ActingIdentityID,
		IdempotencyKey: "api", RequestDigest: sha256.Sum256([]byte("api")),
		CanonicalHostname: "api.session.example.test", Target: "http://127.0.0.1:4000",
		PublicURLScope: PublicURLScopeShared, Purpose: PublicURLPurposeApp, DNSState: PublicURLDNSUnmanaged, PolicyRevision: 1,
	}, now)
	_, err = database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{
		PreviewID: preview.ID, PublicURLID: apiRoute.ID, TeamID: f.request.TeamID,
		IdentityID: f.request.ActingIdentityID, PolicyRevision: 1, ExpectedMutationRevision: apiRoute.MutationRevision,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	apiRequest := f.request
	apiRequest.PublicURLID, apiRequest.IdempotencyKey = apiRoute.ID, "api-publish"
	apiRequest.RequestDigest = sha256.Sum256([]byte(apiRequest.IdempotencyKey))
	apiRequest.ExpectedMutationRevision = apiRoute.MutationRevision
	apiRequest.CertificateCacheKey = apiRoute.CanonicalHostname
	apiRequest.CertificateIdentifiers = []string{apiRoute.CanonicalHostname}
	apiSetup, err := database.CreatePublishRun(t.Context(), apiRequest, now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	api := publishRunFixture{database: database, now: now, request: apiRequest, setup: apiSetup, leases: f.leases}
	for _, run := range []publishRunFixture{f, api} {
		if err := database.EnableShareAccess(t.Context(), run.authentication(), preview.ID); err != nil {
			t.Fatal(err)
		}
		// share handoffs need two current publish runs; certificate readiness is
		// covered by the publish-run integration tests.
		if _, err := database.pool.Exec(t.Context(),
			`UPDATE control.publish_runs SET state = 'ready', ready_at = $2 WHERE id = $1`, run.setup.PublishRunID, now); err != nil {
			t.Fatal(err)
		}
	}
	secret := []byte("0123456789abcdefghijklmnopqrstuv")
	share, err := database.CreateShare(t.Context(), CreateShareRequest{
		PreviewID: preview.ID, TeamID: f.request.TeamID, ActingIdentityID: f.request.ActingIdentityID,
		IdempotencyKey: "two-host-share", SecretFingerprint: sha256.Sum256(secret), ExpiresAt: now.Add(time.Hour),
		PolicyRevision: 1, PublicURLs: []AuthorizedSharePublicURL{
			{PublicURLID: f.setup.PublicURLID, ExpectedMutationRevision: 2},
			{PublicURLID: apiRoute.ID, ExpectedMutationRevision: apiRoute.MutationRevision + 1},
		},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := database.RedeemShare(t.Context(), f.authentication(), share.ID, secret, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(initial.NextURL)
	if err != nil || parsed.Hostname() != apiRoute.CanonicalHostname {
		t.Fatalf("handoff hostname = %s, %v", initial.NextURL, err)
	}
	tokenText := strings.TrimPrefix(parsed.Path, "/__tnl/share/handoff/")
	if tokenText == parsed.Path {
		t.Fatalf("handoff path = %s", parsed.Path)
	}
	token, err := base64.RawURLEncoding.DecodeString(tokenText)
	if err != nil || len(token) != 32 {
		t.Fatalf("handoff token format = %v", err)
	}
	if _, err := database.RedeemShare(t.Context(), f.authentication(), "", nil, token, now); !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("handoff accepted on original host: %v", err)
	}
	visited, err := database.RedeemShare(t.Context(), api.authentication(), "", nil, token, now)
	if err != nil || visited.ShareID != share.ID || visited.NextURL != "https://route-session.example.test/" || visited.CookieSecret == "" {
		t.Fatalf("redeemed handoff = %+v, %v", visited, err)
	}
	if _, err := database.RedeemShare(t.Context(), api.authentication(), "", nil, token, now); !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("handoff could be replayed: %v", err)
	}
	if err := database.ExpireVisitorPermissions(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	var cookies, handoffs int
	if err := database.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM control.share_cookies),(SELECT count(*) FROM control.share_handoffs)`).Scan(&cookies, &handoffs); err != nil || cookies != 2 || handoffs != 0 {
		t.Fatal("cleanup lost live share cookies or retained a consumed handoff", cookies, handoffs, err)
	}
	if err := database.ExpireVisitorPermissions(t.Context(), share.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	if err := database.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.share_cookies`).Scan(&cookies); err != nil || cookies != 0 {
		t.Fatal("share cookie cleanup depended on a publisher snapshot read", cookies, err)
	}
}
