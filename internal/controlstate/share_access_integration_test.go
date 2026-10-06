package controlstate

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestIntegrationShareAccessBindsPublisherAndRevocation(t *testing.T) {
	f := newPublishRunFixture(t)
	database, now := f.database, f.now
	preview, err := database.CreatePreview(t.Context(), f.request.TeamID, f.request.ActingIdentityID, "share-test", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.PublishRunShareState(t.Context(), f.authentication(), now); !errors.Is(err, ErrPublishRunStale) {
		t.Fatalf("unmarked publisher read shares: %v", err)
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
	state, err := database.PublishRunShareState(t.Context(), f.authentication(), now)
	if err != nil || len(state) != 1 || state[0].ID != share.ID || state[0].SecretFingerprint != fingerprint || len(state[0].CookieHashes) != 0 {
		t.Fatalf("initial publisher share state = %+v, %v", state, err)
	}
	if _, err := database.RedeemShare(t.Context(), f.authentication(), share.ID, []byte(strings.Repeat("x", 32)), nil, now); !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("wrong secret redeemed: %v", err)
	}
	redemption, err := database.RedeemShare(t.Context(), f.authentication(), share.ID, secret, nil, now)
	if err != nil || redemption.ShareID != share.ID || redemption.NextURL != "https://route-session.example.test/" || redemption.CookieSecret == "" {
		t.Fatalf("redeemed link = %+v, %v", redemption, err)
	}
	cookie, err := base64.RawURLEncoding.DecodeString(redemption.CookieSecret)
	if err != nil || len(cookie) != 32 || strings.Contains(redemption.CookieSecret, ".") {
		t.Fatalf("issued cookie = %q, %v", redemption.CookieSecret, err)
	}
	state, err = database.PublishRunShareState(t.Context(), f.authentication(), now)
	if err != nil || len(state) != 1 || len(state[0].CookieHashes) != 1 || state[0].CookieHashes[0] != sha256.Sum256(cookie) {
		t.Fatalf("publisher cookie state = %+v, %v", state, err)
	}
	if _, err := database.RevokeShare(t.Context(), share.ID, f.request.ActingIdentityID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	state, err = database.PublishRunShareState(t.Context(), f.authentication(), now.Add(2*time.Second))
	if err != nil || len(state) != 0 {
		t.Fatalf("revoked publisher state = %+v, %v", state, err)
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
		PublicURLScope: PublicURLScopeShared, DNSState: PublicURLDNSUnmanaged, PolicyRevision: 1,
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
}
