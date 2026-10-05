package controlstate

import (
	"crypto/sha256"
	"errors"
	"slices"
	"testing"
	"time"
)

func TestIntegrationSharesSnapshotAndRevoke(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "shares")
	routeRequest := builtinRouteRequest(t, database, now)
	route := createTestPublicURL(t, database, routeRequest, now)
	preview, err := database.CreatePreview(t.Context(), route.TeamID, routeRequest.ActingIdentityID, "preview", now)
	if err != nil {
		t.Fatal(err)
	}
	preview, err = database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{
		PreviewID: preview.ID, PublicURLID: route.ID, TeamID: route.TeamID, IdentityID: routeRequest.ActingIdentityID,
		PolicyRevision: uint64(route.PolicyRevision), ExpectedMutationRevision: route.MutationRevision,
	}, now)
	if err != nil || !slices.Equal(preview.PublicURLIDs, []string{route.ID}) {
		t.Fatalf("preview = %+v, %v", preview, err)
	}
	secret := sha256.Sum256([]byte("secret supplied by client"))
	request := CreateShareRequest{
		PreviewID: preview.ID, TeamID: preview.TeamID, ActingIdentityID: routeRequest.ActingIdentityID,
		IdempotencyKey: "first-share", SecretFingerprint: secret, ExpiresAt: now.Add(24 * time.Hour),
		PolicyRevision: uint64(route.PolicyRevision), PublicURLs: []AuthorizedSharePublicURL{{
			PublicURLID: route.ID, ExpectedMutationRevision: route.MutationRevision,
		}},
	}
	for _, expiresAt := range []time.Time{now, now.Add(31 * 24 * time.Hour)} {
		invalid := request
		invalid.ExpiresAt = expiresAt
		if _, err := database.CreateShare(t.Context(), invalid, now); !errors.Is(err, ErrShareInvalid) {
			t.Fatalf("invalid expiration %s: %v", expiresAt, err)
		}
	}
	share, err := database.CreateShare(t.Context(), request, now)
	if err != nil || share.ID == "" || share.PreviewID != preview.ID || !slices.Equal(share.PublicURLIDs, []string{route.ID}) || share.RevokedAt != nil {
		t.Fatalf("created share = %+v, %v", share, err)
	}
	retry, err := database.CreateShare(t.Context(), request, now)
	if err != nil || retry.ID != share.ID {
		t.Fatalf("idempotent share = %+v, %v", retry, err)
	}
	changed := request
	changed.SecretFingerprint = sha256.Sum256([]byte("different secret"))
	if _, err := database.CreateShare(t.Context(), changed, now); !errors.Is(err, ErrShareIdempotency) {
		t.Fatalf("same key with different secret: %v", err)
	}
	newRouteRequest := routeRequest
	newRouteRequest.IdempotencyKey = "new-service"
	newRouteRequest.RequestDigest = sha256.Sum256([]byte("new-service"))
	newRouteRequest.CanonicalHostname = "new-" + route.CanonicalHostname
	newRoute := createTestPublicURL(t, database, newRouteRequest, now)
	_, err = database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{
		PreviewID: preview.ID, PublicURLID: newRoute.ID, TeamID: route.TeamID, IdentityID: routeRequest.ActingIdentityID,
		PolicyRevision: uint64(newRoute.PolicyRevision), ExpectedMutationRevision: newRoute.MutationRevision,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := database.GetShare(t.Context(), share.ID)
	if err != nil || !slices.Equal(saved.PublicURLIDs, []string{route.ID}) {
		t.Fatalf("share gained a new hostname after creation: %+v, %v", saved, err)
	}
	page, err := database.ListShares(t.Context(), preview.ID, "")
	if err != nil || len(page.Shares) != 1 || page.Shares[0].ID != share.ID || page.NextCursor != "" {
		t.Fatalf("share list = %+v, %v", page, err)
	}
	if _, err := database.RevokeShare(t.Context(), share.ID, "other-identity", now); !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("other identity revoked share: %v", err)
	}
	revoked, err := database.RevokeShare(t.Context(), share.ID, routeRequest.ActingIdentityID, now.Add(time.Minute))
	if err != nil || revoked.RevokedAt == nil || !revoked.RevokedAt.Equal(now.Add(time.Minute).UTC().Truncate(time.Microsecond)) {
		t.Fatalf("revoked share = %+v, %v", revoked, err)
	}
	again, err := database.RevokeShare(t.Context(), share.ID, routeRequest.ActingIdentityID, now.Add(time.Hour))
	if err != nil || again.RevokedAt == nil || !again.RevokedAt.Equal(*revoked.RevokedAt) {
		t.Fatalf("repeated revoke = %+v, %v", again, err)
	}
	if _, err := database.CreateShare(t.Context(), request, now); !errors.Is(err, ErrShareIdempotency) {
		t.Fatalf("reused key revived a revoked share: %v", err)
	}
}

func TestIntegrationShareRejectsStaleOrUnrelatedURLs(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "share_guards")
	routeRequest := builtinRouteRequest(t, database, now)
	route := createTestPublicURL(t, database, routeRequest, now)
	preview, err := database.CreatePreview(t.Context(), route.TeamID, routeRequest.ActingIdentityID, "preview", now)
	if err != nil {
		t.Fatal(err)
	}
	request := CreateShareRequest{
		PreviewID: preview.ID, TeamID: route.TeamID, ActingIdentityID: routeRequest.ActingIdentityID,
		IdempotencyKey: "share", SecretFingerprint: sha256.Sum256([]byte("new secret")), ExpiresAt: now.Add(time.Hour),
		PolicyRevision: uint64(route.PolicyRevision), PublicURLs: []AuthorizedSharePublicURL{{PublicURLID: route.ID, ExpectedMutationRevision: route.MutationRevision}},
	}
	if _, err := database.CreateShare(t.Context(), request, now); !errors.Is(err, ErrShareStale) {
		t.Fatalf("public URL outside preview was shared: %v", err)
	}
	_, err = database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{
		PreviewID: preview.ID, PublicURLID: route.ID, TeamID: route.TeamID, IdentityID: routeRequest.ActingIdentityID,
		PolicyRevision: uint64(route.PolicyRevision), ExpectedMutationRevision: route.MutationRevision,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	request.PublicURLs[0].ExpectedMutationRevision++
	if _, err := database.CreateShare(t.Context(), request, now); !errors.Is(err, ErrShareStale) {
		t.Fatalf("stale public URL revision was shared: %v", err)
	}
	request.PublicURLs[0].ExpectedMutationRevision--
	request.ActingIdentityID = "other-identity"
	if _, err := database.CreateShare(t.Context(), request, now); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("other identity used preview: %v", err)
	}
}
