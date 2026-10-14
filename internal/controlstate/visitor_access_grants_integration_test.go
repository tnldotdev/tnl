package controlstate

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func TestIntegrationExactTeamShareAuthorizesCurrentBrowserMembership(t *testing.T) {
	f := newPublishRunFixture(t)
	database, now := f.database, f.now
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.teams SET kind = 'organization' WHERE id = $1`, f.request.TeamID); err != nil {
		t.Fatal(err)
	}
	member := addAuthorityMember(t, database, now, f.request.ActingIdentityID, f.request.TeamID, "exact-team-share", TeamRoleMember)
	team, err := database.GetTeam(t.Context(), f.request.ActingIdentityID, f.request.TeamID)
	if err != nil {
		t.Fatal(err)
	}
	_, cookie, _ := newBrowserReviewer(t, database, "", f.setup.PublicURLID, member.IdentityID, now)
	check := func(at time.Time, want bool) {
		t.Helper()
		result, err := database.BrowserAuthorization(t.Context(), f.setup.PublicURLID, cookie, at)
		if err != nil || result.VisitAllowed != want {
			t.Fatalf("browser grant at %s = %+v, %v", at, result, err)
		}
	}
	check(now, false)
	expires := now.Add(time.Hour)
	request := CreateTeamURLShareGrantRequest{
		TeamID: f.request.TeamID, PublicURLID: f.setup.PublicURLID, ActingIdentityID: f.request.ActingIdentityID,
		IdempotencyKey: "exact-team-share", PolicyRevision: uint64(team.PolicyRevision),
		ExpectedMutationRevision: 2, ExpiresAt: &expires,
	}
	grant, err := database.CreateTeamURLShareGrant(t.Context(), request, now)
	if err != nil || grant.ID == "" || grant.ExpiresAt == nil || !grant.ExpiresAt.Equal(expires) {
		t.Fatalf("team share = %+v, %v", grant, err)
	}
	check(now, true)
	page, err := database.ListTeamURLShareGrants(t.Context(), f.request.TeamID, f.request.ActingIdentityID, "")
	if err != nil || len(page.Shares) != 1 || page.Shares[0].ID != grant.ID {
		t.Fatalf("team share list = %+v, %v", page, err)
	}
	retry, err := database.CreateTeamURLShareGrant(t.Context(), request, now)
	if err != nil || retry.ID != grant.ID {
		t.Fatalf("idempotent team share = %+v, %v", retry, err)
	}
	changed := request
	changed.ExpiresAt = nil
	if _, err := database.CreateTeamURLShareGrant(t.Context(), changed, now); !errors.Is(err, ErrShareIdempotency) {
		t.Fatalf("changed share request reused key: %v", err)
	}
	if _, err := database.RevokeTeamURLShareGrant(t.Context(), grant.ID, grant.TeamID, member.IdentityID, now.Add(time.Minute)); !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("member revoked owner share: %v", err)
	}
	revoked, err := database.RevokeTeamURLShareGrant(t.Context(), grant.ID, grant.TeamID, f.request.ActingIdentityID, now.Add(time.Minute))
	if err != nil || revoked.RevokedAt == nil {
		t.Fatalf("revoke team share = %+v, %v", revoked, err)
	}
	check(now.Add(time.Minute), false)
	if _, err := database.CreateTeamURLShareGrant(t.Context(), request, now); !errors.Is(err, ErrShareIdempotency) {
		t.Fatalf("revoked share revived by retry: %v", err)
	}
	short := request
	short.IdempotencyKey, short.ExpiresAt = "expiring-team-share", nil
	shortExpiry := now.Add(time.Minute)
	short.ExpiresAt = &shortExpiry
	if _, err := database.CreateTeamURLShareGrant(t.Context(), short, now); err != nil {
		t.Fatal(err)
	}
	check(now, true)
	check(now.Add(2*time.Minute), false)
}

func TestIntegrationPreviewLinkCannotIncludeDatabasePublicURL(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "http_only_preview_link")
	request := builtinRouteRequest(t, database, now)
	if err := database.EnsurePrimaryIngressPool(t.Context(), "192.0.2.10", "", []int32{5432}, now); err != nil {
		t.Fatal(err)
	}
	request.ServiceProtocol, request.Target = PublicURLServicePostgres, ""
	url := createTestPublicURL(t, database, request, now)
	preview, err := database.CreatePreview(t.Context(), request.TeamID, request.ActingIdentityID, "http-only-preview", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{
		PreviewID: preview.ID, TeamID: request.TeamID, IdentityID: request.ActingIdentityID,
		PublicURLID: url.ID, PolicyRevision: uint64(url.PolicyRevision), ExpectedMutationRevision: url.MutationRevision,
	}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateShare(t.Context(), CreateShareRequest{
		PreviewID: preview.ID, TeamID: request.TeamID, ActingIdentityID: request.ActingIdentityID,
		IdempotencyKey: "db-link", SecretFingerprint: sha256.Sum256([]byte("db-link")),
		ExpiresAt: now.Add(time.Hour), PolicyRevision: uint64(url.PolicyRevision),
		PublicURLs: []AuthorizedSharePublicURL{{PublicURLID: url.ID, ExpectedMutationRevision: url.MutationRevision}},
	}, now); !errors.Is(err, ErrShareStale) {
		t.Fatalf("database URL entered anonymous share link: %v", err)
	}
	if _, err := database.SetPreviewTeamAccess(t.Context(), SetPreviewTeamAccessRequest{
		PreviewID: preview.ID, TeamID: request.TeamID, IdentityID: request.ActingIdentityID,
		Enabled: true, PolicyRevision: uint64(url.PolicyRevision),
		PublicURLs: []AuthorizedSharePublicURL{{PublicURLID: url.ID, ExpectedMutationRevision: url.MutationRevision}},
	}, now); !errors.Is(err, ErrPreviewStale) {
		t.Fatalf("database URL entered preview-wide team share: %v", err)
	}
}
