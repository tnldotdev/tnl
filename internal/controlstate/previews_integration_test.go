package controlstate

import (
	"errors"
	"testing"
)

func TestIntegrationPreviewGroupsOnlyAuthorizedPublicURLs(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "previews")
	routeRequest := builtinRouteRequest(t, database, now)
	route := createTestPublicURL(t, database, routeRequest, now)
	group, err := database.CreatePreview(t.Context(), route.TeamID, routeRequest.ActingIdentityID, "project-worktree", now)
	if err != nil || group.ID == "" || len(group.PublicURLIDs) != 0 {
		t.Fatalf("create preview = %+v, %v", group, err)
	}
	retry, err := database.CreatePreview(t.Context(), route.TeamID, routeRequest.ActingIdentityID, "project-worktree", now)
	if err != nil || retry.ID != group.ID {
		t.Fatalf("idempotent preview = %+v, %v", retry, err)
	}
	attach := AddPreviewPublicURLRequest{
		PreviewID: group.ID, PublicURLID: route.ID, TeamID: route.TeamID,
		IdentityID: routeRequest.ActingIdentityID, PolicyRevision: uint64(route.PolicyRevision),
		ExpectedMutationRevision: route.MutationRevision,
	}
	if _, err := database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{
		PreviewID: group.ID, PublicURLID: route.ID, TeamID: route.TeamID,
		IdentityID: "someone-else", PolicyRevision: uint64(route.PolicyRevision),
		ExpectedMutationRevision: route.MutationRevision,
	}, now); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("another identity attached to preview: %v", err)
	}
	attach.ExpectedMutationRevision++
	if _, err := database.AddPreviewPublicURL(t.Context(), attach, now); !errors.Is(err, ErrPreviewStale) {
		t.Fatalf("stale public URL revision attached: %v", err)
	}
	attach.ExpectedMutationRevision--
	group, err = database.AddPreviewPublicURL(t.Context(), attach, now)
	if err != nil || len(group.PublicURLIDs) != 1 || group.PublicURLIDs[0] != route.ID {
		t.Fatalf("attached public URL = %+v, %v", group, err)
	}
	group, err = database.AddPreviewPublicURL(t.Context(), attach, now)
	if err != nil || len(group.PublicURLIDs) != 1 {
		t.Fatalf("idempotent attachment = %+v, %v", group, err)
	}
}

func TestIntegrationTeamAccessStaysInOnePreviewAndCanBeRevoked(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "team-preview-access")
	routeRequest := builtinRouteRequest(t, database, now)
	route := createTestPublicURL(t, database, routeRequest, now)
	preview, err := database.CreatePreview(t.Context(), route.TeamID, routeRequest.ActingIdentityID, "team-access", now)
	if err != nil {
		t.Fatal(err)
	}
	attach := AddPreviewPublicURLRequest{
		PreviewID: preview.ID, PublicURLID: route.ID, TeamID: route.TeamID,
		IdentityID: routeRequest.ActingIdentityID, PolicyRevision: uint64(route.PolicyRevision),
		ExpectedMutationRevision: route.MutationRevision,
	}
	if _, err := database.AddPreviewPublicURL(t.Context(), attach, now); err != nil {
		t.Fatal(err)
	}
	request := SetPreviewTeamAccessRequest{
		PreviewID: preview.ID, TeamID: route.TeamID, IdentityID: routeRequest.ActingIdentityID,
		PolicyRevision: uint64(route.PolicyRevision), Enabled: true,
		PublicURLs: []AuthorizedSharePublicURL{{PublicURLID: route.ID, ExpectedMutationRevision: route.MutationRevision}},
	}
	other, err := database.CreatePreview(t.Context(), route.TeamID, routeRequest.ActingIdentityID, "other-team-access", now)
	if err != nil {
		t.Fatal(err)
	}
	otherAttach := attach
	otherAttach.PreviewID = other.ID
	if _, err := database.AddPreviewPublicURL(t.Context(), otherAttach, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.SetPreviewTeamAccess(t.Context(), request, now); !errors.Is(err, ErrPreviewStale) {
		t.Fatalf("shared URL granted team access through one preview: %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), "DELETE FROM control.preview_public_urls WHERE preview_id = $1", other.ID); err != nil {
		t.Fatal(err)
	}
	request.PublicURLs[0].ExpectedMutationRevision++
	if _, err := database.SetPreviewTeamAccess(t.Context(), request, now); !errors.Is(err, ErrPreviewStale) {
		t.Fatalf("stale revision enabled team access: %v", err)
	}
	request.PublicURLs[0].ExpectedMutationRevision--
	enabled, err := database.SetPreviewTeamAccess(t.Context(), request, now)
	if err != nil || !enabled.TeamAccessEnabled {
		t.Fatalf("enable team access = %+v, %v", enabled, err)
	}
	if _, err := database.AddPreviewPublicURL(t.Context(), otherAttach, now); !errors.Is(err, ErrPreviewStale) {
		t.Fatalf("shared URL attached after team access was enabled: %v", err)
	}
	request.Enabled = false
	request.PublicURLs = nil
	request.PolicyRevision = 0
	disabled, err := database.SetPreviewTeamAccess(t.Context(), request, now)
	if err != nil || disabled.TeamAccessEnabled {
		t.Fatalf("revoke team access = %+v, %v", disabled, err)
	}
	if _, err := database.AddPreviewPublicURL(t.Context(), otherAttach, now); err != nil {
		t.Fatalf("other preview after revoke: %v", err)
	}
}
