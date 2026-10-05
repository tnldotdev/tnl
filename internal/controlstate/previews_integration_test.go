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
