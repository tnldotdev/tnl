package state

import (
	"errors"
	"testing"
)

func TestIntegrationPreviewGroupsOnlyAuthorizedPublicURLs(t *testing.T) {
	f := newServiceHTTPFixture(t)
	database, now, service := f.database, f.now, f.service
	group, err := database.CreatePreview(t.Context(), service.TeamID, f.project.ActorID, "project-worktree", now)
	if err != nil || group.ID == "" || len(group.ServiceIDs) != 0 {
		t.Fatalf("create preview = %+v, %v", group, err)
	}
	retry, err := database.CreatePreview(t.Context(), service.TeamID, f.project.ActorID, "project-worktree", now)
	if err != nil || retry.ID != group.ID {
		t.Fatalf("idempotent preview = %+v, %v", retry, err)
	}
	attach := AddPreviewServiceRequest{
		PreviewID: group.ID, ServiceID: service.ID, TeamID: service.TeamID, IdentityID: f.project.ActorID,
	}
	if _, err := database.AddPreviewService(t.Context(), AddPreviewServiceRequest{
		PreviewID: group.ID, ServiceID: service.ID, TeamID: service.TeamID, IdentityID: "someone-else",
	}, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("another identity attached to preview: %v", err)
	}
	// service attachment checks current transactional facts, not an external
	// public URL mutation receipt. a stale enabled observation cannot attach.
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.services SET enabled=false WHERE id=$1`, service.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.AddPreviewService(t.Context(), attach, now); !errors.Is(err, ErrPreviewStale) {
		t.Fatalf("disabled service attached: %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.services SET enabled=true WHERE id=$1`, service.ID); err != nil {
		t.Fatal(err)
	}
	group, err = database.AddPreviewService(t.Context(), attach, now)
	if err != nil || len(group.ServiceIDs) != 1 || group.ServiceIDs[0] != service.ID {
		t.Fatalf("attached service = %+v, %v", group, err)
	}
	group, err = database.AddPreviewService(t.Context(), attach, now)
	if err != nil || len(group.ServiceIDs) != 1 {
		t.Fatalf("idempotent attachment = %+v, %v", group, err)
	}
}

func TestIntegrationTeamAccessStaysInOnePreviewAndCanBeRevoked(t *testing.T) {
	f := newServiceHTTPFixture(t)
	database, now, service := f.database, f.now, f.service
	preview, err := database.CreatePreview(t.Context(), service.TeamID, f.project.ActorID, "team-access", now)
	if err != nil {
		t.Fatal(err)
	}
	attach := AddPreviewServiceRequest{
		PreviewID: preview.ID, ServiceID: service.ID, TeamID: service.TeamID, IdentityID: f.project.ActorID,
	}
	if _, err := database.AddPreviewService(t.Context(), attach, now); err != nil {
		t.Fatal(err)
	}
	request := SetPreviewTeamAccessRequest{
		PreviewID: preview.ID, TeamID: service.TeamID, IdentityID: f.project.ActorID, Enabled: true,
	}
	other, err := database.CreatePreview(t.Context(), service.TeamID, f.project.ActorID, "other-team-access", now)
	if err != nil {
		t.Fatal(err)
	}
	otherAttach := attach
	otherAttach.PreviewID = other.ID
	if _, err := database.AddPreviewService(t.Context(), otherAttach, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.SetPreviewTeamAccess(t.Context(), request, now); !errors.Is(err, ErrPreviewStale) {
		t.Fatalf("shared URL granted team access through one preview: %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), "DELETE FROM control.preview_services WHERE preview_id = $1", other.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.services SET enabled=false WHERE id=$1`, service.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.SetPreviewTeamAccess(t.Context(), request, now); !errors.Is(err, ErrPreviewStale) {
		t.Fatalf("stale service eligibility enabled team access: %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.services SET enabled=true WHERE id=$1`, service.ID); err != nil {
		t.Fatal(err)
	}
	enabled, err := database.SetPreviewTeamAccess(t.Context(), request, now)
	if err != nil || !enabled.TeamAccessEnabled {
		t.Fatalf("enable team access = %+v, %v", enabled, err)
	}
	if _, err := database.AddPreviewService(t.Context(), otherAttach, now); !errors.Is(err, ErrPreviewStale) {
		t.Fatalf("shared URL attached after team access was enabled: %v", err)
	}
	request.Enabled = false
	disabled, err := database.SetPreviewTeamAccess(t.Context(), request, now)
	if err != nil || disabled.TeamAccessEnabled {
		t.Fatalf("revoke team access = %+v, %v", disabled, err)
	}
	if _, err := database.AddPreviewService(t.Context(), otherAttach, now); err != nil {
		t.Fatalf("other preview after revoke: %v", err)
	}
}
