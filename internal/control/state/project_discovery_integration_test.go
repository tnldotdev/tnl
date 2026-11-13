package state

import (
	"errors"
	"testing"
)

func TestIntegrationProjectDiscoveryPaging(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "project_discovery")
	r := appliedProjectRequest(t, d, now)
	if _, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	// list fixtures need no resource allocations or decrypted configuration.
	if _, err := d.pool.Exec(t.Context(), `INSERT INTO control.applied_projects(team_id,project_key,source_fingerprint,configuration_ciphertext,storage_key_id,created_by_identity_id,updated_at)
	    SELECT team_id,'page-'||lpad(n::text,3,'0'),source_fingerprint,configuration_ciphertext,storage_key_id,created_by_identity_id,updated_at
	    FROM control.applied_projects CROSS JOIN generate_series(1,100) n WHERE team_id=$1 AND project_key=$2`, r.TeamID, r.ProjectKey); err != nil {
		t.Fatal(err)
	}
	page, err := d.ListProjects(t.Context(), r.TeamID, r.ActorID, "")
	if err != nil || len(page.Projects) != 100 || page.NextCursor == "" {
		t.Fatal("first page", err)
	}
	last, err := d.ListProjects(t.Context(), r.TeamID, r.ActorID, page.NextCursor)
	if err != nil || len(last.Projects) != 1 || last.NextCursor != "" || last.Projects[0].ProjectKey <= page.Projects[99].ProjectKey {
		t.Fatal("continuation skipped or duplicated a project", err)
	}
	if _, err := decodeDiscoveryCursor(page.NextCursor, "other/v1", r.TeamID, r.ActorID); !errors.Is(err, ErrDiscoveryCursor) {
		t.Fatal("cursor was reusable across collections", err)
	}
	malformed := encodeDiscoveryCursor(discoveryCursor{Kind: "projects/v1", Team: r.TeamID, Actor: r.ActorID, After: "\x00"})
	if _, err := d.ListProjects(t.Context(), r.TeamID, r.ActorID, malformed); !errors.Is(err, ErrDiscoveryCursor) {
		t.Fatal("project cursor accepted an invalid continuation key", err)
	}
	malformed = encodeDiscoveryCursor(discoveryCursor{Kind: "previews/v1", Team: r.TeamID, Actor: r.ActorID, After: "\x00"})
	if _, err := d.ListPreviews(t.Context(), r.TeamID, r.ActorID, malformed); !errors.Is(err, ErrDiscoveryCursor) {
		t.Fatal("preview cursor accepted an invalid continuation key", err)
	}
	if _, err := d.ListProjects(t.Context(), "another-team", r.ActorID, page.NextCursor); !errors.Is(err, ErrDiscoveryCursor) {
		t.Fatal("cursor was reusable across teams", err)
	}
	if _, err := d.ListProjects(t.Context(), r.TeamID, "another-identity", page.NextCursor); !errors.Is(err, ErrDiscoveryCursor) {
		t.Fatal("cursor was reusable across identities", err)
	}
	if _, err := d.ListProjects(t.Context(), r.TeamID, "another-identity", ""); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("project discovery did not check current authorization", err)
	}
	insertAuthorityIdentity(t, d, "other-creator", "", false, now)
	if _, err := d.CreatePreview(t.Context(), r.TeamID, "other-creator", "other-preview", now); err != nil {
		t.Fatal(err)
	}
	preview, err := d.CreatePreview(t.Context(), r.TeamID, r.ActorID, "own-preview", now)
	if err != nil {
		t.Fatal(err)
	}
	previews, err := d.ListPreviews(t.Context(), r.TeamID, r.ActorID, "")
	if err != nil || len(previews.Previews) != 1 || previews.Previews[0].ID != preview.ID {
		t.Fatal("owner gained another creator's preview", err)
	}
}
