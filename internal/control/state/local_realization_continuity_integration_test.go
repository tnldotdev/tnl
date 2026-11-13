package state

import (
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestIntegrationLocalRealizationPreservesResourceAndGrantIDs(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "local_continuity")
	r := oidcRouteRequest(t, d, now)
	public := createTestPublicURL(t, d, r, now)
	base := RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ActorID: r.ActingIdentityID, ProjectKey: "local-project", SourceFingerprint: strings.Repeat("a", 64), WorktreeKey: "checkout", Now: now}
	type binding struct{ resource, grant string }
	original := map[string]binding{}
	for round := range 4 {
		for _, name := range []string{"api", "web", "sdk"} {
			request := base
			request.Service = name
			request.Configuration = ProjectServiceConfiguration{Target: "http://127.0.0.1:3000", Access: &ProjectServiceAccess{Team: true}}
			if name == "web" {
				request.PublicURLID = public.ID
				request.Configuration.PublicURL = &ProjectServicePublicURL{}
			} else if name == "sdk" {
				request.Configuration.Target = "app"
			}
			realized, err := d.RealizeLocalProjectService(t.Context(), request)
			if err != nil {
				t.Fatalf("round %d, %s: %v", round, name, err)
			}
			var got binding
			if err := d.pool.QueryRow(t.Context(), `SELECT COALESCE(service_id,public_url_id),visitor_grant_id FROM control.local_project_services WHERE team_id=$1 AND project_key=$2 AND worktree_key=$3 AND service=$4`, base.TeamID, base.ProjectKey, base.WorktreeKey, name).Scan(&got.resource, &got.grant); err != nil {
				t.Fatal(err)
			}
			if got.resource != realized.ServiceID || got.grant == "" || name == "web" && got.resource != public.ID {
				t.Fatalf("realization lost its resource or team grant: %+v, %+v", realized, got)
			}
			if round == 0 {
				original[name] = got
			} else if got != original[name] {
				t.Fatalf("round %d replaced %s's resource or grant: %+v != %+v", round, name, got, original[name])
			}
		}
	}
	var resources, grants int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*),count(visitor_grant_id) FROM control.local_project_services WHERE team_id=$1`, base.TeamID).Scan(&resources, &grants); err != nil || resources != 3 || grants != 3 {
		t.Fatalf("repeated realization duplicated resources or grants: resources=%d grants=%d err=%v", resources, grants, err)
	}
	if _, err := d.GetProjectConfiguration(t.Context(), base.TeamID, base.ProjectKey, base.ActorID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("local realization implicitly applied production configuration: %v", err)
	}
}
