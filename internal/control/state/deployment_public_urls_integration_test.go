package state

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationDeploymentSavedPublicURLsBelongToTeamAcrossPublisherReplacement(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "deployment_public_urls")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	if _, err := d.pool.Exec(ctx, `UPDATE control.teams SET kind='organization' WHERE id=$1`, r.TeamID); err != nil {
		t.Fatal(err)
	}
	admin := addAuthorityMember(t, d, now, r.ActorID, r.TeamID, "deployment-admin", TeamRoleAdmin)
	r.ProjectLabel = "shop"
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}}, Services: map[string]ProjectServiceConfiguration{
		"web": {PublisherGroup: "production", Protocol: "http", Target: "app", PublicURL: &ProjectServicePublicURL{}, Access: &ProjectServiceAccess{Team: true}},
		"api": {PublisherGroup: "production", Protocol: "http", Target: "http://api.internal:3000", PublicURL: &ProjectServicePublicURL{Access: &ProjectPublicAccess{Mode: "anonymous"}}},
	}}
	r = selectedProjectRequest(r, "production")
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied.Services) != 2 || len(applied.Groups) != 1 {
		t.Fatal("saved public URL bindings were not returned")
	}
	namespace := applied.Groups[0].Namespace
	scope := DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}
	deployment, err := d.GetDeployment(ctx, scope, "production")
	if err != nil {
		t.Fatal(err)
	}
	for name, metadata := range deployment.Services {
		if metadata.PublicURL != "https://"+name+"."+namespace || !strings.HasPrefix(metadata.ID, "url_") || metadata.Endpoint != nil {
			t.Fatal("deployment URL borrowed a developer namespace or private endpoint", metadata)
		}
	}
	webID, apiID := deployment.Services["web"].ID, deployment.Services["api"].ID
	if !deployment.Targets["web"].App || deployment.Targets["web"].Address != "" {
		t.Fatal("app binding persisted a pretend listener")
	}
	updated, err := d.UpdateDeployment(ctx, UpdateDeploymentRequest{DeploymentScope: scope, Selector: deployment.ID, ExpectedRevision: deployment.Revision, Targets: map[string]DeploymentTarget{"api": {Address: "http://replacement.internal:8080"}}, Now: now})
	if err != nil || updated.Services["api"].ID != apiID || updated.Services["api"].PublicURL != deployment.Services["api"].PublicURL {
		t.Fatal("runtime target update changed public URL ownership", err)
	}
	deployment = updated
	if _, err := d.UpdateDeployment(ctx, UpdateDeploymentRequest{DeploymentScope: scope, Selector: deployment.ID, ExpectedRevision: deployment.Revision, Targets: map[string]DeploymentTarget{"web": {Address: "http://invented:3000"}}, Now: now}); !errors.Is(err, ErrProjectConfigurationInvalid) {
		t.Fatal("runtime management replaced an app-owned listener declaration", err)
	}
	q := controlstatedb.New(d.pool)
	for _, id := range []string{webID, apiID} {
		u, err := q.LockPublicURLForRun(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if u.PublicURLScope != "shared" || u.MembershipID.Valid || !u.PublisherPool || u.Ephemeral || u.Namespace != namespace {
			t.Fatal("saved URL is not deployment/team owned")
		}
		if id == webID && (u.Target != "" || u.AccessMode != "restricted") || id == apiID && u.AccessMode != "anonymous" {
			t.Fatal("saved URL copied another binding's policy or listener")
		}
	}
	// repeat the current saved intent after a lost apply reply; do not roll the
	// runtime target back while testing allocation recovery.
	r.Configuration.Services["api"] = ProjectServiceConfiguration{PublisherGroup: "production", Protocol: "http", Target: "http://replacement.internal:8080", PublicURL: &ProjectServicePublicURL{Access: &ProjectPublicAccess{Mode: "anonymous"}}}
	r.ExpectedRevision = applied.Revision
	again, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal("lost apply response allocated another URL", err)
	}
	applied = again
	again, err = d.ApplyProjectConfiguration(ctx, r)
	if err != nil || again.Revision != applied.Revision {
		t.Fatal("lost apply response was not idempotent", err)
	}
	enrollment, err := d.IssuePublisherGroupEnrollment(ctx, r.TeamID, r.ProjectKey, "production", r.ActorID, 2, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	first := enrollAppliedGroup(t, d, r, enrollment, now)
	if len(first.assignments.Services) != 1 || first.assignments.Services[0].Kind != "public_url" || first.assignments.Services[0].ServiceID != apiID || first.assignments.Services[0].Hostname != "api."+namespace {
		t.Fatal("installed assignment included an app-owned listener or lost canonical hostname", first.assignments)
	}
	second := enrollAppliedGroup(t, d, r, enrollment, now)
	if second.assignments.Services[0].ServiceID != apiID || second.member.PublisherIdentityID == first.member.PublisherIdentityID {
		t.Fatal("publisher replacement changed saved URL ownership")
	}
	_, err = d.RenamePublisherNamespace(ctx, RenamePublisherNamespaceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, Group: "production", NamespaceLabel: "live", ActorID: r.ActorID, ExpectedRevision: applied.Revision, IdempotencyKey: "rename-namespace", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	var reusable bool
	if err := d.pool.QueryRow(ctx, `SELECT control.service_namespace_reusable($1,$2)`, namespace, now.Add(8*24*time.Hour)).Scan(&reusable); err != nil || reusable {
		t.Fatal("namespace rename released still-saved URL authority", err)
	}
	// the creator is audit history, not the serving or ownership authority.
	if _, err := d.pool.Exec(ctx, `UPDATE control.team_memberships SET removed_at=$2,removed_by_identity_id=$4 WHERE team_id=$1 AND identity_id=$3`, r.TeamID, now, r.ActorID, admin.IdentityID); err != nil {
		t.Fatal(err)
	}
	scope.ActorID = admin.IdentityID
	current, err := d.GetDeployment(ctx, scope, deployment.ID)
	if err != nil || current.Services["web"].ID != webID {
		t.Fatal("creator leaving changed team-owned URL", err)
	}
	if _, err := d.GetPublisherGroupAssignments(ctx, first.lease.AccessToken, now); err != nil {
		t.Fatal("creator leaving revoked installed team publisher", err)
	}
	access := groupAssignmentAccess(t, d, first, first.assignments.Services[0], now)
	if access.Scope.Kind != "saved_public_url" || access.Scope.PublicURLID != apiID {
		t.Fatal("replacement did not retain exact team-owned URL authority")
	}
	if err := d.DeleteDeployment(ctx, scope, deployment.ID, current.Revision, now); err != nil {
		t.Fatal(err)
	}
	u, err := q.LockPublicURLForRun(ctx, webID)
	if err != nil || u.LifecycleState != "deleted" {
		t.Fatal("deployment deletion did not retire its saved URL", err)
	}
}

func TestIntegrationDeploymentPublicURLChangesDoNotMutateSiblingOrAdoptNamespace(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "deployment_url_scope")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}}, Services: map[string]ProjectServiceConfiguration{"web": {PublisherGroup: "production", Target: "app", PublicURL: &ProjectServicePublicURL{}}}}
	r = selectedProjectRequest(r, "production")
	first, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.ExpectedRevision = first.Revision
	r.Deployment = "staging"
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"staging": {}}, Services: map[string]ProjectServiceConfiguration{"web": {PublisherGroup: "staging", Target: "app", PublicURL: &ProjectServicePublicURL{}}}}
	staging, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if staging.Services[0].Hostname == first.Services[0].Hostname || staging.Services[0].ServiceID == first.Services[0].ServiceID {
		t.Fatal("deployments share a saved URL")
	}
	r.ExpectedRevision = staging.Revision
	s := r.Configuration.Services["web"]
	s.PublicURL.Hostname = first.Services[0].Hostname
	r.Configuration.Services["web"] = s
	if _, err := d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, ErrPublicURLConflict) {
		t.Fatal("staging adopted production's namespace", err)
	}
	scope := DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}
	current, err := d.GetDeployment(ctx, scope, "staging")
	if err != nil || current.Services["web"].ID != staging.Services[0].ServiceID {
		t.Fatal("failed hostname change was not atomic", err)
	}
}
