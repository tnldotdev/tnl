package state

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationDeploymentExactHostnameIsNotAnAllocationNamespace(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "deployment_exact_hostname")
	r := appliedProjectRequest(t, d, now)
	domain, err := d.ClaimTeamDomain(t.Context(), ClaimDomainRequest{TeamID: r.TeamID, IdentityID: r.ActorID, Domain: "custom.example.test", IdempotencyKey: "custom", RequestDigest: sha256.Sum256([]byte("custom"))}, now)
	if err != nil {
		t.Fatal(err)
	}
	work, found, err := d.ClaimDNSAuthorityWork(t.Context(), "dns-worker", now, time.Minute)
	if err != nil || !found || work.Reference != domain.DNSAuthorityReference {
		t.Fatal("custom domain did not retain its DNS authority", err)
	}
	work.State, work.ProviderZoneID, work.Nameservers, work.AvailableAt = "ready", "ZDEPLOYMENT", []string{"ns-1.example.test", "ns-2.example.test"}, now
	if _, err := d.SaveDNSAuthorityWork(t.Context(), work, now); err != nil {
		t.Fatal(err)
	}
	r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{DomainID: domain.ID}, Services: map[string]ProjectServiceConfiguration{
		"web": {Target: "app", PublicURL: &ProjectServicePublicURL{Hostname: "www.custom.example.test", DomainID: domain.ID}},
	}}
	r = selectedProjectRequest(r, "production")
	applied, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	scope := DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}
	production, err := d.GetDeployment(t.Context(), scope, "production")
	if err != nil {
		t.Fatal(err)
	}
	f := deploymentPublicationFixture{d: d, now: now, project: r, production: production}
	_, _, access, _ := f.approve(t, nil, "restricted")
	u, err := d.AllocateDeploymentPublication(t.Context(), f.allocation(t, access))
	if err != nil {
		t.Fatal(err)
	}
	_, namespace, _ := strings.Cut(u.CanonicalHostname, ".")
	if namespace != applied.Deployments[0].Namespace || strings.HasSuffix(u.CanonicalHostname, ".www.custom.example.test") || production.Services["web"].PublicURL != "https://www.custom.example.test" {
		t.Fatal("exact saved hostname became the allocation namespace")
	}
}

func TestIntegrationDeploymentSavedPublicURLsBelongToTeamAcrossPublisherReplacement(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "deployment_public_urls")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	if _, err := d.pool.Exec(ctx, `UPDATE control.teams SET kind='organization' WHERE id=$1`, r.TeamID); err != nil {
		t.Fatal(err)
	}
	admin := addAuthorityMember(t, d, now, r.ActorID, r.TeamID, "deployment-admin", TeamRoleAdmin)
	r.ProjectLabel = "shop"
	r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{
		"web": {Protocol: "http", Target: "app", PublicURL: &ProjectServicePublicURL{}, Access: &ProjectServiceAccess{Team: true}},
		"api": {Protocol: "http", Target: "http://api.internal:3000", PublicURL: &ProjectServicePublicURL{Access: &ProjectPublicAccess{Mode: "anonymous"}}},
	}}
	r = selectedProjectRequest(r, "production")
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied.Services) != 2 || len(applied.Deployments) != 1 {
		t.Fatal("saved public URL bindings were not returned")
	}
	namespace := applied.Deployments[0].Namespace
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
	r.Configuration.Services["api"] = ProjectServiceConfiguration{Protocol: "http", Target: "http://replacement.internal:8080", PublicURL: &ProjectServicePublicURL{Access: &ProjectPublicAccess{Mode: "anonymous"}}}
	r.ExpectedRevision = applied.Revision
	applied, err = d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal("lost apply response allocated another URL", err)
	}
	again, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil || again.Revision != applied.Revision {
		t.Fatal("lost apply response was not idempotent", err)
	}
	enrollment, err := testDeploymentPublisherEnrollment(d, ctx, r.TeamID, r.ProjectKey, "production", r.ActorID, 2, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	first := enrollAppliedDeployment(t, d, r, enrollment, now)
	if len(first.assignments.Services) != 1 || first.assignments.Services[0].Kind != "public_url" || first.assignments.Services[0].ServiceID != apiID || first.assignments.Services[0].Hostname != "api."+namespace {
		t.Fatal("installed assignment included an app-owned listener or lost canonical hostname", first.assignments)
	}
	second := enrollAppliedDeployment(t, d, r, enrollment, now)
	if second.assignments.Services[0].ServiceID != apiID || second.member.PublisherIdentityID == first.member.PublisherIdentityID {
		t.Fatal("publisher replacement changed saved URL ownership")
	}
	renamed, err := d.RenameDeployment(ctx, r.TeamID, r.ProjectKey, "production", "live", r.ActorID, applied.Revision, now)
	if err != nil {
		t.Fatal(err)
	}
	current, err := d.GetDeployment(ctx, scope, "live")
	if err != nil || current.Services["web"].ID != webID || current.Services["api"].PublicURL != deployment.Services["api"].PublicURL {
		t.Fatal("selector rename changed saved URL identity or hostname", err)
	}
	_, err = d.RenameDeploymentNamespace(ctx, RenameDeploymentNamespaceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, Deployment: "live", NamespaceLabel: "new-dns", ActorID: r.ActorID, ExpectedRevision: renamed.Revision, IdempotencyKey: "rename-namespace", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	var reusable bool
	if err := d.pool.QueryRow(ctx, `SELECT control.service_namespace_reusable($1,$2)`, namespace, now.Add(8*24*time.Hour)).Scan(&reusable); err != nil || reusable {
		t.Fatal("namespace rename released still-saved URL authority", err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.team_memberships SET removed_at=$2,removed_by_identity_id=$4 WHERE team_id=$1 AND identity_id=$3`, r.TeamID, now, r.ActorID, admin.IdentityID); err != nil {
		t.Fatal(err)
	}
	scope.ActorID = admin.IdentityID
	current, err = d.GetDeployment(ctx, scope, deployment.ID)
	if err != nil || current.Services["web"].ID != webID {
		t.Fatal("creator leaving changed team-owned URL", err)
	}
	if _, err := d.GetDeploymentPublisherAssignments(ctx, first.lease.AccessToken, now); err != nil {
		t.Fatal("creator leaving revoked installed team publisher", err)
	}
	access := deploymentAssignmentAccess(t, d, first, first.assignments.Services[0], now)
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
	f := newDeploymentPublicationFixture(t)
	scope := DeploymentScope{TeamID: f.project.TeamID, ProjectKey: f.project.ProjectKey, ActorID: f.project.ActorID}
	r := f.project
	current, err := f.d.GetProjectConfiguration(t.Context(), r.TeamID, r.ProjectKey, r.ActorID, "staging")
	if err != nil {
		t.Fatal(err)
	}
	r.ExpectedRevision, r.Deployment, r.Configuration = current.Revision, "staging", current.Configuration
	web := r.Configuration.Services["web"]
	web.PublicURL.Hostname = strings.TrimPrefix(f.production.Services["web"].PublicURL, "https://")
	r.Configuration.Services["web"] = web
	if _, err := f.d.ApplyProjectConfiguration(t.Context(), r); !errors.Is(err, ErrPublicURLConflict) {
		t.Fatal("staging adopted production's namespace", err)
	}
	staging, err := f.d.GetDeployment(t.Context(), scope, "staging")
	if err != nil || staging.Services["web"].ID != f.staging.Services["web"].ID || staging.Services["web"].ID == f.production.Services["web"].ID {
		t.Fatal("failed hostname change was not atomic or deployments share a URL", err)
	}
}
