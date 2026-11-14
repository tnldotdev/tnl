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
	domain := deploymentCustomDomain(t, d, r, now)
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

func deploymentCustomDomain(t *testing.T, d *Database, r ApplyProjectConfigurationRequest, now time.Time) Domain {
	t.Helper()
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
	return domain
}

func TestIntegrationDeploymentExactHostnamePreservesMemberSlugReservations(t *testing.T) {
	for _, state := range []string{"invited", "quarantined"} {
		t.Run(state, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "deployment_reserved_hostname")
			r := appliedProjectRequest(t, d, now)
			if _, err := d.pool.Exec(t.Context(), `UPDATE control.teams SET kind='organization' WHERE id=$1`, r.TeamID); err != nil {
				t.Fatal(err)
			}
			domain := deploymentCustomDomain(t, d, r, now)
			var invitation InvitationSecret
			if state == "invited" {
				var err error
				invitation, err = d.CreateTeamInvitation(t.Context(), authorityInvitationRequest(r.ActorID, r.TeamID, "alice", now), now)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				member := addAuthorityMember(t, d, now, r.ActorID, r.TeamID, "alice", TeamRoleMember)
				if err := d.RemoveMembership(t.Context(), r.ActorID, r.TeamID, member.ID, now); err != nil {
					t.Fatal(err)
				}
			}
			for _, hostname := range []string{"alice.custom.example.test", "app.alice.custom.example.test", "api.app.alice.custom.example.test"} {
				r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{DomainID: domain.ID}, Services: map[string]ProjectServiceConfiguration{
					"web": {Target: "app", PublicURL: &ProjectServicePublicURL{Hostname: hostname, DomainID: domain.ID}},
				}}
				r = selectedProjectRequest(r, "production")
				if _, err := d.ApplyProjectConfiguration(t.Context(), r); !errors.Is(err, ErrPublicURLConflict) {
					t.Fatal("deployment claimed a reserved member namespace", hostname, err)
				}
				var count int
				if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.public_urls WHERE team_id=$1`, r.TeamID).Scan(&count); err != nil || count != 0 {
					t.Fatal("denied apply saved a public URL", count, err)
				}
			}
			if state == "invited" {
				if err := d.RevokeTeamInvitation(t.Context(), r.ActorID, r.TeamID, invitation.Invitation.ID, now); err != nil {
					t.Fatal(err)
				}
				if _, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil {
					t.Fatal("released invitation still blocked the shared hostname", err)
				}
			}
		})
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

func TestIntegrationDeploymentBindingChangesRetireCredentialRunsWithoutRevokingApproval(t *testing.T) {
	for _, mutation := range []string{"apply-target", "runtime-target", "apply-access", "apply-post-quantum"} {
		t.Run(mutation, func(t *testing.T) {
			f := newDeploymentPublicationFixture(t)
			d, ctx, now := f.d, t.Context(), f.now
			scope := DeploymentScope{TeamID: f.project.TeamID, ProjectKey: f.project.ProjectKey, ActorID: f.project.ActorID}
			current, err := d.GetProjectConfiguration(ctx, scope.TeamID, scope.ProjectKey, scope.ActorID, "production")
			if err != nil {
				t.Fatal(err)
			}
			r := f.project
			r.ExpectedRevision, r.Configuration = current.Revision, current.Configuration
			web := r.Configuration.Services["web"]
			web.Target = "http://original.internal:3000"
			r.Configuration.Services["web"] = web
			applied, err := d.ApplyProjectConfiguration(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			f.production, err = d.GetDeployment(ctx, scope, "production")
			if err != nil {
				t.Fatal(err)
			}
			_, _, _, leases := publishRunPrerequisitesInDatabase(t, d, now, nil)
			registration, key := managementRegistration(t, scope, now)
			registration.Permissions = map[string][]string{"publish": {"web", "api"}}
			registration.TemporaryPublication = "restricted"
			credential, err := d.RegisterDeploymentCredential(ctx, registration)
			if err != nil {
				t.Fatal(err)
			}
			access := managementAccess(t, d, credential, key, now)
			start := func(deployment, service string) publishRunFixture {
				t.Helper()
				publication, err := d.GetDeploymentPublication(ctx, f.scope(access), deployment, service, now)
				if err != nil {
					t.Fatal(err)
				}
				request := reviewRunRequest(t, d, access.PublisherIdentity, key, publication.PublicURL, deployment+"/"+service)
				run, err := d.CreatePublishRun(ctx, request, now, time.Minute, time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				return publishRunFixture{database: d, now: now, request: request, setup: run, leases: leases}
			}
			old := start("production", "web")
			claims := readyTestSession(t, old)
			siblingService, siblingDeployment := start("production", "api"), start("staging", "web")
			temporaryURL, err := d.AllocateDeploymentPublication(ctx, f.allocation(t, access))
			if err != nil {
				t.Fatal(err)
			}
			temporaryRequest := reviewRunRequest(t, d, access.PublisherIdentity, key, temporaryURL, "temporary")
			temporary, err := d.CreatePublishRun(ctx, temporaryRequest, now, time.Minute, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			r.ExpectedRevision = applied.Revision
			if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
				t.Fatal("unchanged apply failed", err)
			}
			if _, err := d.HeartbeatPublishRun(ctx, old.authentication(), now, time.Minute, time.Minute); err != nil {
				t.Fatal("unchanged apply retired a run", err)
			}
			expectedTarget := web.Target
			switch mutation {
			case "runtime-target":
				f.production, err = d.UpdateDeployment(ctx, UpdateDeploymentRequest{DeploymentScope: scope, Selector: f.production.ID, ExpectedRevision: f.production.Revision, Targets: map[string]DeploymentTarget{"web": {Address: "http://replacement.internal:8080"}}, Now: now})
				expectedTarget = "http://replacement.internal:8080"
			default:
				switch mutation {
				case "apply-target":
					web.Target = "http://replacement.internal:8080"
					expectedTarget = web.Target
				case "apply-access":
					web.PublicURL.Access.Mode = "restricted"
				case "apply-post-quantum":
					web.PublicURL.RequirePostQuantum = new(true)
				}
				r.Configuration.Services["web"] = web
				_, err = d.ApplyProjectConfiguration(ctx, r)
			}
			if err != nil {
				t.Fatal("binding mutation failed", err)
			}
			q := controlstatedb.New(d.pool)
			retired, err := q.GetPublishRun(ctx, old.setup.PublishRunID)
			if err != nil || !retired.ClosedAt.Valid || retired.State != "closed" || retired.CloseReason.String != "configuration_changed" {
				t.Fatal("binding mutation retained the old credential run", err)
			}
			var openSlots, tombstones int
			if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.publish_run_connection_slots WHERE publish_run_id=$1 AND (state<>'closed' OR closed_at IS NULL)`, old.setup.PublishRunID).Scan(&openSlots); err != nil || openSlots != 0 {
				t.Fatal("binding mutation retained old assignments", openSlots, err)
			}
			if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.ingress_routing_table_events WHERE public_url_id=$1 AND publish_run_number=$2 AND event_kind='public_url_tombstone'`, old.setup.PublicURLID, old.setup.PublishRunNumber).Scan(&tombstones); err != nil || tombstones != 1 {
				t.Fatal("binding mutation did not retire the old ingress entry", tombstones, err)
			}
			if _, err := d.HeartbeatPublishRun(ctx, old.authentication(), now, time.Minute, time.Minute); !errors.Is(err, ErrPublishRunStale) {
				t.Fatal("old run renewed after the binding changed", err)
			}
			if _, err := d.MarkPublisherConnectionReady(ctx, claims[0], now); err == nil {
				t.Fatal("old assignment became ready after the binding changed")
			}
			if _, err := d.CreateCertificateIssuance(ctx, newTestIssuanceRequest(t, old), now); !errors.Is(err, ErrPublishRunStale) {
				t.Fatal("old run retained certificate authority", err)
			}
			for _, sibling := range []publishRunFixture{siblingService, siblingDeployment, {setup: temporary}} {
				if _, err := d.HeartbeatPublishRun(ctx, sibling.authentication(), now, time.Minute, time.Minute); err != nil {
					t.Fatal("binding mutation retired an unrelated run using the same approval", err)
				}
			}
			var approved bool
			if err := d.pool.QueryRow(ctx, `SELECT approval.revoked_at IS NULL AND selected.revoked_at IS NULL
				FROM control.publisher_grants approval JOIN control.deployment_management_services selected ON selected.grant_id=approval.id
				WHERE approval.id=$1 AND selected.capability='publish' AND selected.service='web'`, credential.GrantID).Scan(&approved); err != nil || !approved {
				t.Fatal("binding mutation revoked reusable publication approval", err)
			}
			publication, err := d.GetDeploymentPublication(ctx, f.scope(access), "production", "web", now)
			if err != nil || publication.PublicURL.ID != old.setup.PublicURLID || publication.PublicURL.Target != expectedTarget {
				t.Fatal("named publication did not return the updated binding", err)
			}
			if mutation == "apply-access" && publication.PublicURL.AccessMode != VisitorAccessRestricted ||
				mutation == "apply-post-quantum" && !publication.PublicURL.RequirePostQuantum {
				t.Fatal("named publication did not retain the new policy")
			}
			replacementRequest := reviewRunRequest(t, d, access.PublisherIdentity, key, publication.PublicURL, "replacement")
			replacement, err := d.CreatePublishRun(ctx, replacementRequest, now, time.Minute, time.Minute)
			if err != nil || replacement.PublishRunID == old.setup.PublishRunID || replacement.PublishRunNumber != old.setup.PublishRunNumber+1 {
				t.Fatal("reusable approval could not start a replacement run", err)
			}
			if _, err := d.HeartbeatPublishRun(ctx, (publishRunFixture{setup: replacement}).authentication(), now, time.Minute, time.Minute); err != nil {
				t.Fatal("replacement run was not current", err)
			}
		})
	}
}
