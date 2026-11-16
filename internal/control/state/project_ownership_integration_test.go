package state

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationAppliedProjectLocalRealizationOwnership(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "local_provenance")
	base := oidcRouteRequest(t, d, now)
	ctx := t.Context()
	if _, err := d.pool.Exec(ctx, `UPDATE control.teams SET kind='organization' WHERE id=$1`, base.TeamID); err != nil {
		t.Fatal(err)
	}
	member := addAuthorityMember(t, d, now, base.ActingIdentityID, base.TeamID, "local-reader", TeamRoleMember)
	unrelated, err := d.CreateServiceAt(ctx, base.TeamID, base.ActingIdentityID, "db", "manual-db", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	configuration := ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{
		"db":  {Protocol: "postgres", Target: "localhost:5432", Access: &ProjectServiceAccess{Team: true}},
		"web": {Target: "app", Public: new(true), Access: &ProjectServiceAccess{Team: true}},
	}}
	r := ApplyProjectConfigurationRequest{TeamID: base.TeamID, ProjectKey: "local-project", SourceFingerprint: strings.Repeat("a", 64), ActorID: base.ActingIdentityID, Configuration: configuration, Now: now}
	r = selectedProjectRequest(r, "local")
	local := RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: "db", WorktreeKey: "checkout-a", ActorID: r.ActorID, Configuration: configuration.Services["db"], Now: now}
	first, err := d.RealizeLocalProjectService(ctx, local)
	if err != nil {
		t.Fatal(err)
	}
	if first.ServiceID == unrelated.ID || first.Metadata == nil {
		t.Fatal("local runtime adopted an unrelated name")
	}
	retry, err := d.RealizeLocalProjectService(ctx, local)
	if err != nil || retry.ServiceID != first.ServiceID {
		t.Fatal("realization retry changed private ID", err)
	}
	local.WorktreeKey = "checkout-b"
	second, err := d.RealizeLocalProjectService(ctx, local)
	if err != nil || second.ServiceID == first.ServiceID {
		t.Fatal("worktrees share a service", err)
	}
	local.Service, local.WorktreeKey, local.Configuration = "web", "checkout-a", configuration.Services["web"]
	public, err := d.RealizeLocalProjectService(ctx, local)
	if err != nil {
		t.Fatal(err)
	}
	spoof := local
	spoof.ProjectKey = "another-project"
	spoof.Configuration.Hostname = public.Hostname
	if _, err = d.RealizeLocalProjectService(ctx, spoof); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("public service hostname adopted by unrelated project", err)
	}
	status, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal("first apply collided with legitimate startup", err)
	}
	for _, s := range status.Services {
		if s.Kind != "local" || s.ServiceID != "" {
			t.Fatal("apply allocated a shared local resource")
		}
	}
	var count int
	if err = d.pool.QueryRow(ctx, `SELECT count(*) FROM control.services WHERE team_id=$1 AND deleted_at IS NULL`, r.TeamID).Scan(&count); err != nil || count != 4 {
		t.Fatal("apply duplicated local service", count, err)
	}
	if _, err = d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, member.IdentityID, "local"); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("member read manager configuration", err)
	}
	if _, err = d.ConfigureService(ctx, first.ServiceID, r.ActorID, *first.Metadata, nil, ServiceUpdateConditions{}, now); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("direct managed definition changed", err)
	}
	if _, err = d.ConfigureService(ctx, first.ServiceID, r.ActorID, *first.Metadata,
		&ProjectServiceConfiguration{Target: "localhost:4000"}, ServiceUpdateConditions{UnconditionalConfiguration: true}, now); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("explicit declaration bypassed project management", err)
	}
	if err = d.DeleteService(ctx, first.ServiceID, r.ActorID, now); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("public service deleted", err)
	}
	var configuredGrant string
	if err = d.pool.QueryRow(ctx, `SELECT visitor_grant_id FROM control.local_project_services WHERE service_id=$1`, first.ServiceID).Scan(&configuredGrant); err != nil {
		t.Fatal(err)
	}
	if err = d.RevokeServiceGrant(ctx, first.ServiceID, r.ActorID, configuredGrant, now); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("configured team grant revoked directly", err)
	}
	extra, err := d.CreateServiceGrant(ctx, first.ServiceID, r.ActorID, "extra-visitor", "identity", member.IdentityID, nil, now)
	if err != nil {
		t.Fatal("extra visitor grant was blanket denied", err)
	}
	if err = d.RevokeServiceGrant(ctx, first.ServiceID, r.ActorID, extra.ID, now); err != nil {
		t.Fatal(err)
	}
	var publicGrant string
	if err = d.pool.QueryRow(ctx, `SELECT visitor_grant_id FROM control.local_project_services WHERE service_id=$1`, public.ServiceID).Scan(&publicGrant); err != nil {
		t.Fatal(err)
	}
	if err = d.RevokeServiceGrant(ctx, public.ServiceID, r.ActorID, publicGrant, now); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("configured local public team grant revoked directly", err)
	}
	r.ExpectedRevision = status.Revision
	r.Configuration = status.Configuration
	for key, s := range r.Configuration.Services {
		s.Access = nil
		r.Configuration.Services[key] = s
	}
	if _, err = d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	for _, grant := range []string{configuredGrant, extra.ID} {
		var revoked bool
		if err = d.pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM control.visitor_grants WHERE id=$1`, grant).Scan(&revoked); err != nil || !revoked {
			t.Fatal("apply restored revoked or removed access", err)
		}
	}
	var revoked bool
	if err = d.pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM control.visitor_grants WHERE id=$1`, publicGrant).Scan(&revoked); err != nil || !revoked {
		t.Fatal("apply did not remove local public team access", err)
	}
	local.Configuration = r.Configuration.Services["web"]
	if _, err = d.RealizeLocalProjectService(ctx, local); err != nil {
		t.Fatal("restart after access removal", err)
	}
	if err = d.pool.QueryRow(ctx, `SELECT count(*) FROM control.visitor_grants WHERE service_id=$1 AND kind='team' AND revoked_at IS NULL`, public.ServiceID).Scan(&count); err != nil || count != 0 {
		t.Fatal("restart restored removed team access", count, err)
	}
	if _, err = d.GetProjectPublicMetadata(ctx, r.TeamID, r.ProjectKey, member.IdentityID, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("removed team access still exposed local public metadata", err)
	}
	local.SourceFingerprint = strings.Repeat("b", 64)
	if _, err = d.RealizeLocalProjectService(ctx, local); !errors.Is(err, ErrProjectSourceConflict) {
		t.Fatal("source conflict accepted", err)
	}
}

func TestIntegrationAppliedProjectLocalEphemeralRealizationAfterExpiry(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "local_ephemeral")
	r := oidcRouteRequest(t, d, now)
	local := RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: "ephemeral", SourceFingerprint: strings.Repeat("a", 64), Service: "web", WorktreeKey: "checkout", ActorID: r.ActingIdentityID, Configuration: ProjectServiceConfiguration{Target: "app", Public: new(true), Ephemeral: true, Access: &ProjectServiceAccess{Team: true}}, Now: now}
	first, err := d.RealizeLocalProjectService(t.Context(), local)
	if err != nil {
		t.Fatal(err)
	}
	local.Configuration.Hostname = "other." + first.Hostname
	if _, err := d.RealizeLocalProjectService(t.Context(), local); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("healthy local binding was silently replaced", err)
	}
	// idle ephemeral services expire through the same owner as service runs.
	expiredAt := now.Add(2*time.Minute + time.Second)
	if _, err := d.ExpireServiceRuns(t.Context(), expiredAt); err != nil {
		t.Fatal("runtime expiry failed", err)
	}
	var deleted bool
	if err := d.pool.QueryRow(t.Context(), `SELECT deleted_at IS NOT NULL FROM control.services WHERE id=$1`, first.ServiceID).Scan(&deleted); err != nil || !deleted {
		t.Fatal("runtime expiry did not delete the old ephemeral service", deleted, err)
	}
	local.Now, local.Configuration.Hostname = expiredAt, ""
	realized, err := d.RealizeLocalProjectService(t.Context(), local)
	if err != nil || realized.ServiceID == first.ServiceID || realized.Hostname != first.Hostname {
		t.Fatal("expired worktree binding prevented restart", err)
	}
	var active int
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.visitor_grants WHERE service_id=$1 AND kind='team' AND revoked_at IS NULL`, first.ServiceID).Scan(&active); err != nil || active != 0 {
		t.Fatal("expiry replacement left the old team grant active", err)
	}
}

func TestIntegrationAppliedProjectLocalPublicationRequirements(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "local_publication_requirements")
	r := appliedProjectRequest(t, d, now)
	local := RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint,
		Service: "web", WorktreeKey: "checkout", ActorID: r.ActorID, Now: now}
	var id string
	var trustRevision int64
	for _, step := range []struct {
		require   *bool
		want      bool
		ephemeral bool
	}{
		{new(true), true, true},
		{nil, true, true},
		{new(false), false, false},
	} {
		local.Configuration = ProjectServiceConfiguration{Target: "app", Ephemeral: step.ephemeral, RequirePostQuantum: step.require}
		realized, err := d.RealizeLocalProjectService(t.Context(), local)
		if err != nil {
			t.Fatal(err)
		}
		row, err := controlstatedb.New(d.pool).GetService(t.Context(), realized.ServiceID)
		if err != nil || row.RequirePostQuantum != step.want || row.Ephemeral != step.ephemeral || row.ExpiresAt.Valid {
			t.Fatal("direct publication settings were dropped, reset, or given an implicit hard expiry", err)
		}
		if id == "" {
			id, trustRevision = row.ID, row.TrustRevision
		} else if row.ID != id || row.TrustRevision != trustRevision {
			t.Fatal("visitor TLS or ephemeral settings changed service identity or target trust")
		}
	}
}

func TestIntegrationAppliedProjectManagedDeploymentGrantsAndSafeMetadata(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "managed_projection")
	d.managedURLMode = naming.ManagedURLModeSimple
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{
		"public": {Target: "http://secret.internal:3000", Access: &ProjectServiceAccess{Team: true}},
		"db":     {Protocol: "postgres", Target: "db.internal:5432"},
	}}
	r = selectedProjectRequest(r, "production")
	status, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	var publicID string
	for _, s := range status.Services {
		if s.Service == "public" {
			publicID = s.ServiceID
		}
	}
	if err = d.DeleteService(t.Context(), publicID, r.ActorID, now); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("public service deletion succeeded", err)
	}
	if !strings.HasPrefix(publicID, "svc_") {
		t.Fatal("HTTP declaration did not produce an ordinary service")
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.teams SET kind='organization' WHERE id=$1`, r.TeamID); err != nil {
		t.Fatal(err)
	}
	member := addAuthorityMember(t, d, now, r.ActorID, r.TeamID, "metadata-reader", TeamRoleMember)
	projection, err := d.GetProjectPublicMetadata(t.Context(), r.TeamID, r.ProjectKey, member.IdentityID, now)
	if !errors.Is(err, ErrServiceAccess) || len(projection.Services) != 0 {
		t.Fatal("managed access granted public URL metadata permission", projection, err)
	}
	encoded, _ := json.Marshal(projection)
	for _, value := range []string{"configuration", "target", "secret.internal", "db.internal", "grant", "publisher", "tls"} {
		if strings.Contains(string(encoded), value) {
			t.Fatal("projection leaked manager data", value)
		}
	}
	if _, err = d.GetProjectConfiguration(t.Context(), r.TeamID, r.ProjectKey, member.IdentityID, "production"); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("visitor read full configuration", err)
	}
	outsider := finalVisitorIdentity(t, d, now, "projection-outsider@example.test")
	if _, err = d.GetProjectPublicMetadata(t.Context(), r.TeamID, r.ProjectKey, outsider, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("ungranted visitor read project source", err)
	}
	e, err := testDeploymentPublisherEnrollment(d, t.Context(), r.TeamID, r.ProjectKey, "production", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedDeployment(t, d, r, e, now)
	a := replica.assignments.Services[0]
	if err = d.RevokePublisherGrant(t.Context(), r.TeamID, replica.member.PublisherIdentityID, a.GrantID, r.ActorID, now); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("managed deployment grant revoked directly", err)
	}
	if current, e := d.GetDeploymentPublisherAssignments(t.Context(), replica.lease.AccessToken, now); e != nil || len(current.Services) != 2 {
		t.Fatal("guard disturbed deployment poll", e)
	}
	// legacy or exceptional revoked state must not be silently recreated by an
	// unrelated apply, and must not turn healthy sibling assignments into 401.
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.publisher_grants SET revoked_at=$2 WHERE id=$1`, a.GrantID, now); err != nil {
		t.Fatal(err)
	}
	r.ExpectedRevision = status.Revision
	r.Configuration = status.Configuration
	r.Configuration.Settings = &DeploymentSettings{Description: "updated description"}
	if _, err = d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	current, err := d.GetDeploymentPublisherAssignments(t.Context(), replica.lease.AccessToken, now)
	if err != nil || len(current.Services) != 1 {
		t.Fatal("one revoked grant broke sibling poll", current, err)
	}
	var grant string
	if err = d.pool.QueryRow(t.Context(), `SELECT grant_id FROM control.deployment_publisher_service_grants WHERE publisher_identity_id=$1 AND service=$2`, replica.member.PublisherIdentityID, a.Service).Scan(&grant); err != nil || grant != a.GrantID {
		t.Fatal("unrelated apply recreated revoked grant", err)
	}
	if err = d.RevokeDeploymentPublisher(t.Context(), DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}, "production", replica.member.PublisherIdentityID, now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.GetDeploymentPublisherAssignments(t.Context(), replica.lease.AccessToken, now); !errors.Is(err, ErrDeploymentPublisher) {
		t.Fatal("operational revoke was not immediate", err)
	}
}

func TestIntegrationPrivateVisitorAssignmentReleaseIsExact(t *testing.T) {
	// the selector remains for the service Task. connector owners do not release
	// ingress handles; exact-owner replacement must leave every sibling intact.
	f := newConnectorPairFixture(t)
	first := f.create(t)
	assertNativeStateStableOwners(t, f.d, f.visitor, f.request, f.key, f.run, f.now)
	if retry, err := f.d.PrepareConnectorPeerPair(f.visitor, f.request, f.now); err != nil || retry.ID != first.ID || retry.Key != first.Key {
		t.Fatal("sibling replacement changed the original owner", err)
	}
}
