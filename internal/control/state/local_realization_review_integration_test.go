package state

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationAppliedProjectPersonalSharedLocalRealization(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "local_shared_personal")
	d.managedURLMode = naming.ManagedURLModeSimple
	r := oidcRouteRequest(t, d, now)
	domain, err := d.ClaimTeamDomain(t.Context(), ClaimDomainRequest{TeamID: r.TeamID, IdentityID: r.ActingIdentityID, Domain: "custom.example.test", IdempotencyKey: "custom", RequestDigest: sha256.Sum256([]byte("custom"))}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.domains SET state='ready',verified_at=$2 WHERE id=$1`, domain.ID, now); err != nil {
		t.Fatal(err)
	}
	local := RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: "personal", SourceFingerprint: strings.Repeat("a", 64), Service: "web", WorktreeKey: "checkout", ActorID: r.ActingIdentityID, Configuration: ProjectServiceConfiguration{Target: "app", Public: new(true), Hostname: "web.custom.example.test", DomainID: domain.ID, Access: &ProjectServiceAccess{Team: true}}, Now: now}
	var service LocalProjectService
	for range 2 {
		realized, err := d.RealizeLocalProjectService(t.Context(), local)
		if err != nil || realized.Hostname != local.Configuration.Hostname || service.ServiceID != "" && realized.ServiceID != service.ServiceID {
			t.Fatal("personal simple-mode service identity changed or was rejected", realized, err)
		}
		service = realized
	}
	projection, err := d.GetProjectPublicMetadata(t.Context(), r.TeamID, local.ProjectKey, r.ActingIdentityID, now)
	if err != nil || projection.SourceFingerprint != local.SourceFingerprint || len(projection.Services) != 1 || projection.Services[0].ServiceID != service.ServiceID {
		t.Fatal("startup metadata before first apply lost the realized service", projection, err)
	}
	if _, err = d.ConfigureService(t.Context(), service.ServiceID, r.ActingIdentityID, *service.Metadata, nil, ServiceUpdateConditions{}, now); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("shared realization lost definition ownership", err)
	}
	if err = d.DeleteService(t.Context(), service.ServiceID, r.ActingIdentityID, observedServiceDeletion(t, d, service.ServiceID), now); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("shared realization lost definition ownership", err)
	}
	otherTeam, err := d.CreateTeam(t.Context(), authorityTeamRequest(r.ActingIdentityID), now)
	if err != nil {
		t.Fatal(err)
	}
	spoof := local
	spoof.TeamID = otherTeam.ID
	if _, err = d.RealizeLocalProjectService(t.Context(), spoof); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("service hostname was adopted by another team", err)
	}
	// another manager's organization/shared URL must not become local merely
	// because the caller created it. its current namespace must select shared.
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.teams SET kind='organization' WHERE id=$1`, r.TeamID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.RealizeLocalProjectService(t.Context(), local); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("organization shared URL was adopted", err)
	}
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.teams SET kind='personal' WHERE id=$1`, r.TeamID); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationAppliedProjectLocalProjectionAndMemberBinding(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "local_projection")
	r := oidcRouteRequest(t, d, now)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.teams SET kind='organization' WHERE id=$1`, r.TeamID); err != nil {
		t.Fatal(err)
	}
	member := addAuthorityMember(t, d, now, r.ActingIdentityID, r.TeamID, "projection-reader", TeamRoleMember)
	local := RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: "local", SourceFingerprint: strings.Repeat("a", 64), Service: "web", WorktreeKey: "checkout-a", ActorID: r.ActingIdentityID, Configuration: ProjectServiceConfiguration{Target: "app", Public: new(true), Access: &ProjectServiceAccess{Team: true}}, Now: now}
	for _, worktree := range []string{"checkout-a", "checkout-b"} {
		// the existing generated member namespace is shared by both worktrees,
		// while service IDs and captured hostnames remain independent.
		var label string
		if err := d.pool.QueryRow(t.Context(), `SELECT managed_label FROM control.team_memberships WHERE id=$1`, r.MembershipID).Scan(&label); err != nil {
			t.Fatal(err)
		}
		local.WorktreeKey = worktree
		local.Configuration.Hostname = worktree + "." + label + ".tunnels.example.test"
		if _, err := d.RealizeLocalProjectService(t.Context(), local); err != nil {
			t.Fatal(err)
		}
	}
	projection, err := d.GetProjectPublicMetadata(t.Context(), r.TeamID, local.ProjectKey, member.IdentityID, now)
	if err != nil || len(projection.Services) != 2 || projection.Services[0].ServiceID == projection.Services[1].ServiceID || projection.Services[0].Hostname == projection.Services[1].Hostname {
		t.Fatal("ordinary member lost authorized realized worktree services", projection, err)
	}
	if _, err = d.GetProjectConfiguration(t.Context(), r.TeamID, local.ProjectKey, member.IdentityID, "local"); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("local visitor read full configuration", err)
	}
	// even a same-team manager cannot bind a different member's saved URL.
	other := addAuthorityMember(t, d, now, r.ActingIdentityID, r.TeamID, "another-owner", TeamRoleAdmin)
	spoof := local
	spoof.ActorID = other.IdentityID
	spoof.WorktreeKey = "other"
	if _, err = d.RealizeLocalProjectService(t.Context(), spoof); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("manager adopted another member's hostname", err)
	}
	// matching created_by is insufficient when the namespace claim disagrees
	// with the service's captured membership owner.
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.service_namespace_claims SET membership_id=$2 WHERE namespace=$1`, local.Configuration.Hostname, other.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.RealizeLocalProjectService(t.Context(), local); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("member binding was ignored", err)
	}
}
