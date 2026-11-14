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
	r.PublicURLScope, r.MembershipID, r.ManagedURLMode = PublicURLScopeShared, "", naming.ManagedURLModeSimple
	domain, err := d.ClaimTeamDomain(t.Context(), ClaimDomainRequest{TeamID: r.TeamID, IdentityID: r.ActingIdentityID, Domain: "custom.example.test", IdempotencyKey: "custom", RequestDigest: sha256.Sum256([]byte("custom"))}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.domains SET state='ready',verified_at=$2 WHERE id=$1`, domain.ID, now); err != nil {
		t.Fatal(err)
	}
	r.DomainID = domain.ID
	r.CanonicalHostname = "web.custom.example.test"
	u := createTestPublicURL(t, d, r, now)
	local := RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: "personal", SourceFingerprint: strings.Repeat("a", 64), Service: "web", WorktreeKey: "checkout", ActorID: r.ActingIdentityID, PublicURLID: u.ID, Configuration: ProjectServiceConfiguration{Target: "app", PublicURL: &ProjectServicePublicURL{}, Access: &ProjectServiceAccess{Team: true}}, Now: now}
	for range 2 {
		realized, err := d.RealizeLocalProjectService(t.Context(), local)
		if err != nil || realized.ServiceID != u.ID {
			t.Fatal("personal simple-mode runtime URL was rejected", realized, err)
		}
	}
	projection, err := d.GetProjectPublicMetadata(t.Context(), r.TeamID, local.ProjectKey, r.ActingIdentityID, now)
	if err != nil || projection.SourceFingerprint != local.SourceFingerprint || len(projection.Services) != 1 ||
		projection.Services[0].PublicURLID != u.ID || projection.Services[0].Hostname != u.CanonicalHostname || projection.Services[0].Port != u.Port {
		t.Fatal("startup metadata before first apply lost the realized URL", projection, err)
	}
	if _, err = d.ReplaceVisitorAccess(t.Context(), u.ID, r.ActingIdentityID, VisitorAccessAnonymous, nil, u.MutationRevision, now); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("shared realization lost access definition ownership", err)
	}
	if err = d.DeletePublicURL(t.Context(), r.ActingIdentityID, u.ID, now); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("shared realization lost definition ownership", err)
	}
	otherTeam, err := d.CreateTeam(t.Context(), authorityTeamRequest(r.ActingIdentityID), now)
	if err != nil {
		t.Fatal(err)
	}
	spoof := local
	spoof.TeamID = otherTeam.ID
	if _, err = d.RealizeLocalProjectService(t.Context(), spoof); !errors.Is(err, ErrPublicURLAccess) {
		t.Fatal("URL was adopted by another team", err)
	}
	// another manager's organization/shared URL must not become local merely
	// because the caller created it. its current namespace must select shared.
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.teams SET kind='organization' WHERE id=$1`, r.TeamID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.RealizeLocalProjectService(t.Context(), local); !errors.Is(err, ErrPublicURLAccess) {
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
	local := RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: "local", SourceFingerprint: strings.Repeat("a", 64), Service: "web", WorktreeKey: "checkout-a", ActorID: r.ActingIdentityID, Configuration: ProjectServiceConfiguration{Target: "app", PublicURL: &ProjectServicePublicURL{}, Access: &ProjectServiceAccess{Team: true}}, Now: now}
	endpoints := make(map[string]PublicURL)
	for _, worktree := range []string{"checkout-a", "checkout-b"} {
		r.IdempotencyKey = worktree
		r.RequestDigest = sha256.Sum256([]byte(worktree))
		// the existing generated member namespace is shared by both worktrees,
		// while immutable public URL IDs and hostnames remain independent.
		var label string
		if err := d.pool.QueryRow(t.Context(), `SELECT managed_label FROM control.team_memberships WHERE id=$1`, r.MembershipID).Scan(&label); err != nil {
			t.Fatal(err)
		}
		r.CanonicalHostname = worktree + "." + label + ".tunnels.example.test"
		u := createTestPublicURL(t, d, r, now)
		endpoints[u.ID] = u
		local.WorktreeKey, local.PublicURLID = worktree, u.ID
		if _, err := d.RealizeLocalProjectService(t.Context(), local); err != nil {
			t.Fatal(err)
		}
		for _, actor := range []string{r.ActingIdentityID, member.IdentityID} {
			bound, err := d.GetLocalProjectService(t.Context(), GetLocalProjectServiceRequest{
				TeamID: r.TeamID, ProjectKey: local.ProjectKey, SourceFingerprint: local.SourceFingerprint,
				Service: local.Service, WorktreeKey: worktree, ActorID: actor, Now: now,
			})
			if err != nil || bound.Kind != "public_url" || bound.ServiceID != u.ID || bound.Hostname != u.CanonicalHostname || bound.Metadata != nil {
				t.Fatal("local lookup did not return the exact authorized public URL binding", bound, err)
			}
		}
	}
	projection, err := d.GetProjectPublicMetadata(t.Context(), r.TeamID, local.ProjectKey, member.IdentityID, now)
	if err != nil || len(projection.Services) != 2 || projection.Services[0].PublicURLID == projection.Services[1].PublicURLID {
		t.Fatal("ordinary member lost authorized realized worktree URLs", projection, err)
	}
	for _, service := range projection.Services {
		saved, ok := endpoints[service.PublicURLID]
		if !ok || service.Hostname != saved.CanonicalHostname || service.Port != saved.Port {
			t.Fatal("worktree metadata changed the saved public endpoint", service)
		}
	}
	lookup := GetLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: local.ProjectKey, SourceFingerprint: strings.Repeat("b", 64),
		Service: local.Service, WorktreeKey: local.WorktreeKey, ActorID: member.IdentityID, Now: now}
	if bound, err := d.GetLocalProjectService(t.Context(), lookup); !errors.Is(err, ErrProjectSourceConflict) || bound.ServiceID != "" || bound.Hostname != "" {
		t.Fatal("authorized public URL lookup ignored its source binding or returned resource facts", err)
	}
	lookup.ActorID = finalVisitorIdentity(t, d, now, "ungranted-local-reader@example.test")
	if bound, err := d.GetLocalProjectService(t.Context(), lookup); !errors.Is(err, ErrServiceAccess) || bound.ServiceID != "" || bound.Hostname != "" {
		t.Fatal("unauthorized public URL lookup revealed source provenance", err)
	}
	lookup.ActorID, lookup.SourceFingerprint, lookup.WorktreeKey = r.ActingIdentityID, local.SourceFingerprint, "unrealized"
	if _, err := d.GetLocalProjectService(t.Context(), lookup); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("local public URL lookup searched another worktree", err)
	}
	if _, err = d.GetProjectConfiguration(t.Context(), r.TeamID, local.ProjectKey, member.IdentityID, "local"); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("local visitor read full configuration", err)
	}
	// even a same-team manager cannot bind a different member's saved URL.
	other := addAuthorityMember(t, d, now, r.ActingIdentityID, r.TeamID, "another-owner", TeamRoleAdmin)
	spoof := local
	spoof.ActorID = other.IdentityID
	spoof.WorktreeKey = "other"
	if _, err = d.RealizeLocalProjectService(t.Context(), spoof); !errors.Is(err, ErrPublicURLAccess) {
		t.Fatal("manager adopted another member's URL", err)
	}
	// matching created_by is insufficient if the immutable membership binding
	// points at a different member (including a corrupt or old imported row).
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.public_urls SET membership_id=$2 WHERE id=$1`, local.PublicURLID, other.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.RealizeLocalProjectService(t.Context(), local); !errors.Is(err, ErrPublicURLAccess) {
		t.Fatal("member binding was ignored", err)
	}
}

func TestIntegrationLocalPublicLookupRetainsUnavailableBinding(t *testing.T) {
	for _, lifecycle := range []string{"suspended", "deleted"} {
		t.Run(lifecycle, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "local_unavailable")
			r := oidcRouteRequest(t, d, now)
			if _, err := d.pool.Exec(t.Context(), `UPDATE control.teams SET kind='organization' WHERE id=$1`, r.TeamID); err != nil {
				t.Fatal(err)
			}
			member := addAuthorityMember(t, d, now, r.ActingIdentityID, r.TeamID, "reader", TeamRoleMember)
			u := createTestPublicURL(t, d, r, now)
			local := RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: "retained", SourceFingerprint: strings.Repeat("a", 64),
				Service: "web", WorktreeKey: "checkout", ActorID: r.ActingIdentityID, PublicURLID: u.ID, Now: now,
				Configuration: ProjectServiceConfiguration{Target: "app", PublicURL: &ProjectServicePublicURL{}, Access: &ProjectServiceAccess{Team: true}}}
			if _, err := d.RealizeLocalProjectService(t.Context(), local); err != nil {
				t.Fatal(err)
			}
			query := `UPDATE control.public_urls SET lifecycle_state='suspended',suspended_at=$2 WHERE id=$1`
			if lifecycle == "deleted" {
				query = `UPDATE control.public_urls SET lifecycle_state='deleted',deleted_at=$2,request_digest_ciphertext=NULL,request_digest_storage_key_id=NULL WHERE id=$1`
			}
			if _, err := d.pool.Exec(t.Context(), query, u.ID, now); err != nil {
				t.Fatal(err)
			}
			lookup := GetLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: local.ProjectKey, SourceFingerprint: local.SourceFingerprint,
				Service: local.Service, WorktreeKey: local.WorktreeKey, ActorID: r.ActingIdentityID, Now: now}
			if bound, err := d.GetLocalProjectService(t.Context(), lookup); !errors.Is(err, ErrProjectConfigurationStale) || bound.ServiceID != "" || bound.Hostname != "" {
				t.Fatal("creator could replace an unavailable bound public URL or read resource facts", err)
			}
			lookup.ActorID = member.IdentityID
			if bound, err := d.GetLocalProjectService(t.Context(), lookup); !errors.Is(err, ErrServiceAccess) || bound.ServiceID != "" || bound.Hostname != "" {
				t.Fatal("visitor learned an unavailable binding", err)
			}
			var retained string
			if err := d.pool.QueryRow(t.Context(), `SELECT public_url_id FROM control.local_project_services WHERE team_id=$1 AND project_key=$2 AND service=$3 AND worktree_key=$4`,
				local.TeamID, local.ProjectKey, local.Service, local.WorktreeKey).Scan(&retained); err != nil || retained != u.ID {
				t.Fatal("lookup replaced or removed the saved binding", err)
			}
		})
	}
}
