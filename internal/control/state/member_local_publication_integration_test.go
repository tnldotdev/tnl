package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

func TestIntegrationMemberFreshNamedLocalPublicationAuthority(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	ctx := t.Context()
	member := addAuthorityMember(t, d, now, owner, team.ID, "local-publisher", TeamRoleMember)
	other := addAuthorityMember(t, d, now, owner, team.ID, "other-publisher", TeamRoleMember)
	fingerprint := strings.Repeat("a", 64)
	r := RealizeLocalProjectServiceRequest{
		TeamID: team.ID, ActorID: member.IdentityID, ProjectKey: "local-" + fingerprint[:48], SourceFingerprint: fingerprint,
		Service: "web", WorktreeKey: "checkout", WorktreeLabel: "feature", Now: now,
		Configuration: ProjectServiceConfiguration{Target: "app", Public: new(true)},
	}
	local, err := d.RealizeLocalProjectService(ctx, r)
	if err != nil {
		t.Fatal("ordinary member cannot realize a fresh named local app", err)
	}
	want := "web-feature." + member.MemberSlug + "." + team.ManagedLabel + ".tunnels.example.test"
	if local.Hostname != want || local.Metadata == nil {
		t.Fatal("member realization escaped the selected namespace")
	}
	retry, err := d.RealizeLocalProjectService(ctx, r)
	if err != nil || retry.ServiceID != local.ServiceID {
		t.Fatal("member realization retry changed identity", err)
	}
	service, err := d.GetService(ctx, local.ServiceID, member.IdentityID)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := d.IssuePublisherEnrollment(ctx, standaloneEnrollmentRequest(t, d, service, member.IdentityID, "member-local", now))
	if err != nil {
		t.Fatal("member could not receive an exact publisher grant", err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(ctx, enrollment.Key, public, now)
	if err != nil || publisher.Scope.Kind != "service" || publisher.Scope.ServiceID != service.ID ||
		publisher.Ownership != "member" || publisher.OwnerMembershipID != member.ID || publisher.CreatorID != member.IdentityID {
		t.Fatal("member preparation widened publisher ownership or scope", err)
	}
	assertInventoryDenied := func() {
		t.Helper()
		if items, _, err := d.ListServices(ctx, team.ID, member.IdentityID, ""); !errors.Is(err, ErrServiceAccess) || len(items) != 0 {
			t.Fatal("member publication opened broad inventory", err)
		}
		if _, err := d.GetProjectConfiguration(ctx, team.ID, r.ProjectKey, member.IdentityID, "local"); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("member publication opened project configuration", err)
		}
	}
	assertInventoryDenied()
	foreign := r
	foreign.ActorID, foreign.ProjectKey, foreign.SourceFingerprint = owner, "local-"+strings.Repeat("b", 48), strings.Repeat("b", 64)
	foreignService, err := d.RealizeLocalProjectService(ctx, foreign)
	if err != nil {
		t.Fatal(err)
	}
	foreignTeamRequest := authorityTeamRequest(owner)
	foreignTeamRequest.DisplayName, foreignTeamRequest.IdempotencyKey = "foreign-local-team", "foreign-local-team"
	foreignTeam, err := d.CreateTeam(ctx, foreignTeamRequest, now)
	if err != nil {
		t.Fatal(err)
	}
	if foreignTeam.ID == team.ID {
		t.Fatal("foreign team fixture reused the selected team")
	}
	saved := ApplyProjectConfigurationRequest{
		TeamID: team.ID, ProjectKey: "local-" + strings.Repeat("c", 48), SourceFingerprint: strings.Repeat("c", 64),
		ActorID: owner, Now: now, Configuration: ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{"web": {Target: "app"}}},
	}
	saved = selectedProjectRequest(saved, "local")
	if _, err := d.ApplyProjectConfiguration(ctx, saved); err != nil {
		t.Fatal(err)
	}
	snapshot := func() string {
		t.Helper()
		var value string
		if err := d.pool.QueryRow(ctx, `SELECT jsonb_build_array(
			(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM control.services s),
			(SELECT jsonb_agg(to_jsonb(l) ORDER BY team_id,project_key,service,worktree_key) FROM control.local_project_services l),
			(SELECT jsonb_agg(to_jsonb(e) ORDER BY service_id,hostname) FROM control.service_endpoints e),
			(SELECT jsonb_agg(to_jsonb(c) ORDER BY namespace) FROM control.service_namespace_claims c),
			(SELECT jsonb_agg(to_jsonb(p) ORDER BY team_id,project_key) FROM control.applied_projects p),
			(SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM control.visitor_grants g),
			(SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM control.publisher_grants g))::text`).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := snapshot()
	for _, test := range []struct {
		name string
		edit func(*RealizeLocalProjectServiceRequest)
		want error
	}{
		{"another member's binding", func(r *RealizeLocalProjectServiceRequest) { r.ActorID = other.IdentityID }, ErrServiceAccess},
		{"another member's project", func(r *RealizeLocalProjectServiceRequest) {
			r.ProjectKey, r.SourceFingerprint, r.WorktreeKey = foreign.ProjectKey, foreign.SourceFingerprint, "unclaimed-worktree"
		}, ErrServiceAccess},
		{"foreign namespace", func(r *RealizeLocalProjectServiceRequest) {
			r.WorktreeKey, r.Configuration.Hostname = "unclaimed-worktree", foreignService.Hostname
		}, ErrServiceAccess},
		{"shared namespace", func(r *RealizeLocalProjectServiceRequest) {
			r.WorktreeKey, r.Configuration.Hostname = "unclaimed-worktree", "shared.tunnels.example.test"
		}, ErrServiceAccess},
		{"foreign team", func(r *RealizeLocalProjectServiceRequest) { r.TeamID = foreignTeam.ID }, ErrServiceAccess},
		{"arbitrary project key", func(r *RealizeLocalProjectServiceRequest) { r.ProjectKey = "team-project" }, ErrServiceAccess},
		{"source substitution", func(r *RealizeLocalProjectServiceRequest) { r.SourceFingerprint = strings.Repeat("d", 64) }, ErrServiceAccess},
		{"colliding source prefix", func(r *RealizeLocalProjectServiceRequest) {
			r.SourceFingerprint = r.SourceFingerprint[:48] + strings.Repeat("d", 16)
		}, ErrProjectSourceConflict},
		{"hostname cannot adopt another worktree", func(r *RealizeLocalProjectServiceRequest) {
			r.WorktreeKey, r.Configuration.Hostname = "unclaimed-worktree", local.Hostname
		}, ErrServiceConflict},
		{"saved desired intent", func(r *RealizeLocalProjectServiceRequest) {
			r.ProjectKey, r.SourceFingerprint = saved.ProjectKey, saved.SourceFingerprint
		}, ErrServiceAccess},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := r
			test.edit(&request)
			if _, err := d.RealizeLocalProjectService(ctx, request); !errors.Is(err, test.want) {
				t.Fatal("member crossed local publication authority", err)
			}
			if snapshot() != before {
				t.Fatal("denied member realization changed saved state")
			}
		})
	}
	saved.ActorID = member.IdentityID
	if _, err := d.ApplyProjectConfiguration(ctx, saved); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("member publication opened apply", err)
	}
	if _, err := d.GetService(ctx, foreignService.ServiceID, member.IdentityID); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("member publication opened another service")
	}
	if err := d.RemoveMembership(ctx, owner, team.ID, member.ID, now); err != nil {
		t.Fatal(err)
	}
	before = snapshot()
	if _, err := d.RealizeLocalProjectService(ctx, r); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("removed member retained realization authority", err)
	}
	if snapshot() != before {
		t.Fatal("removed member changed its saved local realization")
	}
	assertInventoryDenied()
	rejoin, err := d.CreateTeamInvitation(ctx, authorityInvitationRequest(owner, team.ID, "local-publisher-again", now), now)
	if err != nil {
		t.Fatal(err)
	}
	rejoined, err := d.AcceptInvitation(ctx, member.IdentityID, credentials.InvitationToken(rejoin.Secret), now)
	if err != nil || rejoined.ID == member.ID || rejoined.Role != TeamRoleMember {
		t.Fatal("rejoined fixture did not receive a new ordinary membership", err)
	}
	before = snapshot()
	if _, err := d.RealizeLocalProjectService(ctx, r); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("matching creator identity adopted an earlier membership's local service", err)
	}
	if snapshot() != before {
		t.Fatal("rejoined member changed the previous membership's local service")
	}
}

func TestIntegrationMemberLocalRealizationRechecksMembershipAfterTeamLock(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	member := addAuthorityMember(t, d, now, owner, team.ID, "queued-publisher", TeamRoleMember)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := controlstatedb.New(gate).LockLocalTeamForMutation(ctx, team.ID); err != nil {
		t.Fatal(err)
	}
	r := RealizeLocalProjectServiceRequest{
		TeamID: team.ID, ActorID: member.IdentityID, ProjectKey: "local-" + strings.Repeat("a", 48),
		SourceFingerprint: strings.Repeat("a", 64), Service: "web", WorktreeKey: "checkout",
		Configuration: ProjectServiceConfiguration{Target: "app"}, Now: now,
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	done := make(chan error, 1)
	workers.Go(func() { _, err := d.RealizeLocalProjectService(ctx, r); done <- err })
	waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
	if _, err := gate.Exec(ctx, `UPDATE control.team_memberships SET manual_suspended_at=$2 WHERE id=$1`, member.ID, now); err != nil {
		t.Fatal(err)
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("queued realization used membership from before the team lock", err)
	}
	var count int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.local_project_services WHERE team_id=$1`, team.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("queued suspended member left a local realization", err)
	}
}
