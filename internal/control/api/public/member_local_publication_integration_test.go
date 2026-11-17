package public

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/config"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationMemberFreshNamedLocalPreparationWithoutInventory(t *testing.T) {
	f := newCompanyHTTPFixture(t, "member_local_preparation")
	ctx := t.Context()
	owner, session := f.basic(serviceOwnerSub), f.basic(serviceRecipientSub)
	team, err := f.d.CreateTeam(ctx, controlstate.CreateTeamRequest{
		IdentityID: owner.Identity.Identity.Id, DisplayName: "member-local", MemberSlug: "owner",
		IdempotencyKey: "team", RequestDigest: sha256.Sum256([]byte("team")),
	}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	invitation, err := f.d.CreateTeamInvitation(ctx, controlstate.CreateInvitationRequest{
		IdentityID: owner.Identity.Identity.Id, TeamID: team.ID, MemberSlug: "developer",
		InitialRole: controlstate.TeamRoleMember, IdempotencyKey: "member",
		ExpiresAt: f.now.Add(time.Hour), RetrySecret: bytes.Repeat([]byte{9}, 32),
	}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	membership, err := f.d.AcceptInvitation(ctx, session.Identity.Identity.Id, credentials.InvitationToken(invitation.Secret), f.now)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(Config{ControlURL: f.server.URL, ManagedURLMode: naming.ManagedURLModeGenerated}, DatabaseStores(f.d), f.d, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.mux.Handle("/", h)
	control, err := clientcontrol.New(f.server.URL, f.server.Client(), credentials.AccessToken(session.AccessToken))
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(f.server.URL, f.server.Client(), credentials.AccessToken(session.AccessToken))
	if err != nil {
		t.Fatal(err)
	}
	selectedTeam, err := authority.GetTeam(ctx, team.ID)
	if err != nil {
		t.Fatal(err)
	}
	domains, err := authority.ListTeamDomains(ctx, team.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertMember := func() authorityv1.Membership {
		t.Helper()
		identity, err := authority.IdentityContext(ctx)
		if err != nil || identity.Identity.Administrator {
			t.Fatal("ordinary member identity changed", err)
		}
		for _, member := range identity.Memberships {
			if member.TeamId == team.ID {
				if member.Id != membership.ID || member.Role != authorityv1.TeamRoleMember || member.MemberSlug != "developer" {
					t.Fatal("member was promoted or rebound")
				}
				return member
			}
		}
		t.Fatal("missing ordinary membership")
		return authorityv1.Membership{}
	}
	member := assertMember()
	assertNoInventory := func() {
		t.Helper()
		if page, err := control.ListServices(ctx, team.ID); !errors.Is(err, clientcontrol.ErrNotFound) || len(page) != 0 {
			t.Fatal("member gained broad service inventory", err)
		}
		if _, err := control.GetProjectConfiguration(ctx, team.ID, "team-project", "production"); err != nil {
			var problem *clientcontrol.ProblemError
			if !errors.As(err, &problem) || problem.Status != 403 || problem.Problem.Code != controlv1.Forbidden {
				t.Fatal("manager-only project configuration denial changed", err)
			}
		} else {
			t.Fatal("member gained project configuration access")
		}
	}
	assertNoInventory()
	var initial int
	if err := f.sql.QueryRow(ctx, `SELECT count(*) FROM control.services WHERE team_id=$1`, team.ID).Scan(&initial); err != nil || initial != 0 {
		t.Fatal("fresh publication fixture already has a service", err)
	}
	root := t.TempDir()
	project := clientproject.Project{Root: root, Selection: clientproject.Selection{Path: filepath.Join(root, "tnl.json")},
		Config: config.TNL{Services: config.Services{"web": {Public: new(true)}, "unselected": {}}},
	}
	selected := invocation.LocalService{Project: project, Name: "web",
		Team: invocation.FromTeamContext(clientteam.NewContext(selectedTeam, member, domains.Domains, naming.ManagedURLModeGenerated))}
	local, err := invocation.RealizeLocalService(ctx, control, selected)
	if err != nil {
		t.Fatal("ordinary member could not prepare a fresh selected named local app", err)
	}
	source := project.LocalPublicationIdentity()
	if local.Service != "web" || local.WorktreeKey != project.LocalWorktreeKey() || local.ServiceId == "" || local.Metadata == nil || local.Metadata.Endpoint == nil {
		t.Fatal("native preparation lost exact selected local service")
	}
	if !strings.HasSuffix(local.Metadata.Endpoint.Hostname, "."+member.ManagedLabel+".example.test") {
		t.Fatal("native preparation escaped the member namespace")
	}
	retry, err := invocation.RealizeLocalService(ctx, control, selected)
	if err != nil || retry.ServiceId != local.ServiceId {
		t.Fatal("member preparation retry changed identity", err)
	}
	service, err := control.GetService(ctx, local.ServiceId)
	if err != nil || service.Source == nil || service.Source.ProjectKey != source.Key || service.Source.Service != "web" || service.Source.WorktreeKey != local.WorktreeKey {
		t.Fatal("member cannot select its exact realized service", err)
	}
	var creator, claimMember string
	var count, applied int
	if err := f.sql.QueryRow(ctx, `SELECT l.created_by_identity_id,c.membership_id,
		(SELECT count(*) FROM control.local_project_services WHERE team_id=$1),
		(SELECT count(*) FROM control.applied_projects WHERE team_id=$1)
		FROM control.local_project_services l JOIN control.service_endpoints e ON e.service_id=l.service_id
		JOIN control.service_namespace_claims c ON c.namespace=e.namespace AND c.local_source_key=e.local_source_key
		WHERE l.service_id=$2`, team.ID, local.ServiceId).Scan(&creator, &claimMember, &count, &applied); err != nil ||
		creator != session.Identity.Identity.Id || claimMember != membership.ID || count != 1 || applied != 0 {
		t.Fatal("preparation adopted another owner, selected another app, or wrote saved project intent", err)
	}
	assertMember()
	assertNoInventory()
}
