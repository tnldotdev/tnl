package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

type teamCommand struct {
	Current teamCurrentCommand `cmd:"" help:"Show the selected team."`
	List    teamListCommand    `cmd:"" help:"List current memberships."`
	Use     teamUseCommand     `cmd:"" help:"Save a team for commands without a project team."`
	Create  teamCreateCommand  `cmd:"" help:"Create an organization team."`
	Members teamMembersCommand `cmd:"" help:"List team memberships."`
	Invite  teamInviteCommand  `cmd:"" help:"Manage team invitations."`
	Join    teamJoinCommand    `cmd:"" help:"Accept a team invitation."`
	Member  teamMemberCommand  `cmd:"" help:"Manage one team membership."`
}

type teamCurrentCommand struct {
	scopedTeamFlags `embed:""`
}
type teamListCommand struct {
	remoteFlags `embed:""`
}

type teamUseCommand struct {
	remoteFlags `embed:""`
	Team        string `arg:"" name:"team" required:"" help:"Team name or ID."`
}

type teamCreateCommand struct {
	remoteFlags `embed:""`
	Name        string `arg:"" name:"name" required:"" help:"Unique, permanent lowercase DNS label for the team."`
	MemberSlug  string `name:"member-slug" help:"Creator's immutable custom-domain label; defaults to one derived from your identity name."`
}

type teamMembersCommand struct {
	scopedTeamFlags `embed:""`
}

type teamInviteCommand struct {
	Create teamInviteCreateCommand `cmd:"" help:"Create an invitation."`
	List   teamInviteListCommand   `cmd:"" help:"List invitations."`
	Revoke teamInviteRevokeCommand `cmd:"" help:"Revoke an invitation."`
}

type teamInviteCreateCommand struct {
	scopedTeamFlags `embed:""`
	MemberSlug      string               `name:"member-slug" required:"" help:"Reserved member namespace label on custom domains."`
	Role            authorityv1.TeamRole `name:"role" enum:"member,admin,owner" default:"member" help:"Initial team role."`
	Email           string               `name:"email" help:"Optional verified-email restriction."`
	ExpiresIn       time.Duration        `name:"expires-in" default:"168h" help:"Invitation lifetime."`
}

type teamInviteListCommand struct {
	scopedTeamFlags `embed:""`
}

type teamInviteRevokeCommand struct {
	scopedTeamFlags `embed:""`
	InvitationID    string `arg:"" name:"invitation-id" required:"" help:"Invitation ID to revoke."`
}

type teamJoinCommand struct {
	remoteFlags `embed:""`
	Secret      string `arg:"" name:"secret" required:"" help:"Invitation secret."`
}

type teamMemberCommand struct {
	SetRole teamMemberSetRoleCommand `cmd:"" help:"Change a membership role."`
	Remove  teamMemberRemoveCommand  `cmd:"" help:"Remove a membership."`
}

type teamMemberSetRoleCommand struct {
	scopedTeamFlags `embed:""`
	MembershipID    string               `arg:"" name:"membership-id" required:"" help:"Membership ID to update."`
	Role            authorityv1.TeamRole `name:"role" enum:"member,admin,owner" required:"" help:"New team role."`
}

type teamMemberRemoveCommand struct {
	scopedTeamFlags `embed:""`
	MembershipID    string `arg:"" name:"membership-id" required:"" help:"Membership ID to remove."`
}

func runTeamCurrent(ctx context.Context, command teamCurrentCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.selection(), "tnl team current", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl team current", "selected", "",
		clioutput.Fields(
			clioutput.Field{Label: "server", Value: session.authenticated.ServerEndpoint},
			clioutput.Field{Label: "team", Value: current.team.DisplayName},
			clioutput.Field{Label: "kind", Value: string(current.team.Kind)},
			clioutput.Field{Label: "role", Value: string(current.membership.Role)},
			clioutput.Field{Label: "member slug", Value: current.membership.MemberSlug},
			clioutput.Field{Label: "team ID", Value: current.team.Id},
		),
	)
}

func runTeamList(ctx context.Context, command teamListCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl team list", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	selected, _, err := session.store.SelectedTeam(ctx)
	if err != nil {
		return err
	}
	projectID := ""
	if session.projectTeam != "" {
		if project, err := session.resolveMembership(ctx, session.projectTeam); err == nil {
			projectID = project.TeamId
		}
	}
	blocks := make([]clioutput.Block, 0, len(session.identity.Memberships)+1)
	blocks = append(blocks, clioutput.Fields(clioutput.Field{Label: "server", Value: session.authenticated.ServerEndpoint}))
	if session.projectTeam != "" && projectID == "" {
		blocks = append(blocks, clioutput.Fields(clioutput.Field{
			Label: "project team", Value: session.projectTeam + " (not in memberships)",
		}))
	}
	for _, membership := range session.identity.Memberships {
		title := membership.TeamDisplayName
		if membership.TeamId == selected || selected == "" && membership.TeamId == session.identity.PersonalTeamId {
			title = "* " + title
		}
		if membership.TeamId == projectID {
			title = "> " + title
			if membership.TeamId == selected || selected == "" && membership.TeamId == session.identity.PersonalTeamId {
				title = "* > " + membership.TeamDisplayName
			}
		}
		blocks = append(blocks, clioutput.Section(title, clioutput.Fields(
			clioutput.Field{Label: "kind", Value: string(membership.TeamKind)},
			clioutput.Field{Label: "role", Value: string(membership.Role)},
			clioutput.Field{Label: "member slug", Value: membership.MemberSlug},
			clioutput.Field{Label: "team ID", Value: membership.TeamId},
		)))
	}
	footer := "* saved"
	if session.projectTeam != "" {
		footer = "* saved / > project"
	}
	return writeHumanFrame(output, "tnl team list", countState(len(session.identity.Memberships), "team", "teams"), footer, blocks...)
}

func runTeamUse(ctx context.Context, command teamUseCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl team use", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	membership, err := session.resolveMembership(ctx, command.Team)
	if err != nil {
		return err
	}
	if err := session.store.SaveSelectedTeam(ctx, membership.TeamId); err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl team use", "selected", savedTeamFooter(command.ProjectTeam, membership.TeamId, membership.TeamDisplayName),
		clioutput.Fields(
			clioutput.Field{Label: "team", Value: membership.TeamDisplayName},
			clioutput.Field{Label: "role", Value: string(membership.Role)},
			clioutput.Field{Label: "member slug", Value: membership.MemberSlug},
			clioutput.Field{Label: "team ID", Value: membership.TeamId},
		),
	)
}

func runTeamCreate(ctx context.Context, command teamCreateCommand, output, diagnostics io.Writer) error {
	if !naming.ValidAuthorityLabel(command.Name) {
		return failure.Wrap("validate team name", failure.InvalidCommand, errors.New("team name must be one lowercase ASCII DNS label (for example, studio)"))
	}
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl team create", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	if command.MemberSlug != "" && !naming.ValidAuthorityLabel(command.MemberSlug) {
		return failure.Wrap("validate member slug", failure.InvalidCommand, errors.New("member slug must be one lowercase ASCII DNS label"))
	}
	key, err := randomIdempotencyKey()
	if err != nil {
		return err
	}
	request := authorityv1.CreateTeamRequest{DisplayName: authorityv1.CanonicalLabel(command.Name)}
	if command.MemberSlug != "" {
		slug := authorityv1.CanonicalLabel(command.MemberSlug)
		request.MemberSlug = &slug
	}
	team, err := session.api.CreateTeam(ctx, request, key)
	if err != nil {
		return err
	}
	if err := session.store.SaveSelectedTeam(ctx, team.Id); err != nil {
		return err
	}
	fields := []clioutput.Field{{Label: "team", Value: team.DisplayName}, {Label: "team ID", Value: team.Id}}
	if command.MemberSlug != "" {
		fields = append(fields, clioutput.Field{Label: "member slug", Value: command.MemberSlug})
	} else {
		fields = append(fields,
			clioutput.Field{Label: "member slug", Value: "derived from identity name"},
			clioutput.Field{Label: "next", Value: "tnl team current --team=" + team.DisplayName + " --server=" + session.authenticated.ServerEndpoint},
		)
	}
	return writeHumanFrame(output, "tnl team create", "created", savedTeamFooter(command.ProjectTeam, team.Id, team.DisplayName),
		clioutput.Fields(
			fields...,
		),
	)
}

func runTeamMembers(ctx context.Context, command teamMembersCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.selection(), "tnl team members", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	membership, err := session.currentMembership(ctx)
	if err != nil {
		return err
	}
	page, err := session.api.ListTeamMemberships(ctx, membership.TeamId)
	if err != nil {
		return err
	}
	blocks := make([]clioutput.Block, 0, len(page.Memberships))
	for _, value := range page.Memberships {
		blocks = append(blocks, clioutput.Section(value.MemberSlug, clioutput.Fields(
			clioutput.Field{Label: "role", Value: string(value.Role)},
			clioutput.Field{Label: "identity ID", Value: value.IdentityId},
			clioutput.Field{Label: "managed label", Value: value.ManagedLabel},
			clioutput.Field{Label: "membership ID", Value: value.Id},
		)))
	}
	return writeHumanFrame(output, "tnl team members", countState(len(blocks), "member", "members"), "", blocks...)
}

func runTeamInviteCreate(ctx context.Context, command teamInviteCreateCommand, output, diagnostics io.Writer) error {
	if command.ExpiresIn <= 0 {
		return failure.Wrap("validate invitation lifetime", failure.InvalidCommand, errors.New("invitation lifetime must be positive"))
	}
	session, err := openTeamSession(ctx, command.selection(), "tnl team invite create", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	body := authorityv1.CreateInvitationRequest{
		MemberSlug: command.MemberSlug, InitialRole: command.Role, ExpiresAt: time.Now().Add(command.ExpiresIn).UTC(),
	}
	if command.Email != "" {
		email := openapiEmail(command.Email)
		body.EmailRestriction = &email
	}
	key, err := randomIdempotencyKey()
	if err != nil {
		return err
	}
	invitation, err := session.api.CreateTeamInvitation(ctx, current.team.Id, body, key)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "%s\t%s\n", invitation.Invitation.Id, invitation.Secret)
	return err
}

func runTeamInviteList(ctx context.Context, command teamInviteListCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.selection(), "tnl team invite list", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	page, err := session.api.ListTeamInvitations(ctx, current.team.Id)
	if err != nil {
		return err
	}
	blocks := make([]clioutput.Block, 0, len(page.Invitations))
	for _, value := range page.Invitations {
		blocks = append(blocks, clioutput.Section(value.MemberSlug, clioutput.Fields(
			clioutput.Field{Label: "role", Value: string(value.InitialRole)},
			clioutput.Field{Label: "state", Value: string(value.State)},
			clioutput.Field{Label: "expires", Value: value.ExpiresAt.UTC().Format(time.RFC3339)},
			clioutput.Field{Label: "id", Value: value.Id},
		)))
	}
	return writeHumanFrame(output, "tnl team invite list", countState(len(blocks), "invitation", "invitations"), "", blocks...)
}

func runTeamInviteRevoke(ctx context.Context, command teamInviteRevokeCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.selection(), "tnl team invite revoke", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	if err := session.api.RevokeTeamInvitation(ctx, current.team.Id, command.InvitationID); err != nil {
		return err
	}
	return writeHumanTransition(output, "tnl team invite revoke", "revoked", command.InvitationID, "", "invitation revoked", "")
}

func runTeamJoin(ctx context.Context, command teamJoinCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl team join", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	membership, err := session.api.AcceptInvitation(ctx, command.Secret)
	if err != nil {
		return err
	}
	if err := session.store.SaveSelectedTeam(ctx, membership.TeamId); err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl team join", "joined", savedTeamFooter(command.ProjectTeam, membership.TeamId, membership.TeamDisplayName),
		clioutput.Fields(
			clioutput.Field{Label: "team", Value: membership.TeamDisplayName},
			clioutput.Field{Label: "role", Value: string(membership.Role)},
			clioutput.Field{Label: "member slug", Value: membership.MemberSlug},
			clioutput.Field{Label: "id", Value: membership.TeamId},
		),
	)
}

func runTeamMemberSetRole(ctx context.Context, command teamMemberSetRoleCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.selection(), "tnl team member set-role", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	membership, err := session.api.SetMembershipRole(ctx, current.team.Id, command.MembershipID, command.Role)
	if err != nil {
		return err
	}
	return writeHumanTransition(output, "tnl team member set-role", "updated", membership.Id, "role changed",
		string(membership.Role), "")
}

func runTeamMemberRemove(ctx context.Context, command teamMemberRemoveCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.selection(), "tnl team member remove", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	if err := session.api.RemoveMembership(ctx, current.team.Id, command.MembershipID); err != nil {
		return err
	}
	return writeHumanTransition(output, "tnl team member remove", "removed", command.MembershipID, "", "membership removed", "")
}

func openapiEmail(value string) openapi_types.Email { return openapi_types.Email(value) }

func savedTeamFooter(projectTeam, selectedID, selectedName string) string {
	if projectTeam != "" && projectTeam != selectedID && projectTeam != selectedName {
		return "saved; project team still takes precedence here"
	}
	return "saved for commands without a project team"
}
