package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

type teamCommand struct {
	Current teamCurrentCommand `cmd:"" help:"Show the selected team."`
	List    teamListCommand    `cmd:"" help:"List current memberships."`
	Use     teamUseCommand     `cmd:"" help:"Select a team for future commands."`
	Create  teamCreateCommand  `cmd:"" help:"Create an organization team."`
	Members teamMembersCommand `cmd:"" help:"List team memberships."`
	Invite  teamInviteCommand  `cmd:"" help:"Manage team invitations."`
	Join    teamJoinCommand    `cmd:"" help:"Accept a team invitation."`
	Member  teamMemberCommand  `cmd:"" help:"Manage one team membership."`
}

type teamCurrentCommand struct {
	remoteFlags `embed:""`
}
type teamListCommand struct {
	remoteFlags `embed:""`
}

type teamUseCommand struct {
	remoteFlags `embed:""`
	Team        string `arg:"" name:"team" required:"" help:"Team ID or unambiguous display name."`
}

type teamCreateCommand struct {
	remoteFlags `embed:""`
	DisplayName string `arg:"" name:"display-name" required:"" help:"Organization team display name."`
	MemberSlug  string `name:"member-slug" required:"" help:"Immutable member slug for the creator."`
}

type teamMembersCommand struct {
	remoteFlags `embed:""`
	Team        string `name:"team" help:"Team ID or unambiguous display name; defaults to the selected team."`
}

type teamInviteCommand struct {
	Create teamInviteCreateCommand `cmd:"" help:"Create an invitation."`
	List   teamInviteListCommand   `cmd:"" help:"List invitations."`
	Revoke teamInviteRevokeCommand `cmd:"" help:"Revoke an invitation."`
}

type teamInviteCreateCommand struct {
	remoteFlags `embed:""`
	MemberSlug  string        `name:"member-slug" required:"" help:"Reserved immutable member slug."`
	Role        string        `name:"role" enum:"member,admin,owner" default:"member" help:"Initial team role."`
	Email       string        `name:"email" help:"Optional verified-email restriction."`
	ExpiresIn   time.Duration `name:"expires-in" default:"168h" help:"Invitation lifetime."`
}

type teamInviteListCommand struct {
	remoteFlags `embed:""`
}

type teamInviteRevokeCommand struct {
	remoteFlags  `embed:""`
	InvitationID string `arg:"" name:"invitation-id" required:"" help:"Invitation ID to revoke."`
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
	remoteFlags  `embed:""`
	MembershipID string `arg:"" name:"membership-id" required:"" help:"Membership ID to update."`
	Role         string `name:"role" enum:"member,admin,owner" required:"" help:"New team role."`
}

type teamMemberRemoveCommand struct {
	remoteFlags  `embed:""`
	MembershipID string `arg:"" name:"membership-id" required:"" help:"Membership ID to remove."`
}

func runTeamCurrent(ctx context.Context, command teamCurrentCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl team current", diagnostics)
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
	blocks := make([]clioutput.Block, 0, len(session.identity.Memberships))
	for _, membership := range session.identity.Memberships {
		title := membership.TeamDisplayName
		if membership.TeamId == selected || selected == "" && membership.TeamId == session.identity.PersonalTeamId {
			title = "* " + title
		}
		blocks = append(blocks, clioutput.Section(title, clioutput.Fields(
			clioutput.Field{Label: "kind", Value: string(membership.TeamKind)},
			clioutput.Field{Label: "role", Value: string(membership.Role)},
			clioutput.Field{Label: "member slug", Value: membership.MemberSlug},
			clioutput.Field{Label: "team ID", Value: membership.TeamId},
		)))
	}
	return writeHumanFrame(output, "tnl team list", countState(len(blocks), "team", "teams"), "* selected", blocks...)
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
	return writeHumanFrame(output, "tnl team use", "selected", "future commands use this team",
		clioutput.Fields(
			clioutput.Field{Label: "team", Value: membership.TeamDisplayName},
			clioutput.Field{Label: "role", Value: string(membership.Role)},
			clioutput.Field{Label: "member slug", Value: membership.MemberSlug},
			clioutput.Field{Label: "team ID", Value: membership.TeamId},
		),
	)
}

func runTeamCreate(ctx context.Context, command teamCreateCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl team create", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	key, err := randomIdempotencyKey()
	if err != nil {
		return err
	}
	team, err := session.api.CreateTeam(ctx, authorityv1.CreateTeamRequest{DisplayName: command.DisplayName, MemberSlug: command.MemberSlug}, key)
	if err != nil {
		return err
	}
	if err := session.store.SaveSelectedTeam(ctx, team.Id); err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl team create", "created", "selected for future commands",
		clioutput.Fields(
			clioutput.Field{Label: "team", Value: team.DisplayName},
			clioutput.Field{Label: "member slug", Value: command.MemberSlug},
			clioutput.Field{Label: "team ID", Value: team.Id},
		),
	)
}

func runTeamMembers(ctx context.Context, command teamMembersCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl team members", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	team := command.Team
	if team == "" {
		team = session.projectTeam
	}
	membership, err := session.resolveMembership(ctx, team)
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
		return errors.New("invitation lifetime must be positive")
	}
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl team invite create", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	body := authorityv1.CreateInvitationRequest{
		MemberSlug: command.MemberSlug, InitialRole: authorityv1.TeamRole(command.Role), ExpiresAt: time.Now().Add(command.ExpiresIn).UTC(),
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
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl team invite list", diagnostics)
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
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl team invite revoke", diagnostics)
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
	return writeHumanFrame(output, "tnl team join", "joined", "selected for future commands",
		clioutput.Fields(
			clioutput.Field{Label: "team", Value: membership.TeamDisplayName},
			clioutput.Field{Label: "role", Value: string(membership.Role)},
			clioutput.Field{Label: "member slug", Value: membership.MemberSlug},
			clioutput.Field{Label: "id", Value: membership.TeamId},
		),
	)
}

func runTeamMemberSetRole(ctx context.Context, command teamMemberSetRoleCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl team member set-role", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	membership, err := session.api.SetMembershipRole(ctx, current.team.Id, command.MembershipID, authorityv1.TeamRole(command.Role))
	if err != nil {
		return err
	}
	return writeHumanTransition(output, "tnl team member set-role", "updated", membership.Id, "role changed",
		string(membership.Role), "")
}

func runTeamMemberRemove(ctx context.Context, command teamMemberRemoveCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl team member remove", diagnostics)
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
