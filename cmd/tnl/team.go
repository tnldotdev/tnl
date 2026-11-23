package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

type teamCommand struct {
	Feedback teamFeedbackCommand
	Current  teamCurrentCommand
	List     teamListCommand
	Use      teamUseCommand
	Create   teamCreateCommand
	Members  teamMembersCommand
	Invite   teamInviteCommand
	Join     teamJoinCommand
	Member   teamMemberCommand
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
	MemberSlug  string `name:"member-slug" help:"Creator's team-local DNS label. Hosted teams get a generated label if omitted."`
}

type teamMembersCommand struct {
	scopedTeamFlags `embed:""`
}

type teamInviteCommand struct {
	Create teamInviteCreateCommand
	List   teamInviteListCommand
	Revoke teamInviteRevokeCommand
}

type teamInviteCreateCommand struct {
	scopedTeamFlags `embed:""`
	MemberSlug      string               `name:"member-slug" help:"Reserve a team-local DNS label. Hosted teams get a generated label if omitted."`
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
	SetRole teamMemberSetRoleCommand
	Remove  teamMemberRemoveCommand
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
	current, err := session.CurrentWithDomains(ctx)
	if err != nil {
		return err
	}
	fields := []clioutput.Field{
		clioutput.Field{Label: "server", Value: session.Authenticated().ServerEndpoint},
		clioutput.Field{Label: "team", Value: current.Team().DisplayName},
		clioutput.Field{Label: "kind", Value: string(current.Team().Kind)},
		clioutput.Field{Label: "role", Value: string(current.Membership().Role)},
		clioutput.Field{Label: "member slug", Value: current.Membership().MemberSlug},
		clioutput.Field{Label: "team ID", Value: current.Team().Id},
	}
	if domain, err := current.ReadyDomain(""); err == nil {
		namespace, _ := current.Namespace(domain)
		fields = append(fields, clioutput.Field{Label: "new named URL", Value: "https://app." + namespace})
	}
	return writeHumanFrame(output, "tnl team current", "selected", "", clioutput.Fields(fields...))
}

func runTeamList(ctx context.Context, command teamListCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl team list", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	selected, _, err := session.Store().SelectedTeam(ctx)
	if err != nil {
		return err
	}
	projectID := ""
	if session.ProjectTeam() != "" {
		if project, err := session.ResolveMembership(ctx, session.ProjectTeam()); err == nil {
			projectID = project.TeamId
		}
	}
	blocks := make([]clioutput.Block, 0, len(session.Identity().Memberships)+1)
	blocks = append(blocks, clioutput.Fields(clioutput.Field{Label: "server", Value: session.Authenticated().ServerEndpoint}))
	if session.ProjectTeam() != "" && projectID == "" {
		blocks = append(blocks, clioutput.Fields(clioutput.Field{
			Label: "project team", Value: session.ProjectTeam() + " (not in memberships)",
		}))
	}
	for _, membership := range session.Identity().Memberships {
		title := membership.TeamDisplayName
		if membership.TeamId == selected || selected == "" && membership.TeamId == session.InitialTeam() {
			title = "* " + title
		}
		if membership.TeamId == projectID {
			title = "> " + title
			if membership.TeamId == selected || selected == "" && membership.TeamId == session.InitialTeam() {
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
	if session.ProjectTeam() != "" {
		footer = "* saved / > project"
	}
	return writeHumanFrame(output, "tnl team list", countState(len(session.Identity().Memberships), "team", "teams"), footer, blocks...)
}

func runTeamUse(ctx context.Context, command teamUseCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl team use", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	membership, err := session.ResolveMembership(ctx, command.Team)
	if err != nil {
		return err
	}
	if err := session.Store().SaveSelectedTeam(ctx, membership.TeamId); err != nil {
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
	team, err := session.Authenticated().Authority.CreateTeam(ctx, request, key)
	if err != nil {
		return err
	}
	if err := session.Store().SaveSelectedTeam(ctx, team.Id); err != nil {
		return err
	}
	fields := []clioutput.Field{{Label: "team", Value: team.DisplayName}, {Label: "team ID", Value: team.Id}}
	if command.MemberSlug != "" {
		fields = append(fields, clioutput.Field{Label: "member slug", Value: command.MemberSlug})
	} else {
		fields = append(fields,
			clioutput.Field{Label: "member slug", Value: "derived from identity name"},
			clioutput.Field{Label: "next", Value: "tnl team current --team=" + team.DisplayName + " --server=" + session.Authenticated().ServerEndpoint},
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
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	page, err := session.Authenticated().Authority.ListTeamMemberships(ctx, current.Team().Id)
	if err != nil {
		return err
	}
	blocks := make([]clioutput.Block, 0, len(page.Memberships))
	for _, value := range page.Memberships {
		namespace, _ := naming.PublicURLNamespace(naming.NamespaceFacts{
			Domain: session.Authenticated().Discovery.ManagedDomain, Managed: true,
			Mode:     naming.ManagedURLMode(session.Authenticated().Discovery.ManagedUrlMode),
			Personal: value.TeamKind == authorityv1.Personal,
			TeamName: value.TeamDisplayName, MemberSlug: value.MemberSlug, ManagedLabel: current.Team().ManagedLabel,
		})
		blocks = append(blocks, clioutput.Section(value.MemberSlug, clioutput.Fields(
			clioutput.Field{Label: "role", Value: string(value.Role)},
			clioutput.Field{Label: "identity ID", Value: value.IdentityId},
			clioutput.Field{Label: "managed namespace", Value: namespace},
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
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	body := authorityv1.CreateInvitationRequest{
		MemberSlug: command.MemberSlug, InitialRole: command.Role, ExpiresAt: time.Now().Add(command.ExpiresIn).UTC(),
	}
	if body.MemberSlug == "" && current.Mode() == naming.ManagedURLModeGenerated {
		label, err := naming.RandomHostnameLabel()
		if err != nil {
			return err
		}
		body.MemberSlug = "m-" + label
	}
	if command.Email != "" {
		email := openapiEmail(command.Email)
		body.EmailRestriction = &email
	}
	key, err := randomIdempotencyKey()
	if err != nil {
		return err
	}
	invitation, err := session.Authenticated().Authority.CreateTeamInvitation(ctx, current.Team().Id, body, key)
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
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	page, err := session.Authenticated().Authority.ListTeamInvitations(ctx, current.Team().Id)
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
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	if err := session.Authenticated().Authority.RevokeTeamInvitation(ctx, current.Team().Id, command.InvitationID); err != nil {
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
	membership, err := session.Authenticated().Authority.AcceptInvitation(ctx, command.Secret)
	if err != nil {
		return err
	}
	if err := session.Store().SaveSelectedTeam(ctx, membership.TeamId); err != nil {
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
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	membership, err := session.Authenticated().Authority.SetMembershipRole(ctx, current.Team().Id, command.MembershipID, command.Role)
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
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	if err := session.Authenticated().Authority.RemoveMembership(ctx, current.Team().Id, command.MembershipID); err != nil {
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

func (a *commandApp) newTeamCommand() *cobra.Command {
	f := a.flags
	cTeam := &cobra.Command{Use: "team", Short: "Manage teams and memberships.", GroupID: "manage"}
	cTeamFeedback := &cobra.Command{Use: "feedback", Short: "Manage who may write team feedback."}
	cTeamFeedbackGet := &cobra.Command{Use: "get", Short: "Read the feedback author policy."}
	a.leaf(cTeamFeedbackGet, &f.Team.Feedback.Get, func(call commandCall) error {
		return runTeamFeedbackGet(call.ctx, f.Team.Feedback.Get, a.out, a.errOut)
	})
	cTeamFeedback.AddCommand(cTeamFeedbackGet)
	cTeamFeedbackSet := &cobra.Command{Use: "set", Short: "Change who may write feedback."}
	a.leaf(cTeamFeedbackSet, &f.Team.Feedback.Set, func(call commandCall) error {
		return runTeamFeedbackSet(call.ctx, f.Team.Feedback.Set, a.out, a.errOut)
	})
	cTeamFeedback.AddCommand(cTeamFeedbackSet)
	cTeam.AddCommand(cTeamFeedback)
	cTeamCurrent := &cobra.Command{Use: "current", Short: "Show the selected team."}
	a.leaf(cTeamCurrent, &f.Team.Current, func(call commandCall) error {
		return runTeamCurrent(call.ctx, f.Team.Current, a.out, a.errOut)
	})
	cTeam.AddCommand(cTeamCurrent)
	cTeamList := &cobra.Command{Use: "list", Short: "List current memberships."}
	a.leaf(cTeamList, &f.Team.List, func(call commandCall) error {
		return runTeamList(call.ctx, f.Team.List, a.out, a.errOut)
	})
	cTeam.AddCommand(cTeamList)
	cTeamUse := &cobra.Command{Use: "use", Short: "Save a team for commands without a project team."}
	a.leaf(cTeamUse, &f.Team.Use, func(call commandCall) error {
		return runTeamUse(call.ctx, f.Team.Use, a.out, a.errOut)
	})
	cTeam.AddCommand(cTeamUse)
	cTeamCreate := &cobra.Command{Use: "create", Short: "Create an organization team."}
	a.leaf(cTeamCreate, &f.Team.Create, func(call commandCall) error {
		return runTeamCreate(call.ctx, f.Team.Create, a.out, a.errOut)
	})
	cTeam.AddCommand(cTeamCreate)
	cTeamMembers := &cobra.Command{Use: "members", Short: "List team memberships."}
	a.leaf(cTeamMembers, &f.Team.Members, func(call commandCall) error {
		return runTeamMembers(call.ctx, f.Team.Members, a.out, a.errOut)
	})
	cTeam.AddCommand(cTeamMembers)
	cTeamInvite := &cobra.Command{Use: "invite", Short: "Manage team invitations."}
	cTeamInviteCreate := &cobra.Command{Use: "create", Short: "Create an invitation."}
	a.leaf(cTeamInviteCreate, &f.Team.Invite.Create, func(call commandCall) error {
		return runTeamInviteCreate(call.ctx, f.Team.Invite.Create, a.out, a.errOut)
	})
	cTeamInvite.AddCommand(cTeamInviteCreate)
	cTeamInviteList := &cobra.Command{Use: "list", Short: "List invitations."}
	a.leaf(cTeamInviteList, &f.Team.Invite.List, func(call commandCall) error {
		return runTeamInviteList(call.ctx, f.Team.Invite.List, a.out, a.errOut)
	})
	cTeamInvite.AddCommand(cTeamInviteList)
	cTeamInviteRevoke := &cobra.Command{Use: "revoke", Short: "Revoke an invitation."}
	a.leaf(cTeamInviteRevoke, &f.Team.Invite.Revoke, func(call commandCall) error {
		return runTeamInviteRevoke(call.ctx, f.Team.Invite.Revoke, a.out, a.errOut)
	})
	cTeamInvite.AddCommand(cTeamInviteRevoke)
	cTeam.AddCommand(cTeamInvite)
	cTeamJoin := &cobra.Command{Use: "join", Short: "Accept a team invitation."}
	a.leaf(cTeamJoin, &f.Team.Join, func(call commandCall) error {
		return runTeamJoin(call.ctx, f.Team.Join, a.out, a.errOut)
	})
	cTeam.AddCommand(cTeamJoin)
	cTeamMember := &cobra.Command{Use: "member", Short: "Manage one team membership."}
	cTeamMemberSetRole := &cobra.Command{Use: "set-role", Short: "Change a membership role."}
	a.leaf(cTeamMemberSetRole, &f.Team.Member.SetRole, func(call commandCall) error {
		return runTeamMemberSetRole(call.ctx, f.Team.Member.SetRole, a.out, a.errOut)
	})
	cTeamMember.AddCommand(cTeamMemberSetRole)
	cTeamMemberRemove := &cobra.Command{Use: "remove", Short: "Remove a membership."}
	a.leaf(cTeamMemberRemove, &f.Team.Member.Remove, func(call commandCall) error {
		return runTeamMemberRemove(call.ctx, f.Team.Member.Remove, a.out, a.errOut)
	})
	cTeamMember.AddCommand(cTeamMemberRemove)
	cTeam.AddCommand(cTeamMember)
	return cTeam
}
