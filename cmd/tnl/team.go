package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/routeclient"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
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
	DisplayName string `arg:"" name:"display-name" required:""`
	Slug        string `name:"slug" required:"" help:"Immutable member slug for the creator."`
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
	Slug        string        `name:"slug" required:"" help:"Reserved immutable member slug."`
	Role        string        `name:"role" enum:"member,admin,owner" default:"member"`
	Email       string        `name:"email" help:"Optional verified-email restriction."`
	ExpiresIn   time.Duration `name:"expires-in" default:"168h" help:"Invitation lifetime."`
}

type teamInviteListCommand struct {
	remoteFlags `embed:""`
}

type teamInviteRevokeCommand struct {
	remoteFlags  `embed:""`
	InvitationID string `arg:"" name:"invitation-id" required:""`
}

type teamJoinCommand struct {
	remoteFlags `embed:""`
	Secret      string `arg:"" name:"secret" required:""`
}

type teamMemberCommand struct {
	SetRole teamMemberSetRoleCommand `cmd:"" help:"Change a membership role."`
	Remove  teamMemberRemoveCommand  `cmd:"" help:"Remove a membership."`
}

type teamMemberSetRoleCommand struct {
	remoteFlags  `embed:""`
	MembershipID string `arg:"" name:"membership-id" required:""`
	Role         string `name:"role" enum:"member,admin,owner" required:""`
}

type teamMemberRemoveCommand struct {
	remoteFlags  `embed:""`
	MembershipID string `arg:"" name:"membership-id" required:""`
}

type domainCommand struct {
	Claim   domainClaimCommand   `cmd:"" help:"Claim a domain for the selected team."`
	Default domainDefaultCommand `cmd:"" help:"Set the selected team's default domain."`
	List    domainListCommand    `cmd:"" help:"List domains available to the selected team."`
	Release domainReleaseCommand `cmd:"" help:"Release a claimed domain."`
}

type domainClaimCommand struct {
	remoteFlags `embed:""`
	Domain      string `arg:"" name:"domain" required:""`
	Default     bool   `name:"default" help:"Make the domain the team default after it becomes ready."`
}

type domainDefaultCommand struct {
	remoteFlags `embed:""`
	Domain      string `arg:"" name:"domain" required:"" help:"Domain ID or canonical domain."`
}

type domainListCommand struct {
	remoteFlags `embed:""`
}

type domainReleaseCommand struct {
	remoteFlags `embed:""`
	Domain      string `arg:"" name:"domain" required:"" help:"Domain ID or canonical domain."`
}

type routeCommand struct {
	List   routeListCommand   `cmd:"" help:"List durable routes for the selected team."`
	Delete routeDeleteCommand `cmd:"" help:"Delete a durable route."`
}

type routeListCommand struct {
	remoteFlags `embed:""`
}

type routeDeleteCommand struct {
	remoteFlags `embed:""`
	RouteID     string `arg:"" name:"route-id" required:""`
}

type teamAPI interface {
	IdentityContext(context.Context) (authorityv1.IdentityContext, error)
	CreateTeam(context.Context, authorityv1.CreateTeamRequest, string) (authorityv1.Team, error)
	GetTeam(context.Context, string) (authorityv1.Team, error)
	ListTeamMemberships(context.Context, string) (authorityv1.MembershipPage, error)
	SetMembershipRole(context.Context, string, string, authorityv1.TeamRole) (authorityv1.Membership, error)
	RemoveMembership(context.Context, string, string) error
	ListTeamInvitations(context.Context, string) (authorityv1.InvitationPage, error)
	CreateTeamInvitation(context.Context, string, authorityv1.CreateInvitationRequest, string) (authorityv1.InvitationSecret, error)
	RevokeTeamInvitation(context.Context, string, string) error
	AcceptInvitation(context.Context, string) (authorityv1.Membership, error)
	ListTeamDomains(context.Context, string) (authorityv1.DomainPage, error)
	ClaimTeamDomain(context.Context, string, string, string, bool) (authorityv1.Domain, error)
	SetTeamDefaultDomain(context.Context, string, string) (authorityv1.Team, error)
	ReleaseTeamDomain(context.Context, string, string) error
}

type teamContext struct {
	team       authorityv1.Team
	membership authorityv1.Membership
	domains    []authorityv1.Domain
}

type teamSession struct {
	database      *clientstate.Database
	store         *clientstate.Store
	authenticated *clientauth.Client
	api           teamAPI
	identity      authorityv1.IdentityContext
}

func openTeamSession(ctx context.Context, flags remoteFlags, command string, diagnostics io.Writer) (*teamSession, error) {
	serverURL, database, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return nil, err
	}
	store, err := database.Server(ctx, serverURL)
	if err != nil {
		database.Close()
		return nil, err
	}
	authenticated, err := clientauth.Authenticate(ctx, clientauth.Config{
		ServerEndpoint: serverURL, State: database, AccessToken: flags.AccessToken,
		Diagnostics: diagnostics, LoginToken: loginTokenPrompt(os.Stdin, diagnostics),
		AuthenticationPrompt: authenticationPrompt(diagnostics, command),
	})
	if err != nil {
		database.Close()
		return nil, err
	}
	api := teamAPI(authenticated.Authority)
	identity, err := api.IdentityContext(ctx)
	if err != nil {
		database.Close()
		return nil, err
	}
	return &teamSession{database: database, store: store, authenticated: authenticated, api: api, identity: identity}, nil
}

func (s *teamSession) Close() error { return s.database.Close() }

func (s *teamSession) current(ctx context.Context) (teamContext, error) {
	teamID, found, err := s.store.SelectedTeam(ctx)
	if err != nil {
		return teamContext{}, err
	}
	if !found {
		teamID = s.identity.PersonalTeamId
	}
	membership, found := membershipForTeam(s.identity.Memberships, teamID)
	if !found {
		teamID = s.identity.PersonalTeamId
		membership, found = membershipForTeam(s.identity.Memberships, teamID)
		if !found {
			return teamContext{}, errors.New("authenticated identity has no personal-team membership")
		}
	}
	if err := s.store.SaveSelectedTeam(ctx, teamID); err != nil {
		return teamContext{}, err
	}
	team, err := s.api.GetTeam(ctx, teamID)
	if err != nil {
		return teamContext{}, err
	}
	domains, err := s.api.ListTeamDomains(ctx, teamID)
	if err != nil {
		return teamContext{}, err
	}
	return teamContext{team: team, membership: membership, domains: domains.Domains}, nil
}

func (s *teamSession) resolveMembership(ctx context.Context, team string) (authorityv1.Membership, error) {
	if team == "" {
		selected, found, err := s.store.SelectedTeam(ctx)
		if err != nil {
			return authorityv1.Membership{}, err
		}
		if found {
			team = selected
		} else {
			team = s.identity.PersonalTeamId
		}
	}
	var matches []authorityv1.Membership
	for _, membership := range s.identity.Memberships {
		if membership.TeamId == team || membership.TeamDisplayName == team {
			matches = append(matches, membership)
		}
	}
	if len(matches) == 0 {
		return authorityv1.Membership{}, fmt.Errorf("team %q is not in the current identity's memberships", team)
	}
	if len(matches) > 1 {
		ids := make([]string, len(matches))
		for index := range matches {
			ids[index] = matches[index].TeamId
		}
		return authorityv1.Membership{}, fmt.Errorf("team name %q is ambiguous; matching IDs: %s", team, strings.Join(ids, ", "))
	}
	return matches[0], nil
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
			clioutput.Field{Label: "slug", Value: current.membership.MemberSlug},
			clioutput.Field{Label: "id", Value: current.team.Id},
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
			clioutput.Field{Label: "slug", Value: membership.MemberSlug},
			clioutput.Field{Label: "id", Value: membership.TeamId},
		)))
	}
	return writeHumanFrame(output, "tnl team list", countState(len(blocks), "membership", "memberships"), "* selected", blocks...)
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
			clioutput.Field{Label: "slug", Value: membership.MemberSlug},
			clioutput.Field{Label: "id", Value: membership.TeamId},
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
	team, err := session.api.CreateTeam(ctx, authorityv1.CreateTeamRequest{DisplayName: command.DisplayName, MemberSlug: command.Slug}, key)
	if err != nil {
		return err
	}
	if err := session.store.SaveSelectedTeam(ctx, team.Id); err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl team create", "created", "selected for future commands",
		clioutput.Fields(
			clioutput.Field{Label: "team", Value: team.DisplayName},
			clioutput.Field{Label: "slug", Value: command.Slug},
			clioutput.Field{Label: "id", Value: team.Id},
		),
	)
}

func runTeamMembers(ctx context.Context, command teamMembersCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl team members", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	membership, err := session.resolveMembership(ctx, command.Team)
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
			clioutput.Field{Label: "identity", Value: value.IdentityId},
			clioutput.Field{Label: "managed label", Value: value.ManagedLabel},
			clioutput.Field{Label: "id", Value: value.Id},
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
		MemberSlug: command.Slug, InitialRole: authorityv1.TeamRole(command.Role), ExpiresAt: time.Now().Add(command.ExpiresIn).UTC(),
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
			clioutput.Field{Label: "slug", Value: membership.MemberSlug},
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

func runDomainClaim(ctx context.Context, command domainClaimCommand, output, diagnostics io.Writer) error {
	domain, err := naming.CanonicalizeHostname(command.Domain)
	if err != nil || domain != command.Domain {
		return errors.New("domain must be a canonical hostname")
	}
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl domain claim", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	key, err := randomIdempotencyKey()
	if err != nil {
		return err
	}
	claimed, err := session.api.ClaimTeamDomain(ctx, current.team.Id, domain, key, command.Default)
	if err != nil {
		return err
	}
	blocks := []clioutput.Block{clioutput.Fields(
		clioutput.Field{Label: "domain", Value: claimed.CanonicalDomain},
		clioutput.Field{Label: "state", Value: string(claimed.State)},
		clioutput.Field{Label: "id", Value: claimed.Id},
	)}
	for _, record := range claimed.RequiredRecords {
		blocks = append(blocks, clioutput.Section("DNS record", clioutput.Fields(
			clioutput.Field{Label: "name", Value: record.Name},
			clioutput.Field{Label: "type", Value: string(record.Type)},
			clioutput.Field{Label: "value", Value: record.Value},
		)))
	}
	state, footer := "claimed", ""
	if len(claimed.RequiredRecords) != 0 {
		state, footer = "verification required", "add the DNS records to continue"
	}
	if command.Default {
		if footer == "" {
			footer = "selected as the default domain"
		} else {
			footer = "add the DNS records; this domain will become the default"
		}
	}
	return writeHumanFrame(output, "tnl domain claim", state, footer, blocks...)
}

func runDomainList(ctx context.Context, command domainListCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl domain list", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	blocks := make([]clioutput.Block, 0, len(current.domains))
	for _, domain := range current.domains {
		title := domain.CanonicalDomain
		if domain.Id == current.team.DefaultDomainId {
			title = "* " + title
		}
		blocks = append(blocks, clioutput.Section(title, clioutput.Fields(
			clioutput.Field{Label: "kind", Value: string(domain.Kind)},
			clioutput.Field{Label: "state", Value: string(domain.State)},
			clioutput.Field{Label: "id", Value: domain.Id},
		)))
	}
	return writeHumanFrame(output, "tnl domain list", countState(len(blocks), "domain", "domains"), "* default", blocks...)
}

func runDomainDefault(ctx context.Context, command domainDefaultCommand, output, diagnostics io.Writer) error {
	return mutateDomain(ctx, command.remoteFlags, "tnl domain default", command.Domain, output, diagnostics, func(session *teamSession, current teamContext, domain authorityv1.Domain) error {
		team, err := session.api.SetTeamDefaultDomain(ctx, current.team.Id, domain.Id)
		if err != nil {
			return err
		}
		return writeHumanTransition(output, "tnl domain default", "updated", domain.CanonicalDomain, "", "default domain", "",
			clioutput.Field{Label: "id", Value: team.DefaultDomainId})
	})
}

func runDomainRelease(ctx context.Context, command domainReleaseCommand, output, diagnostics io.Writer) error {
	return mutateDomain(ctx, command.remoteFlags, "tnl domain release", command.Domain, output, diagnostics, func(session *teamSession, current teamContext, domain authorityv1.Domain) error {
		if err := session.api.ReleaseTeamDomain(ctx, current.team.Id, domain.Id); err != nil {
			return err
		}
		return writeHumanTransition(output, "tnl domain release", "released", domain.CanonicalDomain, "", "domain released", "",
			clioutput.Field{Label: "id", Value: domain.Id})
	})
}

func mutateDomain(ctx context.Context, flags remoteFlags, command, value string, output, diagnostics io.Writer, mutate func(*teamSession, teamContext, authorityv1.Domain) error) error {
	session, err := openTeamSession(ctx, flags, command, diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	for _, domain := range current.domains {
		if domain.Id == value || domain.CanonicalDomain == value {
			return mutate(session, current, domain)
		}
	}
	return fmt.Errorf("domain %q is not available to the selected team", value)
}

func runRouteList(ctx context.Context, command routeListCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl route list", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	routes, err := session.authenticated.Control.ListRoutes(ctx, current.team.Id)
	if err != nil {
		return err
	}
	blocks := make([]clioutput.Block, 0, len(routes))
	for _, route := range routes {
		blocks = append(blocks, clioutput.Section(route.CanonicalHostname, clioutput.Fields(
			clioutput.Field{Label: "scope", Value: string(route.RouteScope)},
			clioutput.Field{Label: "state", Value: string(route.LifecycleState)},
			clioutput.Field{Label: "route version", Value: strconv.FormatInt(route.NextRouteVersion, 10)},
			clioutput.Field{Label: "id", Value: route.Id},
		)))
	}
	return writeHumanFrame(output, "tnl route list", countState(len(blocks), "route", "routes"), "", blocks...)
}

func runRouteDelete(ctx context.Context, command routeDeleteCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl route delete", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	routes, err := session.authenticated.Control.ListRoutes(ctx, current.team.Id)
	if err != nil {
		return err
	}
	var selected *controlv1.Route
	for index := range routes {
		if routes[index].Id == command.RouteID {
			selected = &routes[index]
			break
		}
	}
	if selected == nil {
		return controlclient.ErrNotFound
	}
	client, err := routeAPI(session.authenticated)
	if err != nil {
		return err
	}
	if err := client.DeleteRoute(ctx, *selected); err != nil {
		return err
	}
	return writeHumanTransition(output, "tnl route delete", "deleted", selected.CanonicalHostname, "", "route deleted", "",
		clioutput.Field{Label: "id", Value: selected.Id})
}

func routeAPI(authenticated *clientauth.Client) (*routeclient.Client, error) {
	return routeclient.New(authenticated.Control)
}

func membershipForTeam(memberships []authorityv1.Membership, teamID string) (authorityv1.Membership, bool) {
	for _, membership := range memberships {
		if membership.TeamId == teamID {
			return membership, true
		}
	}
	return authorityv1.Membership{}, false
}

func randomIdempotencyKey() (string, error) { return opaqueid.New("random_") }

func openapiEmail(value string) openapi_types.Email { return openapi_types.Email(value) }
