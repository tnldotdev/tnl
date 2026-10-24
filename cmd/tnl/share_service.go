package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type serviceShareCommand struct {
	Invite serviceShareInviteCommand `cmd:"" help:"Invite a verified-email identity to exactly one service."`
	List   serviceShareListCommand   `cmd:"" help:"List exact-service identity/team grants and invitations, including expired and revoked entries."`
	Revoke serviceShareRevokeCommand `cmd:"" help:"Revoke one invitation (and its derived grant), identity grant, or service HTTP credential."`
	Link   serviceShareLinkCommand   `cmd:"" help:"Create a bounded share link for a publicly reachable service HTTP service."`
	Token  serviceShareTokenCommand  `cmd:"" help:"Create a bounded token for a publicly reachable service HTTP service."`
}

type serviceShareInviteCommand struct {
	Create serviceShareInviteCreateCommand `cmd:"" help:"Print a one-use invitation secret or retry recovery details; requires --expires-at or --expires-in (at most 30d)."`
	Accept serviceShareInviteAcceptCommand `cmd:"" help:"Accept using the matching signed-in verified email; does not join a team."`
}

type serviceShareSelection struct {
	scopedTeamFlags `embed:""`
	Name            string `arg:"" name:"name" help:"Configured service key or exact service ID (svc_)."`
}

type serviceShareDeadline struct {
	ExpiresAt string `name:"expires-at" help:"Explicit RFC3339 access deadline; select this or --expires-in."`
	ExpiresIn string `name:"expires-in" help:"Explicit access lifetime, such as 4h or 7d; select this or --expires-at."`
}

type serviceShareInviteCreateCommand struct {
	serviceShareSelection `embed:""`
	serviceShareDeadline  `embed:""`
	Email                 string           `name:"email" required:"" help:"Recipient's verified sign-in email."`
	IdempotencyKey        string           `name:"idempotency-key" help:"Retry key (1-128 bytes); requires --expires-at. An exact retry returns the original ID without its secret for explicit revoke/reissue."`
	Output                statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Raw new secret or recovery instructions; JSON omits the secret on an exact retry."`
}

type serviceShareInviteAcceptCommand struct {
	remoteFlags `embed:""`
	Secret      string           `arg:"" name:"secret" help:"One-use service invitation secret."`
	Output      statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type serviceShareListCommand struct {
	serviceShareSelection `embed:""`
	Output                statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}; lists access records without secrets."`
}

type serviceShareRevokeCommand struct {
	serviceShareSelection `embed:""`
	ID                    string           `arg:"" name:"access-id" help:"Invitation (sivt_), identity grant (sgr_), or service HTTP grant (shg_) ID."`
	Output                statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type serviceShareLinkCommand struct {
	Create serviceShareHTTPCreateCommand `cmd:"" help:"Print a one-time share URL; requires --expires-at or --expires-in (at most 7d)."`
}

type serviceShareTokenCommand struct {
	Create serviceShareHTTPCreateCommand `cmd:"" help:"Print a one-time Tnl-Visitor-Token value; requires --expires-at or --expires-in (at most 7d)."`
}

type serviceShareHTTPCreateCommand struct {
	serviceShareSelection `embed:""`
	serviceShareDeadline  `embed:""`
	Output                statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Raw one-time credential or JSON containing it."`
}

func serviceShareInput(message string) error {
	return failure.Wrap("validate service access", failure.InvalidCommand, errors.New(message))
}

func serviceShareResponse() error {
	return failure.Wrap("read service access", failure.ServerResponseInvalid, errors.New("control returned a different service access scope or invalid credential"))
}

func (f serviceShareDeadline) deadline(now time.Time, maximum time.Duration) (time.Time, error) {
	if (f.ExpiresAt == "") == (f.ExpiresIn == "") {
		return time.Time{}, serviceShareInput("set exactly one of --expires-at or --expires-in")
	}
	var at time.Time
	var err error
	if f.ExpiresAt != "" {
		at, err = time.Parse(time.RFC3339, f.ExpiresAt)
	} else {
		var duration time.Duration
		duration, err = parseShareLifetime(f.ExpiresIn)
		at = now.Add(duration)
	}
	if err != nil || !at.After(now) || at.After(now.Add(maximum)) {
		return time.Time{}, serviceShareInput("deadline must be in the future and within this command's maximum lifetime")
	}
	// postgresql stores invitation deadlines at microsecond precision.
	return at.UTC().Truncate(time.Microsecond), nil
}

// only configuration keys and immutable IDs select service access. saved names,
// public URL hostnames, and publisher group names are not fallback selectors.
func serviceShareKey(project projectConfiguration, name string) (string, error) {
	if opaqueid.Valid(name, opaqueid.ServicePrefix) {
		return "", nil
	}
	definition, found := project.Config.Services[name]
	if !found || name == "" {
		return "", serviceShareInput("select a configured service key or exact service ID")
	}
	if config.PublisherGroupName(definition) == "local" && config.IsPublicService(definition) {
		return "", serviceShareInput("this key selects a public URL; use tnl share invite, link, or token with its public URL")
	}
	return name, nil
}

func (project projectConfiguration) applyServiceShare(f *serviceShareSelection) error {
	key, err := serviceShareKey(project, f.Name)
	if err != nil {
		return err
	}
	effective, err := project.EffectiveService(key)
	if err != nil {
		return err
	}
	f.ServerURL, _, err = resolve.Server(f.ServerURL, effective.Server, f.AccessToken)
	if err == nil {
		f.ProjectTeam, err = resolve.TeamForServer(f.ServerURL, effective.Server, effective.Team)
	}
	return err
}

func selectServiceShare(ctx context.Context, s *clientteam.Session, project projectConfiguration, name string) (controlv1.Service, error) {
	key, err := serviceShareKey(project, name)
	if err != nil {
		return controlv1.Service{}, err
	}
	team := ""
	if key != "" || s.SelectedTeam() != "" || s.ProjectTeam() != "" {
		membership, err := s.CurrentMembership(ctx)
		if err != nil {
			return controlv1.Service{}, err
		}
		team = membership.TeamId
	}
	id := name
	var expectedSource *controlv1.LocalServiceSource
	if key != "" {
		expectedSource = &controlv1.LocalServiceSource{Service: key}
		if config.PublisherGroupName(project.Config.Services[key]) == "local" {
			source := project.LocalPublicationIdentity()
			expectedSource.ProjectKey, expectedSource.SourceFingerprint = source.Key, source.Fingerprint
			expectedSource.WorktreeKey = project.LocalWorktreeKey()
		} else {
			source, err := project.SourceIdentity(ctx)
			if err != nil {
				return controlv1.Service{}, failure.Wrap("identify service access project", failure.ProjectConfigInvalid, err)
			}
			expectedSource.ProjectKey, expectedSource.SourceFingerprint = source.Key, source.Fingerprint
		}
		// management inventory carries authoritative source bindings without
		// requiring a visitor grant for either local or applied services.
		services, err := s.Authenticated().Control.ListServices(ctx, team)
		if err != nil {
			return controlv1.Service{}, err
		}
		id = ""
		for _, service := range services {
			if service.TeamId != team {
				return controlv1.Service{}, serviceShareResponse()
			}
			if service.Source == nil || *service.Source != *expectedSource {
				continue
			}
			if !opaqueid.Valid(service.Id, opaqueid.ServicePrefix) {
				return controlv1.Service{}, serviceShareResponse()
			}
			if id != "" {
				return controlv1.Service{}, serviceShareInput("service source binding is ambiguous; use an exact service ID")
			}
			id = service.Id
		}
		if id == "" {
			return controlv1.Service{}, clientcontrol.ErrNotFound
		}
	}
	if !opaqueid.Valid(id, opaqueid.ServicePrefix) {
		return controlv1.Service{}, serviceShareResponse()
	}
	// the manager read and each mutation use the current person's control session.
	service, err := s.Authenticated().Control.GetService(ctx, id)
	if err != nil {
		return service, err
	}
	if service.Id != id || team != "" && service.TeamId != team || expectedSource != nil && (service.Source == nil || *service.Source != *expectedSource) {
		return controlv1.Service{}, serviceShareResponse()
	}
	return service, nil
}

func openServiceShare(ctx context.Context, f serviceShareSelection, project projectConfiguration, command string, d io.Writer) (*clientteam.Session, controlv1.Service, error) {
	if _, err := serviceShareKey(project, f.Name); err != nil {
		return nil, controlv1.Service{}, err
	}
	s, err := openTeamSession(ctx, f.selection(), command, d)
	if err != nil {
		return nil, controlv1.Service{}, err
	}
	service, err := selectServiceShare(ctx, s, project, f.Name)
	if err != nil {
		s.Close()
		return nil, service, err
	}
	return s, service, nil
}

func privateInvitationSecret(secret, id string) bool {
	return opaqueid.Valid(id, opaqueid.ServiceInvitationPrefix) && serviceShareSecret(secret, id)
}

func serviceShareSecret(secret, id string) bool {
	prefix, encoded, found := strings.Cut(secret, ".")
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	return found && prefix == id && len(encoded) == 43 && err == nil && len(raw) == 32
}

func runServiceShareInviteCreate(ctx context.Context, f serviceShareInviteCreateCommand, project projectConfiguration, o, d io.Writer) error {
	if f.IdempotencyKey != "" && (len(f.IdempotencyKey) > 128 || f.ExpiresAt == "") {
		return serviceShareInput("use a 1-128 byte --idempotency-key with --expires-at so retries keep the exact deadline")
	}
	at, err := f.deadline(time.Now(), 30*24*time.Hour)
	if err != nil {
		return err
	}
	s, service, err := openServiceShare(ctx, f.serviceShareSelection, project, "tnl share service invite create", d)
	if err != nil {
		return err
	}
	defer s.Close()
	return createServiceShareInvitation(ctx, s.Authenticated().Control, service.Id, f, at, o)
}

func createServiceShareInvitation(ctx context.Context, control *clientcontrol.Client, service string, f serviceShareInviteCreateCommand, at time.Time, o io.Writer) error {
	key := f.IdempotencyKey
	if key == "" {
		var err error
		key, err = randomIdempotencyKey()
		if err != nil {
			return err
		}
	}
	invite, err := control.InviteServiceVisitor(ctx, service, key, controlv1.CreateServiceInvitationRequest{Email: openapi_types.Email(f.Email), ExpiresAt: at})
	if err != nil {
		return err
	}
	if invite.ServiceId != service || !opaqueid.Valid(invite.Id, opaqueid.ServiceInvitationPrefix) || !strings.EqualFold(string(invite.Email), strings.TrimSpace(f.Email)) || !invite.ExpiresAt.Equal(at) || invite.Secret != nil && (!privateInvitationSecret(*invite.Secret, invite.Id) || invite.AcceptedAt != nil || invite.RevokedAt != nil) {
		return serviceShareResponse()
	}
	if f.Output == statusOutputJSON {
		return failure.Wrap("write service invitation", failure.OutputUnavailable, json.NewEncoder(o).Encode(invite))
	}
	if invite.Secret == nil {
		state := serviceShareState(&invite.ExpiresAt, invite.RevokedAt, time.Now())
		if state == "active" {
			state = "pending"
			if invite.AcceptedAt != nil {
				state = "accepted"
			}
		}
		return writeHumanFrame(o, "tnl share service invite create", "secret unavailable", "revoke this invitation, then create with a new key", clioutput.Fields(
			clioutput.Field{Label: "service ID", Value: service},
			clioutput.Field{Label: "invitation ID", Value: invite.Id},
			clioutput.Field{Label: "state", Value: state},
		), clioutput.Section("revoke", clioutput.Text("tnl share service revoke "+service+" "+invite.Id)))
	}
	_, err = fmt.Fprintln(o, *invite.Secret)
	return failure.Wrap("write service invitation secret", failure.OutputUnavailable, err)
}

func runServiceShareInviteAccept(ctx context.Context, f serviceShareInviteAcceptCommand, o, d io.Writer) error {
	id, _, _ := strings.Cut(f.Secret, ".")
	if !privateInvitationSecret(f.Secret, id) {
		return serviceShareInput("use a service invitation secret from tnl share service invite create")
	}
	s, err := openTeamSession(ctx, f.remoteFlags, "tnl share service invite accept", d)
	if err != nil {
		return err
	}
	defer s.Close()
	return acceptServiceShareInvitation(ctx, s.Authenticated().Control, f, o)
}

func acceptServiceShareInvitation(ctx context.Context, control *clientcontrol.Client, f serviceShareInviteAcceptCommand, o io.Writer) error {
	grant, err := control.AcceptServiceInvitation(ctx, f.Secret)
	if err != nil {
		return err
	}
	id, _, _ := strings.Cut(f.Secret, ".")
	if !validServiceShareGrant(grant, grant.ServiceId) || grant.Kind != "identity" || grant.InvitationId == nil || *grant.InvitationId != id || grant.IdentityId == nil || !opaqueid.Valid(*grant.IdentityId, opaqueid.IdentityPrefix) || grant.ExpiresAt == nil || grant.RevokedAt != nil {
		return serviceShareResponse()
	}
	if f.Output == statusOutputJSON {
		return failure.Wrap("write accepted service invitation", failure.OutputUnavailable, json.NewEncoder(o).Encode(grant))
	}
	return writeHumanFrame(o, "tnl share service invite accept", "accepted", "", clioutput.Fields(
		clioutput.Field{Label: "service ID", Value: grant.ServiceId},
		clioutput.Field{Label: "grant ID", Value: grant.Id},
		clioutput.Field{Label: "expires", Value: grant.ExpiresAt.UTC().Format(time.RFC3339)},
	))
}

func validServiceShareGrant(g controlv1.ServiceGrant, service string) bool {
	return opaqueid.Valid(service, opaqueid.ServicePrefix) && g.ServiceId == service && opaqueid.Valid(g.Id, opaqueid.ServiceGrantPrefix) && g.Kind.Valid()
}

func runServiceShareList(ctx context.Context, f serviceShareListCommand, project projectConfiguration, o, d io.Writer) error {
	s, service, err := openServiceShare(ctx, f.serviceShareSelection, project, "tnl share service list", d)
	if err != nil {
		return err
	}
	defer s.Close()
	return listServiceShares(ctx, s.Authenticated().Control, service.Id, f.Output, o)
}

func listServiceShares(ctx context.Context, control *clientcontrol.Client, service string, mode statusOutputMode, o io.Writer) error {
	grants, err := control.ListServiceGrants(ctx, service)
	if err != nil {
		return err
	}
	invitations, err := control.ListServiceInvitations(ctx, service)
	if err != nil {
		return err
	}
	for _, grant := range grants {
		if !validServiceShareGrant(grant, service) {
			return serviceShareResponse()
		}
	}
	for _, invite := range invitations {
		if invite.ServiceId != service || !opaqueid.Valid(invite.Id, opaqueid.ServiceInvitationPrefix) || invite.Secret != nil {
			return serviceShareResponse()
		}
	}
	httpGrants, err := control.ListServiceHTTPGrants(ctx, service)
	if err != nil {
		return err
	}
	for _, grant := range httpGrants {
		if grant.Subject.Kind != "service" || grant.Subject.Id != service || !opaqueid.Valid(grant.Id, "shg_") || !grant.Kind.Valid() || grant.ExpiresAt.IsZero() {
			return serviceShareResponse()
		}
	}
	if mode == statusOutputJSON {
		return failure.Wrap("write service access list", failure.OutputUnavailable, json.NewEncoder(o).Encode(struct {
			SchemaVersion int                                 `json:"schema_version"`
			ServiceID     string                              `json:"service_id"`
			Grants        []controlv1.ServiceGrant            `json:"grants"`
			Invitations   []controlv1.ServiceInvitation       `json:"invitations"`
			HTTPGrants    []controlv1.ServiceHTTPGrantSummary `json:"http_grants"`
		}{1, service, grants, invitations, httpGrants}))
	}
	now := time.Now()
	blocks := []clioutput.Block{clioutput.Fields(clioutput.Field{Label: "service ID", Value: service})}
	for _, grant := range grants {
		expires := "perpetual"
		if grant.ExpiresAt != nil {
			expires = grant.ExpiresAt.UTC().Format(time.RFC3339)
		}
		fields := []clioutput.Field{{Label: "kind", Value: string(grant.Kind)}, {Label: "state", Value: serviceShareState(grant.ExpiresAt, grant.RevokedAt, now)}, {Label: "expires", Value: expires}}
		if grant.IdentityId != nil {
			fields = append(fields, clioutput.Field{Label: "identity ID", Value: *grant.IdentityId})
		}
		if grant.InvitationId != nil {
			fields = append(fields, clioutput.Field{Label: "invitation ID", Value: *grant.InvitationId})
		}
		blocks = append(blocks, clioutput.Section(grant.Id, clioutput.Fields(fields...)))
	}
	for _, invite := range invitations {
		state := serviceShareState(&invite.ExpiresAt, invite.RevokedAt, now)
		if state == "active" {
			state = "pending"
			if invite.AcceptedAt != nil {
				state = "accepted"
			}
		}
		blocks = append(blocks, clioutput.Section(invite.Id, clioutput.Fields(
			clioutput.Field{Label: "email", Value: string(invite.Email)},
			clioutput.Field{Label: "state", Value: state},
			clioutput.Field{Label: "expires", Value: invite.ExpiresAt.UTC().Format(time.RFC3339)},
		)))
	}
	for _, grant := range httpGrants {
		blocks = append(blocks, clioutput.Section(grant.Id, clioutput.Fields(
			clioutput.Field{Label: "kind", Value: "http " + string(grant.Kind)},
			clioutput.Field{Label: "state", Value: serviceShareState(&grant.ExpiresAt, grant.RevokedAt, now)},
			clioutput.Field{Label: "expires", Value: grant.ExpiresAt.UTC().Format(time.RFC3339)},
		)))
	}
	return writeHumanFrame(o, "tnl share service list", "access", "", blocks...)
}

func serviceShareState(expires, revoked *time.Time, now time.Time) string {
	if revoked != nil {
		return "revoked"
	}
	if expires != nil && !expires.After(now) {
		return "expired"
	}
	return "active"
}

func serviceShareAccessID(id string) bool {
	return opaqueid.Valid(id, opaqueid.ServiceInvitationPrefix) || opaqueid.Valid(id, opaqueid.ServiceGrantPrefix) || opaqueid.Valid(id, "shg_")
}

func runServiceShareRevoke(ctx context.Context, f serviceShareRevokeCommand, project projectConfiguration, o, d io.Writer) error {
	if !serviceShareAccessID(f.ID) {
		return serviceShareInput("select an exact service invitation, identity grant, or service HTTP grant ID")
	}
	s, service, err := openServiceShare(ctx, f.serviceShareSelection, project, "tnl share service revoke", d)
	if err != nil {
		return err
	}
	defer s.Close()
	return revokeServiceShare(ctx, s.Authenticated().Control, service.Id, f, o)
}

func revokeServiceShare(ctx context.Context, control *clientcontrol.Client, service string, f serviceShareRevokeCommand, o io.Writer) error {
	var err error
	switch {
	case opaqueid.Valid(f.ID, opaqueid.ServiceInvitationPrefix):
		err = control.RevokeServiceInvitation(ctx, service, f.ID)
	case opaqueid.Valid(f.ID, opaqueid.ServiceGrantPrefix):
		// do not let this person-scoped workflow revoke a declared team grant.
		grants, listErr := control.ListServiceGrants(ctx, service)
		if listErr != nil {
			return listErr
		}
		found := false
		for _, grant := range grants {
			if !validServiceShareGrant(grant, service) {
				return serviceShareResponse()
			}
			if grant.Id == f.ID {
				if grant.Kind != "identity" {
					return serviceShareInput("this workflow revokes identity grants only; manage team access in project configuration")
				}
				found = true
			}
		}
		if !found {
			return clientcontrol.ErrNotFound
		}
		err = control.RevokeServiceGrant(ctx, service, f.ID)
	case opaqueid.Valid(f.ID, "shg_"):
		err = control.RevokeServiceHTTPGrant(ctx, service, f.ID)
	default:
		return serviceShareInput("select an exact service access ID")
	}
	if err != nil {
		return err
	}
	if f.Output == statusOutputJSON {
		return failure.Wrap("write service access revocation", failure.OutputUnavailable, json.NewEncoder(o).Encode(struct {
			ServiceID string `json:"service_id"`
			AccessID  string `json:"access_id"`
			Revoked   bool   `json:"revoked"`
		}{service, f.ID, true}))
	}
	return writeHumanFrame(o, "tnl share service revoke", "revoked", "", clioutput.Fields(
		clioutput.Field{Label: "service ID", Value: service}, clioutput.Field{Label: "access ID", Value: f.ID},
	))
}

func runServiceShareHTTPCreate(ctx context.Context, f serviceShareHTTPCreateCommand, project projectConfiguration, kind controlv1.CreateVisitorCredentialRequestKind, o, d io.Writer) error {
	at, err := f.deadline(time.Now(), 7*24*time.Hour)
	if err != nil {
		return err
	}
	s, service, err := openServiceShare(ctx, f.serviceShareSelection, project, "tnl share service", d)
	if err != nil {
		return err
	}
	defer s.Close()
	return createServiceShareHTTP(ctx, s.Authenticated().Control, service, f.Output, kind, at, o)
}

func createServiceShareHTTP(ctx context.Context, control *clientcontrol.Client, service controlv1.Service, mode statusOutputMode, kind controlv1.CreateVisitorCredentialRequestKind, at time.Time, o io.Writer) error {
	if service.Protocol != controlv1.ServiceProtocolHTTP || service.Endpoint == nil || !service.Endpoint.Public {
		return serviceShareInput("HTTP links and tokens require a publicly reachable service HTTP service; use an identity invitation for connector access")
	}
	credential, err := control.CreateVisitorCredential(ctx, controlv1.CreateVisitorCredentialRequest{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: service.Id}, Kind: kind, ExpiresAt: at})
	if err != nil {
		return err
	}
	permission := credential.Permission
	if permission.Resource.Kind != "service" || permission.Resource.Id != service.Id || permission.Hostname != service.Endpoint.Hostname || permission.Port != service.Endpoint.Port || permission.VisitorPolicyRevision < 1 || !permission.ExpiresAt.After(time.Now()) || permission.ExpiresAt.After(at.Truncate(time.Second)) || !opaqueid.Valid(credential.GrantId, "shg_") || !serviceShareSecret(strings.TrimPrefix(credential.RefreshCredential, "vrf1."), credential.GrantId) || !strings.HasPrefix(credential.RefreshCredential, "vrf1.") || len(permission.VisitorToken) == 0 || len(permission.VisitorToken) > visitortoken.MaxTokenBytes || strings.ContainsAny(permission.VisitorToken, "\x00\r\n\t ") || strings.Count(permission.VisitorToken, ".") != 2 {
		return serviceShareResponse()
	}
	// keep the command's JSON shape and exact raw one-time output while using
	// the common signed credential contract at the control boundary.
	grant := struct {
		Subject   controlv1.VisitorResourceScope `json:"subject"`
		ID        string                         `json:"id"`
		Kind      string                         `json:"kind"`
		Secret    string                         `json:"secret"`
		ShareURL  *string                        `json:"share_url,omitempty"`
		ExpiresAt time.Time                      `json:"expires_at"`
	}{Subject: permission.Resource, ID: credential.GrantId, Kind: string(kind), Secret: permission.VisitorToken, ExpiresAt: permission.ExpiresAt}
	value := grant.Secret
	if kind == "share" {
		value = "https://" + net.JoinHostPort(service.Endpoint.Hostname, strconv.Itoa(service.Endpoint.Port)) + "/__tnl/share/" + grant.Secret
		grant.ShareURL = &value
	}
	if mode == statusOutputJSON {
		return failure.Wrap("write service HTTP credential", failure.OutputUnavailable, json.NewEncoder(o).Encode(grant))
	}
	_, err = fmt.Fprintln(o, value)
	return failure.Wrap("write service HTTP credential", failure.OutputUnavailable, err)
}
