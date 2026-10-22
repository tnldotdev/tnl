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
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type serviceShareCommand struct {
	Invite serviceShareInviteCommand `cmd:"" help:"Invite a verified-email identity to exactly one service."`
	List   serviceShareListCommand   `cmd:"" help:"List exact-service identity/team grants and invitations, including expired and revoked entries."`
	Revoke serviceShareRevokeCommand `cmd:"" help:"Revoke one invitation (and its derived grant), identity grant, or managed HTTP credential."`
	Link   serviceShareLinkCommand   `cmd:"" help:"Create a bounded share link for a publicly reachable managed HTTP service."`
	Token  serviceShareTokenCommand  `cmd:"" help:"Create a bounded token for a publicly reachable managed HTTP service."`
}

type serviceShareInviteCommand struct {
	Create serviceShareInviteCreateCommand `cmd:"" help:"Print a one-use invitation secret or retry recovery details; requires --expires-at or --expires-in (at most 30d)."`
	Accept serviceShareInviteAcceptCommand `cmd:"" help:"Accept using the matching signed-in verified email; does not join a team."`
}

type serviceShareSelection struct {
	scopedTeamFlags `embed:""`
	Name            string `arg:"" name:"name" help:"Configured service key or exact private service ID (psvc_)."`
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
	Secret      string           `arg:"" name:"secret" help:"One-use private service invitation secret."`
	Output      statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type serviceShareListCommand struct {
	serviceShareSelection `embed:""`
	Output                statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}; lists access records without secrets."`
}

type serviceShareRevokeCommand struct {
	serviceShareSelection `embed:""`
	ID                    string           `arg:"" name:"access-id" help:"Invitation (psivt_), identity grant (psgr_), or managed HTTP grant (mhg_) ID."`
	Output                statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type serviceShareLinkCommand struct {
	Create serviceShareHTTPCreateCommand `cmd:"" help:"Print a one-time share URL; requires --expires-at or --expires-in (at most 7d)."`
}

type serviceShareTokenCommand struct {
	Create serviceShareHTTPCreateCommand `cmd:"" help:"Print a one-time Tnl-Access-Token value; requires --expires-at or --expires-in (at most 7d)."`
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
	if opaqueid.Valid(name, opaqueid.PrivateServicePrefix) {
		return "", nil
	}
	definition, found := project.Config.Services[name]
	if !found || name == "" {
		return "", serviceShareInput("select a configured service key or exact private service ID")
	}
	if config.PublisherName(definition) == "local" && config.IsPublicService(definition) {
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
	f.ServerURL, _, err = resolveProjectServer(f.ServerURL, effective.Server, f.AccessToken)
	if err == nil {
		f.ProjectTeam, err = projectTeamForServer(f.ServerURL, effective.Server, effective.Team)
	}
	return err
}

func selectServiceShare(ctx context.Context, s *teamSession, project projectConfiguration, name string) (controlv1.PrivateService, error) {
	key, err := serviceShareKey(project, name)
	if err != nil {
		return controlv1.PrivateService{}, err
	}
	team := ""
	if key != "" || s.selectedTeam != "" || s.projectTeam != "" {
		membership, err := s.currentMembership(ctx)
		if err != nil {
			return controlv1.PrivateService{}, err
		}
		team = membership.TeamId
	}
	id := name
	var expectedSource *controlv1.LocalServiceSource
	if key != "" {
		expectedSource = &controlv1.LocalServiceSource{Service: key}
		if config.PublisherName(project.Config.Services[key]) == "local" {
			source := project.LocalPublicationIdentity()
			expectedSource.ProjectKey, expectedSource.SourceFingerprint = source.Key, source.Fingerprint
			expectedSource.WorktreeKey = project.LocalWorktreeKey()
		} else {
			source, err := project.SourceIdentity(ctx)
			if err != nil {
				return controlv1.PrivateService{}, failure.Wrap("identify service access project", failure.ProjectConfigInvalid, err)
			}
			expectedSource.ProjectKey, expectedSource.SourceFingerprint = source.Key, source.Fingerprint
		}
		// management inventory carries authoritative source bindings without
		// requiring a visitor grant for either local or applied services.
		services, err := s.authenticated.Control.ListPrivateServices(ctx, team)
		if err != nil {
			return controlv1.PrivateService{}, err
		}
		id = ""
		for _, service := range services {
			if service.TeamId != team {
				return controlv1.PrivateService{}, serviceShareResponse()
			}
			if service.Source == nil || *service.Source != *expectedSource {
				continue
			}
			if !opaqueid.Valid(service.Id, opaqueid.PrivateServicePrefix) {
				return controlv1.PrivateService{}, serviceShareResponse()
			}
			if id != "" {
				return controlv1.PrivateService{}, serviceShareInput("service source binding is ambiguous; use an exact private service ID")
			}
			id = service.Id
		}
		if id == "" {
			return controlv1.PrivateService{}, controlclient.ErrNotFound
		}
	}
	if !opaqueid.Valid(id, opaqueid.PrivateServicePrefix) {
		return controlv1.PrivateService{}, serviceShareResponse()
	}
	// the manager read and each mutation use the current person's control session.
	service, err := s.authenticated.Control.GetPrivateService(ctx, id)
	if err != nil {
		return service, err
	}
	if service.Id != id || team != "" && service.TeamId != team || expectedSource != nil && (service.Source == nil || *service.Source != *expectedSource) {
		return controlv1.PrivateService{}, serviceShareResponse()
	}
	return service, nil
}

func openServiceShare(ctx context.Context, f serviceShareSelection, project projectConfiguration, command string, d io.Writer) (*teamSession, controlv1.PrivateService, error) {
	if _, err := serviceShareKey(project, f.Name); err != nil {
		return nil, controlv1.PrivateService{}, err
	}
	s, err := openTeamSession(ctx, f.selection(), command, d)
	if err != nil {
		return nil, controlv1.PrivateService{}, err
	}
	service, err := selectServiceShare(ctx, s, project, f.Name)
	if err != nil {
		s.Close()
		return nil, service, err
	}
	return s, service, nil
}

func privateInvitationSecret(secret, id string) bool {
	return opaqueid.Valid(id, opaqueid.PrivateServiceInvitationPrefix) && serviceShareSecret(secret, id)
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
	return createServiceShareInvitation(ctx, s.authenticated.Control, service.Id, f, at, o)
}

func createServiceShareInvitation(ctx context.Context, control *controlclient.Client, service string, f serviceShareInviteCreateCommand, at time.Time, o io.Writer) error {
	key := f.IdempotencyKey
	if key == "" {
		var err error
		key, err = randomIdempotencyKey()
		if err != nil {
			return err
		}
	}
	invite, err := control.InvitePrivateServiceVisitor(ctx, service, key, controlv1.CreatePrivateServiceInvitationRequest{Email: openapi_types.Email(f.Email), ExpiresAt: at})
	if err != nil {
		return err
	}
	if invite.PrivateServiceId != service || !opaqueid.Valid(invite.Id, opaqueid.PrivateServiceInvitationPrefix) || !strings.EqualFold(string(invite.Email), strings.TrimSpace(f.Email)) || !invite.ExpiresAt.Equal(at) || invite.Secret != nil && (!privateInvitationSecret(*invite.Secret, invite.Id) || invite.AcceptedAt != nil || invite.RevokedAt != nil) {
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
		return serviceShareInput("use a private service invitation secret from tnl share service invite create")
	}
	s, err := openTeamSession(ctx, f.remoteFlags, "tnl share service invite accept", d)
	if err != nil {
		return err
	}
	defer s.Close()
	return acceptServiceShareInvitation(ctx, s.authenticated.Control, f, o)
}

func acceptServiceShareInvitation(ctx context.Context, control *controlclient.Client, f serviceShareInviteAcceptCommand, o io.Writer) error {
	grant, err := control.AcceptPrivateServiceInvitation(ctx, f.Secret)
	if err != nil {
		return err
	}
	id, _, _ := strings.Cut(f.Secret, ".")
	if !validServiceShareGrant(grant, grant.PrivateServiceId) || grant.Kind != "identity" || grant.InvitationId == nil || *grant.InvitationId != id || grant.IdentityId == nil || !opaqueid.Valid(*grant.IdentityId, opaqueid.IdentityPrefix) || grant.ExpiresAt == nil || grant.RevokedAt != nil {
		return serviceShareResponse()
	}
	if f.Output == statusOutputJSON {
		return failure.Wrap("write accepted service invitation", failure.OutputUnavailable, json.NewEncoder(o).Encode(grant))
	}
	return writeHumanFrame(o, "tnl share service invite accept", "accepted", "", clioutput.Fields(
		clioutput.Field{Label: "service ID", Value: grant.PrivateServiceId},
		clioutput.Field{Label: "grant ID", Value: grant.Id},
		clioutput.Field{Label: "expires", Value: grant.ExpiresAt.UTC().Format(time.RFC3339)},
	))
}

func validServiceShareGrant(g controlv1.PrivateServiceGrant, service string) bool {
	return opaqueid.Valid(service, opaqueid.PrivateServicePrefix) && g.PrivateServiceId == service && opaqueid.Valid(g.Id, opaqueid.PrivateServiceGrantPrefix) && g.Kind.Valid()
}

func runServiceShareList(ctx context.Context, f serviceShareListCommand, project projectConfiguration, o, d io.Writer) error {
	s, service, err := openServiceShare(ctx, f.serviceShareSelection, project, "tnl share service list", d)
	if err != nil {
		return err
	}
	defer s.Close()
	return listServiceShares(ctx, s.authenticated.Control, service.Id, f.Output, o)
}

func listServiceShares(ctx context.Context, control *controlclient.Client, service string, mode statusOutputMode, o io.Writer) error {
	grants, err := control.ListPrivateServiceGrants(ctx, service)
	if err != nil {
		return err
	}
	invitations, err := control.ListPrivateServiceInvitations(ctx, service)
	if err != nil {
		return err
	}
	for _, grant := range grants {
		if !validServiceShareGrant(grant, service) {
			return serviceShareResponse()
		}
	}
	for _, invite := range invitations {
		if invite.PrivateServiceId != service || !opaqueid.Valid(invite.Id, opaqueid.PrivateServiceInvitationPrefix) || invite.Secret != nil {
			return serviceShareResponse()
		}
	}
	httpGrants, err := control.ListManagedHTTPGrants(ctx, service)
	if err != nil {
		return err
	}
	for _, grant := range httpGrants {
		if grant.Subject.Kind != "managed_service" || grant.Subject.Id != service || !opaqueid.Valid(grant.Id, "mhg_") || !grant.Kind.Valid() || grant.ExpiresAt.IsZero() {
			return serviceShareResponse()
		}
	}
	if mode == statusOutputJSON {
		return failure.Wrap("write service access list", failure.OutputUnavailable, json.NewEncoder(o).Encode(struct {
			SchemaVersion    int                                  `json:"schema_version"`
			PrivateServiceID string                               `json:"private_service_id"`
			Grants           []controlv1.PrivateServiceGrant      `json:"grants"`
			Invitations      []controlv1.PrivateServiceInvitation `json:"invitations"`
			HTTPGrants       []controlv1.ManagedHTTPGrantSummary  `json:"http_grants"`
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
	return opaqueid.Valid(id, opaqueid.PrivateServiceInvitationPrefix) || opaqueid.Valid(id, opaqueid.PrivateServiceGrantPrefix) || opaqueid.Valid(id, "mhg_")
}

func runServiceShareRevoke(ctx context.Context, f serviceShareRevokeCommand, project projectConfiguration, o, d io.Writer) error {
	if !serviceShareAccessID(f.ID) {
		return serviceShareInput("select an exact service invitation, identity grant, or managed HTTP grant ID")
	}
	s, service, err := openServiceShare(ctx, f.serviceShareSelection, project, "tnl share service revoke", d)
	if err != nil {
		return err
	}
	defer s.Close()
	return revokeServiceShare(ctx, s.authenticated.Control, service.Id, f, o)
}

func revokeServiceShare(ctx context.Context, control *controlclient.Client, service string, f serviceShareRevokeCommand, o io.Writer) error {
	var err error
	switch {
	case opaqueid.Valid(f.ID, opaqueid.PrivateServiceInvitationPrefix):
		err = control.RevokePrivateServiceInvitation(ctx, service, f.ID)
	case opaqueid.Valid(f.ID, opaqueid.PrivateServiceGrantPrefix):
		// do not let this person-scoped workflow revoke a declared team grant.
		grants, listErr := control.ListPrivateServiceGrants(ctx, service)
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
			return controlclient.ErrNotFound
		}
		err = control.RevokePrivateServiceGrant(ctx, service, f.ID)
	case opaqueid.Valid(f.ID, "mhg_"):
		err = control.RevokeManagedHTTPGrant(ctx, service, f.ID)
	default:
		return serviceShareInput("select an exact service access ID")
	}
	if err != nil {
		return err
	}
	if f.Output == statusOutputJSON {
		return failure.Wrap("write service access revocation", failure.OutputUnavailable, json.NewEncoder(o).Encode(struct {
			PrivateServiceID string `json:"private_service_id"`
			AccessID         string `json:"access_id"`
			Revoked          bool   `json:"revoked"`
		}{service, f.ID, true}))
	}
	return writeHumanFrame(o, "tnl share service revoke", "revoked", "", clioutput.Fields(
		clioutput.Field{Label: "service ID", Value: service}, clioutput.Field{Label: "access ID", Value: f.ID},
	))
}

func runServiceShareHTTPCreate(ctx context.Context, f serviceShareHTTPCreateCommand, project projectConfiguration, kind controlv1.CreateManagedHTTPGrantRequestKind, o, d io.Writer) error {
	at, err := f.deadline(time.Now(), 7*24*time.Hour)
	if err != nil {
		return err
	}
	s, service, err := openServiceShare(ctx, f.serviceShareSelection, project, "tnl share service", d)
	if err != nil {
		return err
	}
	defer s.Close()
	return createServiceShareHTTP(ctx, s.authenticated.Control, service, f.Output, kind, at, o)
}

func createServiceShareHTTP(ctx context.Context, control *controlclient.Client, service controlv1.PrivateService, mode statusOutputMode, kind controlv1.CreateManagedHTTPGrantRequestKind, at time.Time, o io.Writer) error {
	if service.Protocol != controlv1.PrivateHttp || service.ManagedTls == nil || !service.ManagedTls.Public {
		return serviceShareInput("HTTP links and tokens require a publicly reachable managed HTTP service; use an identity invitation for connector access")
	}
	grant, err := control.CreateManagedHTTPGrant(ctx, service.Id, controlv1.CreateManagedHTTPGrantRequest{Kind: kind, ExpiresAt: at})
	if err != nil {
		return err
	}
	if grant.Subject.Kind != "managed_service" || grant.Subject.Id != service.Id || string(grant.Kind) != string(kind) || !grant.ExpiresAt.Equal(at) || !opaqueid.Valid(grant.Id, "mhg_") || !serviceShareSecret(grant.Secret, grant.Id) {
		return serviceShareResponse()
	}
	value := grant.Secret
	if kind == controlv1.CreateManagedHTTPGrantRequestKindToken && grant.ShareUrl != nil {
		return serviceShareResponse()
	}
	if kind == controlv1.CreateManagedHTTPGrantRequestKindShare {
		expected := "https://" + net.JoinHostPort(service.ManagedTls.Hostname, strconv.Itoa(service.ManagedTls.Port)) + "/__tnl/share/" + grant.Secret
		if grant.ShareUrl == nil || *grant.ShareUrl != expected {
			return serviceShareResponse()
		}
		value = *grant.ShareUrl
	}
	if mode == statusOutputJSON {
		return failure.Wrap("write managed HTTP credential", failure.OutputUnavailable, json.NewEncoder(o).Encode(grant))
	}
	_, err = fmt.Fprintln(o, value)
	return failure.Wrap("write managed HTTP credential", failure.OutputUnavailable, err)
}
