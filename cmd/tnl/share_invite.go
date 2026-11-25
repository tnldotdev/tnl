package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"
	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type shareInviteCommand struct {
	Create shareInviteCreateCommand
	Accept shareInviteAcceptCommand
	List   shareInviteListCommand
	Revoke shareInviteRevokeCommand
}
type shareInviteCreateCommand struct {
	remoteFlags `embed:""`
	URL         string `arg:"" required:""`
	Email       string `name:"email" required:""`
	ExpiresIn   string `name:"expires-in" default:"24h"`
}
type shareInviteAcceptCommand struct {
	remoteFlags `embed:""`
	Secret      string `arg:"" required:""`
}
type shareInviteListCommand struct {
	remoteFlags `embed:""`
	URL         string           `arg:"" required:""`
	Output      statusOutputMode `name:"output" enum:"human,json" default:"human"`
}
type shareInviteRevokeCommand struct {
	remoteFlags  `embed:""`
	URL          string `arg:"" required:""`
	InvitationID string `arg:"" required:""`
}

func runShareInviteCreate(ctx context.Context, f shareInviteCreateCommand, o, d io.Writer) error {
	duration, err := parseShareLifetime(f.ExpiresIn)
	if err != nil {
		return err
	}
	s, err := openTeamSession(ctx, f.remoteFlags, "tnl share invite create", d)
	if err != nil {
		return err
	}
	defer s.Close()
	return createShareInvitation(ctx, s, f, duration, o)
}

func createShareInvitation(ctx context.Context, s *clientteam.Session, f shareInviteCreateCommand, duration time.Duration, o io.Writer) error {
	item, err := resolveManagedService(ctx, s, f.URL)
	if err != nil {
		return err
	}
	key, err := randomIdempotencyKey()
	if err != nil {
		return err
	}
	at := time.Now().UTC().Add(duration).Truncate(time.Microsecond)
	invite, err := s.Authenticated().Control.InviteServiceVisitor(ctx, item.Id, key, controlv1.CreateServiceInvitationRequest{Email: openapi_types.Email(f.Email), ExpiresAt: at})
	if err != nil {
		return err
	}
	if !privateInvitationSecret(invite.Credential, invite.Invitation.Id) || invite.Invitation.ServiceId != item.Id || !strings.EqualFold(string(invite.Invitation.Email), strings.TrimSpace(f.Email)) || !invite.Invitation.ExpiresAt.Equal(at) || invite.Invitation.AcceptedAt != nil || invite.Invitation.RevokedAt != nil {
		return failure.Wrap("create visitor invitation", failure.ServerResponseInvalid, errors.New("server returned an incomplete invitation or another service"))
	}
	// one-time credentials are raw stdout values, never framed or logged.
	_, err = io.WriteString(o, invite.Credential+"\n")
	return err
}
func runShareInviteAccept(ctx context.Context, f shareInviteAcceptCommand, o, d io.Writer) error {
	s, err := openTeamSession(ctx, f.remoteFlags, "tnl share invite accept", d)
	if err != nil {
		return err
	}
	defer s.Close()
	grant, err := s.Authenticated().Control.AcceptServiceInvitation(ctx, f.Secret)
	if err != nil {
		return err
	}
	invitationID, _, _ := strings.Cut(f.Secret, ".")
	if !validServiceShareGrant(grant, grant.ServiceId) || grant.Kind != "identity" || grant.InvitationId == nil || *grant.InvitationId != invitationID || grant.IdentityId == nil || grant.ExpiresAt == nil || grant.RevokedAt != nil {
		return serviceShareResponse()
	}
	return writeAcceptedShare(o, grant)
}

func writeAcceptedShare(output io.Writer, grant controlv1.ServiceGrant) error {
	return writeResult(output, clioutput.Line("Access granted to "+grant.ServiceId),
		clioutput.Line("Expires: "+shareExpiry(*grant.ExpiresAt)), clioutput.Line("Grant: "+grant.Id))
}
func runShareInviteList(ctx context.Context, f shareInviteListCommand, o, d io.Writer) error {
	s, err := openTeamSession(ctx, f.remoteFlags, "tnl share invite list", d)
	if err != nil {
		return err
	}
	defer s.Close()
	item, err := resolveManagedService(ctx, s, f.URL)
	if err != nil {
		return err
	}
	invites, err := s.Authenticated().Control.ListServiceInvitations(ctx, item.Id)
	if err != nil {
		return err
	}
	if f.Output == statusOutputJSON {
		return json.NewEncoder(o).Encode(invites)
	}
	rows := make([][]string, 0, len(invites))
	for _, invite := range invites {
		rows = append(rows, []string{string(invite.Email), invitationState(invite, time.Now()), shareExpiry(invite.ExpiresAt), invite.Id})
	}
	return writeResult(o, clioutput.Table([]string{"EMAIL", "STATE", "EXPIRES", "INVITATION ID"}, rows, "No invitations."))
}
func runShareInviteRevoke(ctx context.Context, f shareInviteRevokeCommand, o, d io.Writer) error {
	s, err := openTeamSession(ctx, f.remoteFlags, "tnl share invite revoke", d)
	if err != nil {
		return err
	}
	defer s.Close()
	item, err := resolveManagedService(ctx, s, f.URL)
	if err != nil {
		return err
	}
	if err = s.Authenticated().Control.RevokeServiceInvitation(ctx, item.Id, f.InvitationID); err != nil {
		return err
	}
	return writeResult(o, clioutput.Line("Revoked invitation "+f.InvitationID))
}
