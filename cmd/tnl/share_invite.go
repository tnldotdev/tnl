package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"

	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/clioutput"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type shareInviteCommand struct {
	Create shareInviteCreateCommand `cmd:""`
	Accept shareInviteAcceptCommand `cmd:""`
	List   shareInviteListCommand   `cmd:""`
	Revoke shareInviteRevokeCommand `cmd:""`
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
	item, err := resolveVisitorPublicURL(ctx, s, f.URL)
	if err != nil {
		return err
	}
	var secret [32]byte
	if _, err = rand.Read(secret[:]); err != nil {
		return err
	}
	digest := sha256.Sum256(secret[:])
	key, err := randomIdempotencyKey()
	if err != nil {
		return err
	}
	invite, err := s.Authenticated().Control.CreateVisitorInvitation(ctx, item.Id, key, controlv1.CreateVisitorInvitationRequest{Email: f.Email, TokenDigest: hex.EncodeToString(digest[:]), ExpiresAt: time.Now().Add(duration)})
	if err != nil {
		return err
	}
	// one-time credentials are raw stdout values, never framed or logged.
	_, err = io.WriteString(o, invite.Id+"."+base64.RawURLEncoding.EncodeToString(secret[:])+"\n")
	return err
}
func runShareInviteAccept(ctx context.Context, f shareInviteAcceptCommand, o, d io.Writer) error {
	s, err := openTeamSession(ctx, f.remoteFlags, "tnl share invite accept", d)
	if err != nil {
		return err
	}
	defer s.Close()
	grant, err := s.Authenticated().Control.AcceptVisitorInvitation(ctx, f.Secret)
	if err != nil {
		return err
	}
	fields := []clioutput.Field{{Label: "public URL ID", Value: grant.PublicUrlId}, {Label: "grant ID", Value: grant.Id}}
	return writeHumanFrame(o, "tnl share invite accept", "accepted", "", clioutput.Fields(fields...))
}
func runShareInviteList(ctx context.Context, f shareInviteListCommand, o, d io.Writer) error {
	s, err := openTeamSession(ctx, f.remoteFlags, "tnl share invite list", d)
	if err != nil {
		return err
	}
	defer s.Close()
	item, err := resolveVisitorPublicURL(ctx, s, f.URL)
	if err != nil {
		return err
	}
	invites, err := s.Authenticated().Control.ListVisitorInvitations(ctx, item.Id)
	if err != nil {
		return err
	}
	if f.Output == statusOutputJSON {
		return json.NewEncoder(o).Encode(invites)
	}
	blocks := []clioutput.Block{}
	for _, invite := range invites {
		fields := []clioutput.Field{{Label: "email", Value: invite.Email}, {Label: "expires", Value: invite.ExpiresAt.UTC().Format(time.RFC3339)}}
		blocks = append(blocks, clioutput.Section(invite.Id, clioutput.Fields(fields...)))
	}
	return writeHumanFrame(o, "tnl share invite list", countState(len(invites), "invitation", "invitations"), "", blocks...)
}
func runShareInviteRevoke(ctx context.Context, f shareInviteRevokeCommand, o, d io.Writer) error {
	s, err := openTeamSession(ctx, f.remoteFlags, "tnl share invite revoke", d)
	if err != nil {
		return err
	}
	defer s.Close()
	item, err := resolveVisitorPublicURL(ctx, s, f.URL)
	if err != nil {
		return err
	}
	if err = s.Authenticated().Control.RevokeVisitorInvitation(ctx, item.Id, f.InvitationID); err != nil {
		return err
	}
	return writeHumanFrame(o, "tnl share invite revoke", "revoked", "", clioutput.Fields(clioutput.Field{Label: "invitation ID", Value: f.InvitationID}))
}
