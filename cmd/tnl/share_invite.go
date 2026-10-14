package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type inviteShareCommand struct {
	Create inviteShareCreateCommand `cmd:"" help:"Invite a verified email address to one public URL."`
	Accept inviteShareAcceptCommand `cmd:"" help:"Accept an invitation for your verified email."`
}

type inviteShareCreateCommand struct {
	scopedTeamFlags `embed:""`
	URL             string           `arg:"" name:"url" required:"" help:"Public URL ID, hostname, HTTPS origin, or database hostname:port."`
	Email           string           `name:"email" required:"" help:"Recipient's verified account email."`
	ExpiresIn       string           `name:"expires-in" default:"7d" help:"Lifetime (at most 30d)."`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type inviteShareAcceptCommand struct {
	remoteFlags `embed:""`
	Secret      string           `arg:"" name:"secret" required:"" help:"One-time invitation secret from the issuer."`
	Output      statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

func runShareInviteCreate(ctx context.Context, flags inviteShareCreateCommand, output, diagnostics io.Writer) error {
	lifetime, err := parseShareLifetime(flags.ExpiresIn)
	if err != nil {
		return err
	}
	if strings.TrimSpace(flags.Email) == "" {
		return failure.Wrap("select invite recipient", failure.ShareInputInvalid, errors.New("provide a verified email address with --email"))
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl share invite create", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	routes, err := session.authenticated.Control.ListPublicURLs(ctx, current.team.Id)
	if err != nil {
		return err
	}
	selected, err := selectTeamSharePublicURL(flags.URL, routes)
	if err != nil {
		return err
	}
	if selected.ServiceProtocol != controlv1.Http && selected.ServiceProtocol != controlv1.Postgres &&
		selected.ServiceProtocol != controlv1.Mysql && selected.ServiceProtocol != controlv1.Redis {
		return failure.Wrap("select invite public URL", failure.ShareInputInvalid, errors.New("invite one HTTP app or database public URL"))
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("generate visitor invitation secret: %w", err)
	}
	digest := sha256.Sum256(secret)
	key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
	if err != nil {
		return err
	}
	invitation, err := session.authenticated.Control.CreateVisitorInvitation(ctx, key, controlv1.CreateVisitorInvitationRequest{
		TeamId: current.team.Id, PublicUrlId: selected.Id, Email: flags.Email,
		SecretFingerprint: hex.EncodeToString(digest[:]), ExpiresAt: time.Now().UTC().Add(lifetime),
	})
	if err != nil {
		return err
	}
	if !opaqueid.Valid(invitation.Id, opaqueid.SharePrefix) || invitation.TeamId != current.team.Id || invitation.PublicUrlId != selected.Id ||
		invitation.AcceptedAt != nil || invitation.RevokedAt != nil {
		return failure.Wrap("create named share", failure.ServerResponseInvalid, errors.New("server returned an invalid invitation"))
	}
	token := invitation.Id + "." + base64.RawURLEncoding.EncodeToString(secret)
	address, err := savedPublicAddress(selected)
	if err != nil {
		return err
	}
	if flags.Output == statusOutputJSON {
		return failure.Wrap("write invitation secret", failure.OutputUnavailable, json.NewEncoder(output).Encode(struct {
			controlv1.VisitorInvitation
			Secret string `json:"invite_secret"`
		}{invitation, token}))
	}
	if err := writeHumanFrame(output, "tnl share invite create", "invited", "", clioutput.Fields(
		clioutput.Field{Label: "public URL", Value: address},
		clioutput.Field{Label: "recipient", Value: invitation.Email},
		clioutput.Field{Label: "share ID", Value: invitation.Id},
		clioutput.Field{Label: "expires", Value: invitation.ExpiresAt.UTC().Format(time.RFC3339)},
	)); err != nil {
		return err
	}
	_, err = fmt.Fprintln(output, "invite secret: "+token)
	return failure.Wrap("write invitation secret", failure.OutputUnavailable, err)
}

func runShareInviteAccept(ctx context.Context, flags inviteShareAcceptCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, flags.remoteFlags, "tnl share invite accept", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	result, err := session.authenticated.Control.AcceptVisitorInvitation(ctx, flags.Secret)
	if err != nil {
		return err
	}
	if result.AcceptedIdentityId == nil || *result.AcceptedIdentityId != session.identity.Identity.Id || result.PublicUrlId == "" || result.TeamId == "" {
		return failure.Wrap("accept named share", failure.ServerResponseInvalid, errors.New("server returned an invitation for another identity"))
	}
	if flags.Output == statusOutputJSON {
		return failure.Wrap("write accepted share", failure.OutputUnavailable, json.NewEncoder(output).Encode(result))
	}
	return writeHumanFrame(output, "tnl share invite accept", "accepted", "tnl url list shows public URLs shared with you", clioutput.Fields(
		clioutput.Field{Label: "share ID", Value: result.Id},
		clioutput.Field{Label: "public URL ID", Value: result.PublicUrlId},
		clioutput.Field{Label: "expires", Value: result.ExpiresAt.UTC().Format(time.RFC3339)},
	))
}
