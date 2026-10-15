package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"time"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type urlVisitorTokenCreateCommand struct {
	scopedTeamFlags `embed:""`
	URL             string `arg:"" required:"" help:"Public URL ID, hostname, or HTTPS origin."`
	ExpiresIn       string `name:"expires-in" default:"1h" help:"Lifetime of the visitor credential, at most 30 days."`
	Name            string `name:"name" required:"" help:"Name of the caller that will use this credential."`
	Link            bool   `name:"link" help:"Print a browser link that redeems into a host-only cookie instead of a header token."`
}

type urlVisitorTokenListCommand struct {
	scopedTeamFlags `embed:""`
	URL             string `arg:"" required:""`
}

type urlVisitorTokenRevokeCommand struct {
	scopedTeamFlags `embed:""`
	URL             string `arg:"" required:""`
	TokenID         string `arg:"" required:""`
}

func runURLVisitorTokenCreate(ctx context.Context, flags urlVisitorTokenCreateCommand, out, diagnostics io.Writer) error {
	lifetime, err := time.ParseDuration(flags.ExpiresIn)
	if err != nil || lifetime <= 0 || lifetime > 30*24*time.Hour {
		return failure.Wrap("validate visitor token lifetime", failure.InvalidCommand, errors.New("visitor token lifetime must be greater than zero and at most 30 days"))
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl url access token create", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	item, err := resolveVisitorPublicURL(ctx, session, flags.URL)
	if err != nil {
		return err
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return err
	}
	digest := sha256.Sum256(secret[:])
	key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
	if err != nil {
		return err
	}
	grant, err := session.authenticated.Control.CreateVisitorToken(ctx, item.Id, key, controlv1.CreateVisitorTokenRequest{
		Label: flags.Name, TokenDigest: hex.EncodeToString(digest[:]), ExpiresAt: time.Now().Add(lifetime),
	})
	if err != nil {
		return err
	}
	value := grant.Id + "." + base64.RawURLEncoding.EncodeToString(secret[:])
	if flags.Link {
		value = "https://" + item.CanonicalHostname + "/__tnl/access/" + value
	}
	_, err = io.WriteString(out, value+"\n")
	return err
}

func runURLVisitorTokenList(ctx context.Context, flags urlVisitorTokenListCommand, out, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, flags.selection(), "tnl url access token list", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	item, err := resolveVisitorPublicURL(ctx, session, flags.URL)
	if err != nil {
		return err
	}
	grants, err := session.authenticated.Control.ListVisitorGrants(ctx, item.Id)
	if err != nil {
		return err
	}
	blocks := []clioutput.Block{}
	for _, grant := range grants {
		if string(grant.Kind) != "token" {
			continue
		}
		expiry := "unknown"
		if grant.ExpiresAt != nil {
			expiry = grant.ExpiresAt.UTC().Format(time.RFC3339)
		}
		blocks = append(blocks, clioutput.Section(grant.Id, clioutput.Fields(clioutput.Field{Label: "name", Value: grant.Label}, clioutput.Field{Label: "expires", Value: expiry})))
	}
	return writeHumanFrame(out, "tnl url access token list", "saved", "", blocks...)
}

func runURLVisitorTokenRevoke(ctx context.Context, flags urlVisitorTokenRevokeCommand, out, diagnostics io.Writer) error {
	if !opaqueid.Valid(flags.TokenID, opaqueid.VisitorTokenPrefix) {
		return failure.Wrap("validate visitor token ID", failure.InvalidCommand, errors.New("invalid visitor token ID"))
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl url access token revoke", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	item, err := resolveVisitorPublicURL(ctx, session, flags.URL)
	if err != nil {
		return err
	}
	if err := session.authenticated.Control.RevokeVisitorGrant(ctx, item.Id, flags.TokenID); err != nil {
		return err
	}
	return writeHumanFrame(out, "tnl url access token revoke", "revoked", "", clioutput.Fields(clioutput.Field{Label: "token ID", Value: flags.TokenID}))
}
