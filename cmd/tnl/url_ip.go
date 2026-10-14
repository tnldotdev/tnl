package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type publicURLIPCommand struct {
	Set    publicURLIPSetCommand    `cmd:"" help:"Replace durable visitor IP entries without stopping publication."`
	Add    publicURLIPAddCommand    `cmd:"" help:"Allow a visitor IP for a limited time."`
	List   publicURLIPListCommand   `cmd:"" help:"List current expiring visitor IP entries."`
	Remove publicURLIPRemoveCommand `cmd:"" help:"Revoke an expiring visitor IP entry."`
}

type publicURLIPFlags struct {
	scopedTeamFlags `embed:""`
	PublicURLID     string `arg:"" name:"public-url-id" required:""`
}

type publicURLIPSetCommand struct {
	publicURLIPFlags `embed:""`
	AllowIP          []string `name:"allow-ip" help:"Durable visitor address or prefix; repeat for more visitors."`
	AllowAllIPs      bool     `name:"allow-all-ips" help:"Allow every visitor instead of a durable IP allowlist."`
}

type publicURLIPAddCommand struct {
	publicURLIPFlags `embed:""`
	IP               string           `arg:"" name:"ip" required:""`
	For              time.Duration    `name:"for" default:"1h" help:"Visitor IP lifetime, from 1m to 24h."`
	Output           statusOutputMode `name:"output" enum:"human,json" default:"human"`
}

type publicURLIPListCommand struct {
	publicURLIPFlags `embed:""`
	Output           statusOutputMode `name:"output" enum:"human,json" default:"human"`
}

type publicURLIPRemoveCommand struct {
	publicURLIPFlags `embed:""`
	EntryID          string `arg:"" name:"entry-id" required:""`
}

func openURLIPSession(ctx context.Context, flags publicURLIPFlags, command string, diagnostics io.Writer) (*teamSession, error) {
	if !opaqueid.Valid(flags.PublicURLID, opaqueid.PublicURLPrefix) {
		return nil, failure.Wrap("select public URL IP policy", failure.InvalidTunnelFlags, errors.New("pass a saved public URL ID"))
	}
	session, err := openTeamSession(ctx, flags.selection(), command, diagnostics)
	if err != nil {
		return nil, err
	}
	current, err := session.current(ctx)
	if err == nil {
		var route controlv1.PublicURL
		route, err = session.authenticated.Control.GetPublicURL(ctx, flags.PublicURLID)
		if err == nil && route.TeamId != current.team.Id {
			err = controlclient.ErrNotFound
		}
	}
	if err != nil {
		session.Close()
		return nil, err
	}
	return session, nil
}

func runURLIPSet(ctx context.Context, command publicURLIPSetCommand, output, diagnostics io.Writer) error {
	if command.AllowAllIPs == (len(command.AllowIP) != 0) {
		return failure.Wrap("set visitor IP policy", failure.InvalidTunnelFlags,
			errors.New("pass --allow-ip at least once, or --allow-all-ips"))
	}
	prefixes := []string{}
	if !command.AllowAllIPs {
		var err error
		prefixes, err = authorization.CanonicalizeIPPrefixes(command.AllowIP)
		if err != nil {
			return failure.Wrap("set visitor IP policy", failure.InvalidTunnelFlags, err)
		}
	}
	session, err := openURLIPSession(ctx, command.publicURLIPFlags, "tnl url ip set", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	route, err := session.authenticated.Control.ReplacePublicURLIPPolicy(ctx, command.PublicURLID, prefixes)
	if err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl url ip set", "updated", "new visitor connections use the changed policy",
		clioutput.Fields(clioutput.Field{Label: "URL ID", Value: route.Id}))
}

func runURLIPAdd(ctx context.Context, command publicURLIPAddCommand, output, diagnostics io.Writer) error {
	if command.For < time.Minute || command.For > 24*time.Hour || command.For%time.Second != 0 {
		return failure.Wrap("allow visitor IP", failure.InvalidTunnelFlags, errors.New("--for must be whole seconds between 1m and 24h"))
	}
	canonical, err := authorization.CanonicalizeIPPrefixes([]string{command.IP})
	if err != nil {
		return failure.Wrap("allow visitor IP", failure.InvalidTunnelFlags, err)
	}
	session, err := openURLIPSession(ctx, command.publicURLIPFlags, "tnl url ip add", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	entry, err := session.authenticated.Control.AddOperatorIP(ctx, command.PublicURLID, canonical[0], command.For)
	if err != nil {
		return err
	}
	if command.Output == statusOutputJSON {
		return json.NewEncoder(output).Encode(entry)
	}
	return writeHumanFrame(output, "tnl url ip add", "allowed", "new visitors from this IP may connect until expiry",
		clioutput.Fields(clioutput.Field{Label: "IP", Value: entry.Prefix},
			clioutput.Field{Label: "entry", Value: entry.Id},
			clioutput.Field{Label: "expires", Value: entry.ExpiresAt.UTC().Format(time.RFC3339)}))
}

func runURLIPList(ctx context.Context, command publicURLIPListCommand, output, diagnostics io.Writer) error {
	session, err := openURLIPSession(ctx, command.publicURLIPFlags, "tnl url ip list", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	entries, err := session.authenticated.Control.ListOperatorIPs(ctx, command.PublicURLID)
	if err != nil {
		return err
	}
	if command.Output == statusOutputJSON {
		return json.NewEncoder(output).Encode(struct {
			SchemaVersion int                         `json:"schema_version"`
			Entries       []controlv1.OperatorIPEntry `json:"entries"`
		}{1, entries})
	}
	fields := make([]clioutput.Field, 0, len(entries)*3+1)
	fields = append(fields, clioutput.Field{Label: "URL ID", Value: command.PublicURLID})
	for _, entry := range entries {
		fields = append(fields, clioutput.Field{Label: "IP", Value: entry.Prefix},
			clioutput.Field{Label: "entry", Value: entry.Id},
			clioutput.Field{Label: "expires", Value: entry.ExpiresAt.UTC().Format(time.RFC3339)})
	}
	state := "allowed"
	if len(entries) == 0 {
		state = "none"
	}
	return writeHumanFrame(output, "tnl url ip list", state, "durable source entries are set with tnl url ip set", clioutput.Fields(fields...))
}

func runURLIPRemove(ctx context.Context, command publicURLIPRemoveCommand, output, diagnostics io.Writer) error {
	if !opaqueid.Valid(command.EntryID, opaqueid.IPPolicyEntryPrefix) {
		return failure.Wrap("revoke visitor IP", failure.InvalidTunnelFlags, fmt.Errorf("invalid operator IP entry ID %q", command.EntryID))
	}
	session, err := openURLIPSession(ctx, command.publicURLIPFlags, "tnl url ip remove", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	if err := session.authenticated.Control.RemoveOperatorIP(ctx, command.PublicURLID, command.EntryID); err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl url ip remove", "revoked", "new visitors from this entry are no longer allowed",
		clioutput.Fields(clioutput.Field{Label: "entry", Value: command.EntryID}))
}
