package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type urlIPCommand struct {
	Set    urlIPSetCommand    `cmd:""`
	Add    urlIPAddCommand    `cmd:""`
	List   urlIPListCommand   `cmd:""`
	Remove urlIPRemoveCommand `cmd:""`
}
type urlIPSetCommand struct {
	remoteFlags `embed:""`
	URL         string           `arg:"" required:""`
	Prefixes    []string         `arg:"" optional:""`
	ExpiresIn   string           `name:"expires-in"`
	Output      statusOutputMode `name:"output" enum:"human,json" default:"human"`
}
type urlIPAddCommand struct {
	remoteFlags `embed:""`
	URL         string           `arg:"" required:""`
	Prefix      string           `arg:"" required:""`
	ExpiresIn   string           `name:"expires-in"`
	Output      statusOutputMode `name:"output" enum:"human,json" default:"human"`
}
type urlIPListCommand struct {
	remoteFlags `embed:""`
	URL         string           `arg:"" required:""`
	Output      statusOutputMode `name:"output" enum:"human,json" default:"human"`
}
type urlIPRemoveCommand struct {
	remoteFlags `embed:""`
	URL         string           `arg:"" required:""`
	GrantID     string           `arg:"" required:""`
	Output      statusOutputMode `name:"output" enum:"human,json" default:"human"`
}

func runURLIPSet(ctx context.Context, f urlIPSetCommand, o, d io.Writer) error {
	return runURLIPs(ctx, f.remoteFlags, f.URL, "set", "", f.Prefixes, f.ExpiresIn, f.Output, o, d)
}
func runURLIPAdd(ctx context.Context, f urlIPAddCommand, o, d io.Writer) error {
	return runURLIPs(ctx, f.remoteFlags, f.URL, "add", "", []string{f.Prefix}, f.ExpiresIn, f.Output, o, d)
}
func runURLIPList(ctx context.Context, f urlIPListCommand, o, d io.Writer) error {
	return runURLIPs(ctx, f.remoteFlags, f.URL, "list", "", nil, "", f.Output, o, d)
}
func runURLIPRemove(ctx context.Context, f urlIPRemoveCommand, o, d io.Writer) error {
	return runURLIPs(ctx, f.remoteFlags, f.URL, "remove", f.GrantID, nil, "", f.Output, o, d)
}
func runURLIPs(ctx context.Context, f remoteFlags, selector, operation, id string, prefixes []string, lifetime string, mode statusOutputMode, o, d io.Writer) error {
	var expires *time.Time
	if lifetime != "" {
		duration, err := time.ParseDuration(lifetime)
		if err != nil || duration <= 0 {
			return failure.Wrap("validate IP grant lifetime", failure.InvalidCommand, errors.New("IP grant lifetime must be greater than zero"))
		}
		at := time.Now().Add(duration)
		expires = &at
	}
	input := make([]controlv1.VisitorIPGrantInput, len(prefixes))
	for i, raw := range prefixes {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			addr, e := netip.ParseAddr(raw)
			if e != nil {
				return failure.Wrap("validate IP address or prefix", failure.InvalidCommand, e)
			}
			addr = addr.Unmap()
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		input[i] = controlv1.VisitorIPGrantInput{Prefix: prefix.Masked().String(), ExpiresAt: expires}
	}
	s, err := openTeamSession(ctx, f, "tnl url ip "+operation, d)
	if err != nil {
		return err
	}
	defer s.Close()
	item, err := resolveVisitorPublicURL(ctx, s, selector)
	if err != nil {
		return err
	}
	var result []controlv1.VisitorIPGrant
	switch operation {
	case "set":
		result, err = s.authenticated.Control.SetVisitorIPGrants(ctx, item.Id, input)
	case "add":
		result, err = s.authenticated.Control.AddVisitorIPGrant(ctx, item.Id, input[0])
	case "list":
		result, err = s.authenticated.Control.ListVisitorIPGrants(ctx, item.Id)
	case "remove":
		err = s.authenticated.Control.RemoveVisitorIPGrant(ctx, item.Id, id)
	}
	if err != nil {
		return err
	}
	if mode == statusOutputJSON {
		return json.NewEncoder(o).Encode(result)
	}
	blocks := []clioutput.Block{clioutput.Fields(clioutput.Field{Label: "public URL ID", Value: item.Id})}
	for _, grant := range result {
		expiry := "perpetual"
		if grant.ExpiresAt != nil {
			expiry = grant.ExpiresAt.UTC().Format(time.RFC3339)
		}
		blocks = append(blocks, clioutput.Section(grant.Id, clioutput.Fields(clioutput.Field{Label: "IP", Value: grant.Prefix}, clioutput.Field{Label: "expires", Value: expiry})))
	}
	return writeHumanFrame(o, "tnl url ip "+operation, "current", "new connections use this IP set", blocks...)
}

type urlAvailableCommand struct {
	remoteFlags `embed:""`
	Output      statusOutputMode `name:"output" enum:"human,json" default:"human"`
}

func runURLAvailable(ctx context.Context, f urlAvailableCommand, o, d io.Writer) error {
	s, err := openTeamSession(ctx, f.remoteFlags, "tnl url available", d)
	if err != nil {
		return err
	}
	defer s.Close()
	items := []controlv1.AvailablePublicURL{}
	cursor := ""
	for {
		page, err := s.authenticated.Control.ListAvailablePublicURLs(ctx, "", cursor)
		if err != nil {
			return err
		}
		items = append(items, page.PublicUrls...)
		if page.NextCursor == nil {
			break
		}
		if *page.NextCursor == cursor {
			return failure.Wrap("read visitor inventory", failure.ServerResponseInvalid, errors.New("invalid visitor inventory cursor"))
		}
		cursor = *page.NextCursor
	}
	if f.Output == statusOutputJSON {
		return json.NewEncoder(o).Encode(items)
	}
	blocks := make([]clioutput.Block, 0, len(items))
	for _, item := range items {
		blocks = append(blocks, clioutput.Section(item.CanonicalHostname, clioutput.Fields(clioutput.Field{Label: "public URL ID", Value: item.Id}, clioutput.Field{Label: "team", Value: item.TeamName}, clioutput.Field{Label: "protocol", Value: item.ServiceProtocol}, clioutput.Field{Label: "access", Value: string(item.VisitorAccess)})))
	}
	return writeHumanFrame(o, "tnl url available", countState(len(items), "public URL", "public URLs"), "", blocks...)
}
