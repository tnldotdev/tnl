package main

import (
	"context"
	"errors"
	"io"
	"net/netip"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type urlAccessCommand struct {
	Show urlAccessShowCommand `cmd:"" help:"Show the saved visitor access policy."`
	Set  urlAccessSetCommand  `cmd:"" help:"Replace the complete visitor access policy, including its IP list, without stopping the publisher."`
}

type urlAccessShowCommand struct {
	scopedTeamFlags `embed:""`
	URL             string `arg:"" required:"" help:"Public URL ID, hostname, or HTTPS origin."`
}

type urlAccessSetCommand struct {
	urlAccessShowCommand `embed:""`
	Mode                 controlv1.VisitorAccessMode `arg:"" enum:"restricted,anonymous" required:"" help:"Require a tnl visitor credential or admit visitors anonymously."`
	IP                   []string                    `name:"ip" help:"Restrict source IPs to an address, CIDR, or 'current'. Repeat to allow several networks."`
}

func writeAccessPolicy(out io.Writer, command string, item controlv1.PublicURL) error {
	fields := []clioutput.Field{{Label: "public URL", Value: item.CanonicalHostname}, {Label: "access", Value: string(item.AccessMode)}}
	if item.AllowedIpPrefixes == nil || len(*item.AllowedIpPrefixes) == 0 {
		fields = append(fields, clioutput.Field{Label: "IP filter", Value: "none"})
	} else {
		for _, prefix := range *item.AllowedIpPrefixes {
			fields = append(fields, clioutput.Field{Label: "IP", Value: prefix})
		}
	}
	hint := "new visitor work uses this policy"
	if command == "tnl url access set" {
		hint = "project config with access set reapplies on the next start"
	}
	return writeHumanFrame(out, command, "saved", hint, clioutput.Fields(fields...))
}

func runURLAccessShow(ctx context.Context, flags urlAccessShowCommand, out, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, flags.selection(), "tnl url access show", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	item, err := resolveManagedPublicURL(ctx, session, flags.URL)
	if err != nil {
		return err
	}
	return writeAccessPolicy(out, "tnl url access show", item)
}

func resolveManagedPublicURL(ctx context.Context, session *teamSession, selector string) (controlv1.PublicURL, error) {
	current, err := session.current(ctx)
	if err != nil {
		return controlv1.PublicURL{}, err
	}
	routes, err := session.authenticated.Control.ListPublicURLs(ctx, current.team.Id)
	if err != nil {
		return controlv1.PublicURL{}, err
	}
	return selectSharePublicURL(selector, routes)
}

func accessIPPrefixes(ctx context.Context, control interface {
	ClientIP(context.Context) (controlv1.ClientIPResponse, error)
}, values []string) ([]string, error) {
	input := make([]string, 0, len(values))
	for _, value := range values {
		if value == "current" {
			current, err := control.ClientIP(ctx)
			if err != nil {
				return nil, err
			}
			address, err := netip.ParseAddr(current.Ip)
			if err != nil || address.Zone() != "" {
				return nil, errors.New("control returned an invalid current IP")
			}
			address = address.Unmap()
			value = netip.PrefixFrom(address, address.BitLen()).String()
		}
		input = append(input, value)
	}
	result, err := authorization.CanonicalizeIPPrefixes(input)
	if err != nil || len(result) > 256 {
		return nil, failure.Wrap("validate visitor IP list", failure.InvalidCommand, errors.New("IP list must contain at most 256 distinct addresses or prefixes"))
	}
	return append([]string{}, result...), nil
}

func runURLAccessSet(ctx context.Context, flags urlAccessSetCommand, out, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, flags.selection(), "tnl url access set", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	item, err := resolveManagedPublicURL(ctx, session, flags.URL)
	if err != nil {
		return err
	}
	ips, err := accessIPPrefixes(ctx, session.authenticated.Control, flags.IP)
	if err != nil {
		return err
	}
	item, err = session.authenticated.Control.ReplaceVisitorAccess(ctx, item.Id, controlv1.ReplaceVisitorAccessRequest{
		Mode: flags.Mode, Ip: ips, ExpectedRevision: item.MutationRevision,
	})
	if err != nil {
		return err
	}
	return writeAccessPolicy(out, "tnl url access set", item)
}
