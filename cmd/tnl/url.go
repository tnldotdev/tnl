package main

import (
	"context"
	"errors"
	"io"
	"strconv"
	"time"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type publicURLCommand struct {
	List       publicURLListCommand       `cmd:"" help:"List public URLs for the selected team."`
	Update     publicURLUpdateCommand     `cmd:"" help:"Change a saved public URL target or visitor policy."`
	Delete     publicURLDeleteCommand     `cmd:"" help:"Delete a public URL by ID; use tnl url list to find it."`
	Credential publicURLCredentialCommand `cmd:"" help:"Manage credentials scoped to publishing one public URL."`
}

type publicURLUpdateCommand struct {
	scopedTeamFlags `embed:""`
	PublicURLID     string   `arg:"" name:"public-url-id" required:""`
	Target          string   `name:"target" help:"New HTTP or HTTPS target origin; no connection is made from this command."`
	AllowIP         []string `name:"allow-ip" help:"Replace visitor addresses; repeat for each address or prefix."`
	AllowAllIPs     bool     `name:"allow-all-ips" help:"Allow visitors from every IP."`
	Keep            bool     `name:"keep" help:"Keep this saved public URL indefinitely instead of retiring it when idle."`
	AutoRetire      bool     `name:"auto-retire" help:"Resume retirement after 180 idle days and a 30-day recovery window."`
}

type publicURLListCommand struct {
	scopedTeamFlags `embed:""`
}

type publicURLDeleteCommand struct {
	scopedTeamFlags `embed:""`
	PublicURLID     string `arg:"" name:"public-url-id" required:"" help:"Public URL ID to delete."`
}

func runURLList(ctx context.Context, command publicURLListCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.selection(), "tnl url list", diagnostics)
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
	blocks := []clioutput.Block{clioutput.Fields(
		clioutput.Field{Label: "server", Value: session.authenticated.ServerEndpoint},
		clioutput.Field{Label: "team", Value: current.team.DisplayName},
	)}
	for _, route := range routes {
		fields := []clioutput.Field{
			clioutput.Field{Label: "scope", Value: string(route.PublicUrlScope)},
			clioutput.Field{Label: "state", Value: string(route.LifecycleState)},
			clioutput.Field{Label: "next publish run number", Value: strconv.FormatInt(route.NextPublishRunNumber, 10)},
			clioutput.Field{Label: "public URL ID", Value: route.Id},
		}
		if route.ServiceProtocol == controlv1.Postgres || route.ServiceProtocol == controlv1.Mysql {
			address, err := savedPublicAddress(route)
			if err != nil {
				return err
			}
			fields = append(fields, clioutput.Field{Label: "protocol", Value: string(route.ServiceProtocol)},
				clioutput.Field{Label: "public URL", Value: address})
		}
		if route.Kept != nil && *route.Kept {
			fields = append(fields, clioutput.Field{Label: "retirement", Value: "kept"})
		} else if route.IdleRecoveryUntil != nil {
			fields = append(fields, clioutput.Field{Label: "recovery until", Value: route.IdleRecoveryUntil.UTC().Format(time.RFC3339)})
		}
		blocks = append(blocks, clioutput.Section(route.CanonicalHostname, clioutput.Fields(fields...)))
	}
	return writeHumanFrame(output, "tnl url list", countState(len(routes), "public URL", "public URLs"), "", blocks...)
}

func runURLDelete(ctx context.Context, command publicURLDeleteCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.selection(), "tnl url delete", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	selected, err := session.authenticated.Control.GetPublicURL(ctx, command.PublicURLID)
	if err != nil {
		return err
	}
	if selected.TeamId != current.team.Id {
		return controlclient.ErrNotFound
	}
	if err := session.authenticated.Control.DeletePublicURL(ctx, selected.Id); err != nil {
		return err
	}
	return writeHumanTransition(output, "tnl url delete", "deleted", selected.CanonicalHostname, "", "public URL deleted", "",
		clioutput.Field{Label: "id", Value: selected.Id})
}

func runURLUpdate(ctx context.Context, flags publicURLUpdateCommand, output, diagnostics io.Writer) error {
	if flags.Target == "" && flags.AllowIP == nil && !flags.AllowAllIPs && !flags.Keep && !flags.AutoRetire {
		return failure.Wrap("validate URL update", failure.InvalidTunnelFlags, errors.New("set --target, --allow-ip, --allow-all-ips, --keep, or --auto-retire"))
	}
	if flags.AllowAllIPs && flags.AllowIP != nil {
		return failure.Wrap("validate URL update", failure.InvalidTunnelFlags, errors.New("--allow-all-ips cannot be combined with --allow-ip"))
	}
	if flags.Keep && flags.AutoRetire {
		return failure.Wrap("validate URL update", failure.InvalidTunnelFlags, errors.New("--keep and --auto-retire cannot be combined"))
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl url update", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	route, err := session.authenticated.Control.GetPublicURL(ctx, flags.PublicURLID)
	if err != nil {
		return err
	}
	if route.TeamId != current.team.Id {
		return controlclient.ErrNotFound
	}
	if flags.Target != "" && route.ServiceProtocol != controlv1.Http {
		return failure.Wrap("validate database URL update", failure.InvalidTunnelFlags,
			errors.New("database targets are configured on the publisher, not the saved public URL"))
	}
	target := route.Target
	if flags.Target != "" {
		target, err = localproxy.NormalizeTarget(flags.Target)
		if err != nil {
			return err
		}
	}
	allowed := []string{}
	if route.AllowedIpPrefixes != nil {
		allowed = *route.AllowedIpPrefixes
	}
	if flags.AllowIP != nil || flags.AllowAllIPs {
		policy, policyErr := resolveIPPolicy(ctx, session.authenticated.Control, flags.AllowIP, flags.AllowAllIPs)
		if policyErr != nil {
			return policyErr
		}
		allowed = policy.prefixes
	}
	body := controlv1.UpdatePublicURLRequest{Target: target, AllowedIpPrefixes: allowed}
	if flags.Keep || flags.AutoRetire {
		kept := flags.Keep
		body.Kept = &kept
	}
	updated, err := session.authenticated.Control.UpdatePublicURL(ctx, flags.PublicURLID, body)
	if err != nil {
		return err
	}
	address, err := savedPublicAddress(updated)
	if err != nil {
		return err
	}
	fields := []clioutput.Field{{Label: "public URL", Value: address}}
	if updated.Target != "" {
		fields = append(fields, clioutput.Field{Label: "target", Value: updated.Target})
	}
	footer := "restart the publisher to use the new target or policy"
	if flags.Keep || flags.AutoRetire {
		footer = "idle retirement setting saved"
	}
	return writeHumanFrame(output, "tnl url update", "updated", footer,
		clioutput.Fields(fields...))
}
