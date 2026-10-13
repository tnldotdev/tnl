package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type publicURLCommand struct {
	List   publicURLListCommand   `cmd:"" help:"List public URLs for the selected team."`
	Show   publicURLShowCommand   `cmd:"" help:"Show one saved public URL for a configured service or ID."`
	Update publicURLUpdateCommand `cmd:"" help:"Change a saved public URL target or visitor policy."`
	Delete publicURLDeleteCommand `cmd:"" help:"Delete a public URL by ID; use tnl url list to find it."`
}

type publicURLShowCommand struct {
	scopedTeamFlags `embed:""`
	Selector        string           `arg:"" name:"service-or-public-url-id" required:""`
	Output          scalarOutputMode `name:"output" enum:"human,raw,json" default:"human" help:"Output format: ${enum}."`
}

func runURLShow(ctx context.Context, command publicURLShowCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.selection(), "tnl url show", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.currentWithDomains(ctx)
	if err != nil {
		return err
	}
	var saved controlv1.PublicURL
	var expectedProtocol controlv1.PublicURLServiceProtocol
	if opaqueid.Valid(command.Selector, opaqueid.PublicURLPrefix) {
		saved, err = session.authenticated.Control.GetPublicURL(ctx, command.Selector)
	} else {
		if !project.Found() {
			return failure.Wrap("select project service", failure.ServiceNotConfigured, errors.New("a configured service is required"))
		}
		effective, resolveErr := project.EffectiveService(command.Selector)
		if resolveErr != nil {
			return failure.Wrap("select project service", failure.ServiceNotConfigured, resolveErr)
		}
		expectedProtocol = controlv1.PublicURLServiceProtocol(config.ServiceProtocol(effective.Publish))
		service, resolveErr := configuredProjectService(command.Selector, project.Worktree, effective, current)
		if resolveErr != nil {
			return resolveErr
		}
		saved, err = session.authenticated.Control.GetPublicURLByHostname(ctx, current.team.Id, service.Hostname)
	}
	if err != nil {
		return err
	}
	if saved.TeamId != current.team.Id {
		return controlclient.ErrNotFound
	}
	if expectedProtocol != "" && saved.ServiceProtocol != expectedProtocol {
		return failure.Wrap("select project public URL", failure.ServerConflict,
			fmt.Errorf("saved public URL protocol %s does not match configured service %q (%s)", saved.ServiceProtocol, command.Selector, expectedProtocol))
	}
	address, err := savedPublicAddress(saved)
	if err != nil {
		return err
	}
	return writeURLShow(command.Output, saved, address, output)
}

func writeURLShow(mode scalarOutputMode, saved controlv1.PublicURL, address string, output io.Writer) error {
	switch mode {
	case scalarOutputRaw:
		_, err := fmt.Fprintln(output, address)
		return err
	case scalarOutputJSON:
		return json.NewEncoder(output).Encode(struct {
			SchemaVersion int                                `json:"schema_version"`
			PublicURLID   string                             `json:"public_url_id"`
			PublicURL     string                             `json:"public_url"`
			Protocol      controlv1.PublicURLServiceProtocol `json:"protocol"`
			State         controlv1.PublicURLLifecycleState  `json:"state"`
		}{1, saved.Id, address, saved.ServiceProtocol, saved.LifecycleState})
	default:
		return writeHumanFrame(output, "tnl url show", string(saved.LifecycleState), "tnl status shows local publication readiness",
			clioutput.Fields(
				clioutput.Field{Label: "public URL", Value: address},
				clioutput.Field{Label: "protocol", Value: string(saved.ServiceProtocol)},
				clioutput.Field{Label: "public URL ID", Value: saved.Id},
				clioutput.Field{Label: "scope", Value: string(saved.PublicUrlScope)},
			))
	}
}

type publicURLUpdateCommand struct {
	scopedTeamFlags `embed:""`
	PublicURLID     string   `arg:"" name:"public-url-id" required:""`
	Target          string   `name:"target" help:"New HTTP or HTTPS target origin; no connection is made from this command."`
	AllowIP         []string `name:"allow-ip" help:"Replace visitor addresses; repeat for each address or prefix."`
	AllowAllIPs     bool     `name:"allow-all-ips" help:"Allow visitors from every IP."`
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
		if route.ServiceProtocol != controlv1.Http {
			address, err := savedPublicAddress(route)
			if err != nil {
				return err
			}
			fields = append(fields, clioutput.Field{Label: "protocol", Value: string(route.ServiceProtocol)},
				clioutput.Field{Label: "public URL", Value: address})
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
	if flags.Target == "" && flags.AllowIP == nil && !flags.AllowAllIPs {
		return failure.Wrap("validate URL update", failure.InvalidTunnelFlags, errors.New("set --target, --allow-ip, or --allow-all-ips to update this public URL"))
	}
	if flags.AllowAllIPs && flags.AllowIP != nil {
		return failure.Wrap("validate URL update", failure.InvalidTunnelFlags, errors.New("--allow-all-ips cannot be combined with --allow-ip"))
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
		return failure.Wrap("validate TCP URL update", failure.InvalidTunnelFlags,
			errors.New("TCP targets are configured on the publisher, not the saved public URL"))
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
	updated, err := session.authenticated.Control.UpdatePublicURL(ctx, flags.PublicURLID, controlv1.UpdatePublicURLRequest{
		Target: target, AllowedIpPrefixes: allowed,
	})
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
	return writeHumanFrame(output, "tnl url update", "updated", "restart the publisher to use the new target or policy",
		clioutput.Fields(fields...))
}
