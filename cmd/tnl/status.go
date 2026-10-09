package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/projectconfig"
)

type statusOutputMode string

const (
	statusOutputHuman statusOutputMode = "human"
	statusOutputJSON  statusOutputMode = "json"
)

type statusCommand struct {
	Output        statusOutputMode     `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
	StateDir      string               `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
	All           bool                 `name:"all" help:"Show tunnels from every local project."`
	Project       string               `kong:"-"`
	Configuration projectConfiguration `kong:"-"`
}

func runStatus(ctx context.Context, flags statusCommand, output io.Writer) error {
	root, err := clientStateRoot(flags.StateDir)
	if err != nil {
		return err
	}
	state, err := clientstate.Open(ctx, root)
	if err != nil {
		return err
	}
	defer state.Close()
	root = state.Root()
	var snapshot clientstate.TunnelSnapshot
	if flags.All {
		snapshot, err = state.Snapshot(ctx)
	} else {
		if flags.Project == "" {
			flags.Project, err = currentProjectRoot(ctx)
			if err != nil {
				return err
			}
		}
		snapshot, err = state.SnapshotProject(ctx, flags.Project)
	}
	if err != nil {
		return err
	}
	appSnapshot := clientruntime.Snapshot{Cursor: "0", Services: []clientruntime.Service{}}
	projects := []clientruntime.Snapshot{}
	if !flags.All {
		project, resolveErr := flags.Configuration, error(nil)
		if project.Root == "" {
			project, _, resolveErr = runtimeProject(ctx, runtimeOptions{Directory: flags.Project, StateDir: root})
		}
		if resolveErr == nil {
			appSnapshot, err = readAppSnapshot(ctx, project, root)
			if err != nil {
				return err
			}
		}
	} else {
		projects, err = clientruntime.ListSnapshots(root)
		if err != nil {
			return err
		}
		for _, project := range projects {
			socket, err := runtimeSocket(project.Project, root)
			if err != nil {
				return err
			}
			available := runtimeAvailable(ctx, socket)
			for _, service := range project.Services {
				service.Project = project.Project
				if !available {
					if service.Registered {
						service.Failure = "runtime.manager_unavailable"
					}
					service.Registered, service.Routable, service.Ready = false, false, false
					service.Observation = nil
				}
				appSnapshot.Services = append(appSnapshot.Services, service)
			}
		}
	}
	if flags.Output == statusOutputJSON {
		return json.NewEncoder(output).Encode(struct {
			clientstate.TunnelSnapshot
			Cursor   string                  `json:"cursor"`
			Services []clientruntime.Service `json:"services"`
		}{snapshot, appSnapshot.Cursor, appSnapshot.Services})
	}
	if len(snapshot.Tunnels) == 0 && len(snapshot.Aliases) == 0 && len(appSnapshot.Services) == 0 {
		return writeHumanFrame(output, "tnl status", "no local tunnels", "",
			clioutput.Tree(clioutput.TreeNode{Label: "start one with", Children: []clioutput.TreeNode{
				{Label: "tnl publish 3000"},
				{Label: "pnpm dev with a tnl integration"},
			}}),
		)
	}
	blocks := appServiceBlocks(appSnapshot)
	for _, tunnel := range snapshot.Tunnels {
		fields := make([]clioutput.Field, 0, 8)
		if tunnel.PublicURL != "" {
			fields = append(fields, clioutput.Field{Label: "URL", Value: tunnel.PublicURL})
		} else if tunnel.Hostname != "" {
			fields = append(fields, clioutput.Field{Label: "hostname", Value: tunnel.Hostname})
		}
		if tunnel.Target != "" {
			fields = append(fields, clioutput.Field{Label: "target", Value: tunnel.Target})
		}
		fields = append(fields,
			clioutput.Field{Label: "command", Value: string(tunnel.Command)},
			clioutput.Field{Label: "server", Value: tunnel.Server},
		)
		if tunnel.Service != "" {
			fields = append(fields, clioutput.Field{Label: "service", Value: tunnel.Service})
		}
		if flags.All {
			fields = append(fields, clioutput.Field{Label: "project", Value: tunnel.Project})
		}
		if tunnel.Framework != "" {
			fields = append(fields, clioutput.Field{Label: "framework", Value: tunnel.Framework})
		}
		if tunnel.PublishRunNumber != 0 {
			fields = append(fields, clioutput.Field{Label: "publish run number", Value: strconv.FormatUint(tunnel.PublishRunNumber, 10)})
		}
		fields = append(fields, clioutput.Field{Label: "tunnel", Value: tunnel.ID})
		blocks = append(blocks, clioutput.Section(string(tunnel.State), clioutput.Fields(fields...)))
	}
	for _, integrationURL := range snapshot.IntegrationURLs {
		fields := []clioutput.Field{
			{Label: "public URL", Value: integrationURL.PublicURL},
			{Label: "server", Value: integrationURL.Server},
		}
		if integrationURL.Reason != "" {
			fields = append(fields, clioutput.Field{Label: "reason", Value: string(integrationURL.Reason)})
			fields = append(fields, clioutput.Field{Label: "action", Value: integrationURL.Action})
		}
		blocks = append(blocks, clioutput.Section(integrationURL.Kind+" "+integrationURL.State, clioutput.Fields(fields...)))
		for _, endpoint := range integrationURL.Endpoints {
			fields := []clioutput.Field{
				{Label: "endpoint", Value: endpoint.URL},
				{Label: "service", Value: endpoint.Service},
				{Label: "delivery", Value: endpoint.Delivery},
				{Label: "ready receivers", Value: strconv.Itoa(len(endpoint.ReadyReceivers))},
			}
			for _, receiver := range endpoint.ReadyReceivers {
				fields = append(fields, clioutput.Field{Label: "worktree", Value: receiver.PublicURL})
			}
			if endpoint.Owner != nil {
				fields = append(fields, clioutput.Field{Label: "owner", Value: endpoint.Owner.PublicURL})
				fields = append(fields, clioutput.Field{Label: "owner state", Value: endpoint.Owner.State})
			}
			if endpoint.Reason != "" {
				fields = append(fields, clioutput.Field{Label: "reason", Value: string(endpoint.Reason)})
				fields = append(fields, clioutput.Field{Label: "action", Value: endpoint.Action})
			}
			blocks = append(blocks, clioutput.Section("webhook "+endpoint.Name+" "+endpoint.State, clioutput.Fields(fields...)))
		}
	}
	for _, alias := range snapshot.Aliases {
		fields := []clioutput.Field{
			{Label: "alias", Value: alias.Name}, {Label: "public URL", Value: alias.PublicURL},
			{Label: "service", Value: alias.Service}, {Label: "selected worktree", Value: alias.SelectedProject},
		}
		if alias.SelectedProject == alias.DefaultProject {
			fields = append(fields, clioutput.Field{Label: "selection", Value: "primary checkout (default)"})
		}
		if alias.Reason != "" {
			fields = append(fields, clioutput.Field{Label: "reason", Value: string(alias.Reason)}, clioutput.Field{Label: "action", Value: alias.Action})
		}
		blocks = append(blocks, clioutput.Section("alias "+alias.State, clioutput.Fields(fields...)))
	}
	if len(appSnapshot.Services) != 0 {
		return writeHumanFrame(output, "tnl status", countState(len(appSnapshot.Services), "configured service", "configured services"), "cursor "+appSnapshot.Cursor, blocks...)
	}
	return writeHumanFrame(output, "tnl status", countState(len(snapshot.Tunnels), "local tunnel", "local tunnels"),
		statusSummary(snapshot.Summary), blocks...)
}

func statusSummary(summary clientstate.TunnelSummary) string {
	parts := make([]string, 0, 5)
	for _, value := range []struct {
		count int
		state string
	}{
		{summary.Starting, "starting"},
		{summary.Provisioning, "provisioning"},
		{summary.Ready, "ready"},
		{summary.Draining, "draining"},
		{summary.Stale, "stale"},
	} {
		if value.count != 0 {
			parts = append(parts, strconv.Itoa(value.count)+" "+value.state)
		}
	}
	return strings.Join(parts, " / ")
}

func currentProjectRoot(ctx context.Context) (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	worktree, err := projectconfig.ResolveWorktree(ctx, cwd)
	if err != nil {
		return "", err
	}
	return worktree.Root, nil
}
