package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/projectconfig"
)

type statusCommand struct {
	Output   string `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
	StateDir string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
	All      bool   `name:"all" help:"Show tunnels from every local project."`
	Project  string `kong:"-"`
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
	if flags.Output == "json" {
		return json.NewEncoder(output).Encode(snapshot)
	}
	if len(snapshot.Tunnels) == 0 {
		return writeHumanFrame(output, "tnl status", "no local tunnels", "",
			clioutput.Tree(clioutput.TreeNode{Label: "start one with", Children: []clioutput.TreeNode{
				{Label: "tnl publish 3000"},
				{Label: "tnl dev -- pnpm dev"},
			}}),
		)
	}
	blocks := make([]clioutput.Block, 0, len(snapshot.Tunnels))
	for _, tunnel := range snapshot.Tunnels {
		fields := make([]clioutput.Field, 0, 8)
		if tunnel.PublicURL != "" {
			fields = append(fields, clioutput.Field{Label: "public", Value: tunnel.PublicURL})
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
		if tunnel.RouteVersion != 0 {
			fields = append(fields, clioutput.Field{Label: "route version", Value: strconv.FormatUint(tunnel.RouteVersion, 10)})
		}
		fields = append(fields, clioutput.Field{Label: "tunnel", Value: tunnel.ID})
		blocks = append(blocks, clioutput.Section(string(tunnel.State), clioutput.Fields(fields...)))
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
