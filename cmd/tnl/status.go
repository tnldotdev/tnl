package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/tnldotdev/tnl/internal/clientstate"
)

type statusCommand struct {
	Output   string `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
	StateDir string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Directory for persistent client state."`
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
	snapshot, err := state.Snapshot(ctx)
	if err != nil {
		return err
	}
	if flags.Output == "json" {
		return json.NewEncoder(output).Encode(snapshot)
	}
	if len(snapshot.Tunnels) == 0 {
		_, err := fmt.Fprintln(output, "No local tunnels.")
		return err
	}
	table := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "TUNNEL ID\tSTATE\tURL\tTARGET\tCOMMAND"); err != nil {
		return err
	}
	for _, tunnel := range snapshot.Tunnels {
		if _, err := fmt.Fprintf(
			table, "%s\t%s\t%s\t%s\t%s\n",
			tunnel.ID, tunnel.State, tunnel.PublicURL, tunnel.Target, tunnel.Command,
		); err != nil {
			return err
		}
	}
	return table.Flush()
}
