package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
)

type statusCommand struct {
	Output   string `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
	StateDir string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Directory for persistent client state."`
}

type statusJSONSnapshot struct {
	SchemaVersion int                       `json:"schema_version"`
	ObservedAt    time.Time                 `json:"observed_at"`
	Summary       clientstate.TunnelSummary `json:"summary"`
	Tunnels       []statusJSONTunnel        `json:"tunnels"`
}

type statusJSONTunnel struct {
	ID             string                    `json:"tunnel_id"`
	Command        clientstate.TunnelCommand `json:"command"`
	State          clientstate.TunnelState   `json:"state"`
	ProcessID      int                       `json:"process_id"`
	Server         string                    `json:"server"`
	RouteID        string                    `json:"route_id,omitempty"`
	RouteVersion   uint64                    `json:"route_version,omitempty"`
	Hostname       string                    `json:"hostname,omitempty"`
	PublicURL      string                    `json:"public_url,omitempty"`
	Target         string                    `json:"target,omitempty"`
	Framework      string                    `json:"framework,omitempty"`
	StartedAt      time.Time                 `json:"started_at"`
	UpdatedAt      time.Time                 `json:"updated_at"`
	HeartbeatAt    time.Time                 `json:"heartbeat_at"`
	LeaseExpiresAt time.Time                 `json:"lease_expires_at"`
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
		value := statusJSONSnapshot{
			SchemaVersion: snapshot.SchemaVersion, ObservedAt: snapshot.ObservedAt, Summary: snapshot.Summary,
			Tunnels: make([]statusJSONTunnel, len(snapshot.Tunnels)),
		}
		for index, tunnel := range snapshot.Tunnels {
			value.Tunnels[index] = statusJSONTunnel{
				ID: tunnel.ID, Command: tunnel.Command, State: tunnel.State, ProcessID: tunnel.ProcessID,
				Server: tunnel.Server, RouteID: tunnel.RouteID, RouteVersion: tunnel.RouteVersion,
				Hostname: tunnel.Hostname, PublicURL: tunnel.PublicURL, Target: tunnel.Target, Framework: tunnel.Framework,
				StartedAt: tunnel.StartedAt, UpdatedAt: tunnel.UpdatedAt,
				HeartbeatAt: tunnel.HeartbeatAt, LeaseExpiresAt: tunnel.LeaseExpiresAt,
			}
		}
		return json.NewEncoder(output).Encode(value)
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
