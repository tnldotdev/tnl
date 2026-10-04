package main

import (
	"context"
	"io"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
)

type telemetryCommand struct {
	On     telemetryPreferenceCommand `cmd:"" help:"Enable usage telemetry in this client state."`
	Off    telemetryPreferenceCommand `cmd:"" help:"Disable usage telemetry in this client state."`
	Status telemetryPreferenceCommand `cmd:"" help:"Show the saved usage telemetry choice."`
}

type telemetryPreferenceCommand struct {
	StateDir string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
}

func runTelemetryPreference(ctx context.Context, command telemetryPreferenceCommand, action string, output io.Writer) error {
	root, err := clientStateRoot(command.StateDir)
	if err != nil {
		return err
	}
	var enabled bool
	if action == "status" {
		enabled, err = clientstate.TelemetryEnabledAt(ctx, root)
	} else {
		state, openErr := clientstate.Open(ctx, root)
		if openErr != nil {
			return openErr
		}
		defer state.Close()
		if err := state.SetTelemetryEnabled(ctx, action == "on"); err != nil {
			return err
		}
		enabled, err = state.TelemetryEnabled(ctx)
	}
	if err != nil {
		return err
	}
	value := "off"
	if enabled {
		value = "on"
	}
	return clioutput.Write(output, clioutput.Frame{
		Command: "tnl telemetry " + action, State: value,
		Blocks: []clioutput.Block{clioutput.Fields(
			clioutput.Field{Label: "usage telemetry", Value: value},
		)},
	})
}
