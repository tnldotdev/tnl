package main

import (
	"context"
	"io"

	"github.com/spf13/cobra"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/clioutput"
)

type telemetryCommand struct {
	On     telemetryPreferenceCommand
	Off    telemetryPreferenceCommand
	Status telemetryPreferenceCommand
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

func (a *commandApp) newTelemetryCommand() *cobra.Command {
	f := a.flags
	cTelemetry := &cobra.Command{Use: "telemetry", Short: "Manage the saved usage telemetry choice.", GroupID: "manage"}
	cTelemetryOn := &cobra.Command{Use: "on", Short: "Enable usage telemetry in this client state."}
	a.leaf(cTelemetryOn, &f.Telemetry.On, func(call commandCall) error {
		return runTelemetryPreference(call.ctx, f.Telemetry.On, "on", a.out)
	})
	cTelemetry.AddCommand(cTelemetryOn)
	cTelemetryOff := &cobra.Command{Use: "off", Short: "Disable usage telemetry in this client state."}
	a.leaf(cTelemetryOff, &f.Telemetry.Off, func(call commandCall) error {
		return runTelemetryPreference(call.ctx, f.Telemetry.Off, "off", a.out)
	})
	cTelemetry.AddCommand(cTelemetryOff)
	cTelemetryStatus := &cobra.Command{Use: "status", Short: "Show the saved usage telemetry choice."}
	a.leaf(cTelemetryStatus, &f.Telemetry.Status, func(call commandCall) error {
		return runTelemetryPreference(call.ctx, f.Telemetry.Status, "status", a.out)
	})
	cTelemetry.AddCommand(cTelemetryStatus)
	return cTelemetry
}
